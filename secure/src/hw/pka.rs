//! STM32U585 PKA (Public Key Accelerator) driver for BLS12-381 field arithmetic.
//!
//! Provides hardware-accelerated modular arithmetic over the BLS12-381 base
//! field Fp (381-bit prime). The PKA runs Montgomery multiplication, modular
//! inverse, and modular add/sub as standalone operations with arbitrary primes.
//!
//! # PKA RAM Layout (from RM0456)
//!
//! All standalone arithmetic modes share the same operand layout:
//!   - NB_BITS  @ offset 0x0408 — operand size in bits
//!   - OP1      @ offset 0x0A50 — first operand (12 × u32, LE limb order)
//!   - OP2      @ offset 0x0C68 — second operand
//!   - OP3      @ offset 0x1088 — modulus
//!   - RESULT   @ offset 0x0E78 — output
//!
//! # Safety
//!
//! The PKA peripheral is memory-mapped. All MMIO is funnelled through
//! `hw::mmio::{Reg32, RoReg32}`, which encapsulates `read_volatile` /
//! `write_volatile` once per address. The peripheral must be configured as
//! a TrustZone secure peripheral via GTZC before use, and only one
//! operation may be in flight at a time (no concurrent access — the secure
//! world is single-threaded and non-preemptive).

use crate::hw::mmio::{Reg32, RoReg32};

// ── PKA peripheral registers ────────────────────────────────────────────

/// PKA peripheral base address (STM32U585, AHB2 bus — secure alias).
/// NS alias is 0x420C_2000; TZSC_SECCFGRx config marks PKA secure, so
/// secure code must use 0x520C_2000.
const PKA_BASE: u32 = 0x520C_2000;

/// RCC AHB2ENR1 (NS alias used at boot before TZ flips this to secure-only).
const RCC_AHB2ENR1_ADDR: u32 = 0x4002_084C;
const RCC_AHB2ENR1_PKAEN: u32 = 1 << 15;

// CR bit fields
const CR_EN: u32 = 1 << 0;
const CR_START: u32 = 1 << 1;
const CR_MODE_SHIFT: u32 = 8;
const CR_MODE_MASK: u32 = 0x3F << CR_MODE_SHIFT;

// SR bit fields
const SR_INITOK: u32 = 1 << 0;
#[allow(dead_code)]
const SR_BUSY: u32 = 1 << 16;
const SR_PROCENDF: u32 = 1 << 17;

// CLRFR bit fields
const CLRFR_PROCENDFC: u32 = 1 << 17;

// ── PKA operation modes ─────────────────────────────────────────────────

#[allow(dead_code)]
const MODE_MONTGOMERY_PARAM: u32 = 0x01;
const MODE_MODULAR_INV: u32 = 0x08;
const MODE_MODULAR_ADD: u32 = 0x0E;
const MODE_MODULAR_SUB: u32 = 0x0F;
const MODE_MONTGOMERY_MUL: u32 = 0x10;

// ── PKA RAM offsets (byte addresses from PKA_BASE) ──────────────────────

/// PKA RAM base (operand storage area)
const PKA_RAM_BASE: u32 = PKA_BASE + 0x400;

/// Operand size in bits — word offset 2 → byte offset 0x0008 from RAM base
const RAM_NB_BITS_ADDR: u32 = PKA_RAM_BASE + 0x0008;
/// First operand — word offset 0x294 → byte offset 0x0A50 from PKA_BASE
const RAM_OP1: u32 = PKA_BASE + 0x0A50;
/// Second operand
const RAM_OP2: u32 = PKA_BASE + 0x0C68;
/// Result
const RAM_RESULT: u32 = PKA_BASE + 0x0E78;
/// Modulus (OP3)
const RAM_MODULUS: u32 = PKA_BASE + 0x1088;

// ── BLS12-381 base field prime (Fp) ─────────────────────────────────────

/// BLS12-381 base field prime p as 12 × u32 in little-endian limb order.
/// p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
const BLS12_381_P: [u32; 12] = [
    0xFFFF_AAAB, 0xFFFF_FFFF, 0xB9FE_FFFF, 0x1EAB_FFFE,
    0xF6B0_F624, 0x6730_D2A0, 0xF385_12BF, 0x6477_4B84,
    0x4B1B_A7B6, 0x434B_ACD7, 0x397F_E69A, 0x1A01_11EA,
];

/// Operand size in bits for BLS12-381 Fp
const BLS12_381_BITS: u32 = 384;

/// Number of 32-bit limbs for a 384-bit operand
const N_LIMBS: usize = 12;

// ── Register handles ────────────────────────────────────────────────────

/// All MMIO registers this driver owns, bundled so the one-time
/// `unsafe { ... }` for `Reg32::new` happens once at module scope.
struct PkaRegs {
    /// PKA control register
    cr: Reg32,
    /// PKA status register (read-only flags)
    sr: RoReg32,
    /// PKA clear-flag register
    clrfr: Reg32,
    /// RCC AHB2ENR1 — owns the PKAEN bit
    rcc_ahb2enr1: Reg32,
    /// PKA RAM cell holding the operand-size-in-bits parameter
    ram_nb_bits: Reg32,
    /// Base of operand slot OP1 (used with `write_at` / `read_at`).
    op1: Reg32,
    /// Base of operand slot OP2.
    op2: Reg32,
    /// Base of operand slot OP3 (modulus).
    modulus: Reg32,
    /// Base of operand slot RESULT (read-only after `execute`).
    result: RoReg32,
}

// SAFETY: each address below is a real, 4-byte-aligned MMIO register or
// PKA-RAM operand slot exclusively owned by this driver. The secure world
// is single-threaded and non-preemptive — nothing else races us. Operand
// slots are stepped via the safe-looking `unsafe fn read_at` / `write_at`
// helpers; the safety obligation there is "offset stays in-bank", which
// is enforced at every use site by an explicit `0..=N_LIMBS` bound.
// `RCC_AHB2ENR1` is shared with other peripherals; we only ever flip the
// PKAEN bit (bit 15) via `set_bits`, so no aliased state is mutated.
const REG: PkaRegs = unsafe {
    PkaRegs {
        cr: Reg32::new(PKA_BASE),
        sr: RoReg32::new(PKA_BASE + 0x04),
        clrfr: Reg32::new(PKA_BASE + 0x08),
        rcc_ahb2enr1: Reg32::new(RCC_AHB2ENR1_ADDR),
        ram_nb_bits: Reg32::new(RAM_NB_BITS_ADDR),
        op1: Reg32::new(RAM_OP1),
        op2: Reg32::new(RAM_OP2),
        modulus: Reg32::new(RAM_MODULUS),
        result: RoReg32::new(RAM_RESULT),
    }
};

// ── PKA driver interface ────────────────────────────────────────────────

/// Initialize the PKA peripheral. Must be called once at boot before any
/// PKA operation. Enables the peripheral clock, enables PKA, and preloads
/// the BLS12-381 modulus (which never changes across operations).
///
/// # Safety
/// - RCC and GTZC must be configured to allow secure access to PKA
/// - Must be called from the secure world
pub unsafe fn init() {
    // Enable PKA clock: RCC_AHB2ENR1.PKAEN.
    REG.rcc_ahb2enr1.set_bits(RCC_AHB2ENR1_PKAEN);

    // Small delay for clock stabilization.
    cortex_m::asm::dsb();

    // Enable PKA.
    REG.cr.write(CR_EN);

    // Wait for INITOK.
    while REG.sr.read() & SR_INITOK == 0 {
        cortex_m::asm::nop();
    }

    // Preload the BLS12-381 modulus into PKA RAM (stays for all operations).
    write_operand(REG.modulus, &BLS12_381_P);

    // Preload NB_BITS (stays constant for all BLS12-381 Fp operations).
    REG.ram_nb_bits.write(BLS12_381_BITS);
}

/// Write a 12-word operand into a PKA RAM operand slot.
///
/// `slot` must be one of the module-level operand-slot handles (OP1, OP2,
/// modulus). Stepping word-by-word with the in-bank `write_at` helper keeps
/// the unsafety pinned to a single call site whose bounds are obvious.
#[inline]
fn write_operand(slot: Reg32, limbs: &[u32; N_LIMBS]) {
    // SAFETY: each PKA operand slot is sized for 384-bit operands plus
    // headroom; offsets `0..=N_LIMBS = 12` stay inside the slot's bank
    // (operand slots are 0x218 bytes apart in PKA RAM — 134 words — well
    // beyond the 13 words we touch). PKA RAM is owned exclusively by
    // this driver.
    unsafe {
        for i in 0..N_LIMBS {
            slot.write_at(i, limbs[i]);
        }
        // Clear the terminator word past our operand (PKA RAM may have
        // stale data from a previous op).
        slot.write_at(N_LIMBS, 0);
    }
}

/// Read a 12-word result from a PKA RAM operand slot.
#[inline]
fn read_result(slot: RoReg32) -> [u32; N_LIMBS] {
    let mut out = [0u32; N_LIMBS];
    // SAFETY: same precondition as `write_operand` — offsets `0..N_LIMBS`
    // stay inside the result-operand slot.
    unsafe {
        for i in 0..N_LIMBS {
            out[i] = slot.read_at(i);
        }
    }
    out
}

/// Execute a PKA operation: set mode, start, poll until done.
#[inline]
fn execute(mode: u32) {
    // Set mode and start (keep EN set).
    let cr = CR_EN | ((mode << CR_MODE_SHIFT) & CR_MODE_MASK) | CR_START;
    REG.cr.write(cr);

    // Poll for completion.
    while REG.sr.read() & SR_PROCENDF == 0 {
        cortex_m::asm::nop();
    }

    // Clear the completion flag.
    REG.clrfr.write(CLRFR_PROCENDFC);

    // Reset mode (keep EN, clear START and MODE).
    REG.cr.write(CR_EN);
}

/// Montgomery multiplication: result = a * b * R^{-1} mod p
///
/// Both operands must be in Montgomery form. The BLS12-381 modulus is
/// preloaded at init and does not need to be set per call.
///
/// # Safety
/// PKA must be initialized via `init()`.
pub unsafe fn mont_mul(a: &[u32; N_LIMBS], b: &[u32; N_LIMBS]) -> [u32; N_LIMBS] {
    write_operand(REG.op1, a);
    write_operand(REG.op2, b);
    execute(MODE_MONTGOMERY_MUL);
    read_result(REG.result)
}

/// Modular inverse: result = a^{-1} mod p
///
/// Input is a regular (non-Montgomery) field element; output is also
/// non-Montgomery. For inverting a Montgomery-form element, convert out
/// of Montgomery form first, invert, then convert back. Alternatively,
/// compute mont_mul(a_mont, R^3 mod p) to get the inverse in Montgomery form.
///
/// # Safety
/// PKA must be initialized via `init()`.
pub unsafe fn mod_inv(a: &[u32; N_LIMBS]) -> [u32; N_LIMBS] {
    write_operand(REG.op1, a);
    // Modulus is already loaded at REG.modulus from init()
    execute(MODE_MODULAR_INV);
    read_result(REG.result)
}

/// Modular addition: result = (a + b) mod p
///
/// # Safety
/// PKA must be initialized via `init()`.
pub unsafe fn mod_add(a: &[u32; N_LIMBS], b: &[u32; N_LIMBS]) -> [u32; N_LIMBS] {
    write_operand(REG.op1, a);
    write_operand(REG.op2, b);
    execute(MODE_MODULAR_ADD);
    read_result(REG.result)
}

/// Modular subtraction: result = (a - b) mod p
///
/// # Safety
/// PKA must be initialized via `init()`.
pub unsafe fn mod_sub(a: &[u32; N_LIMBS], b: &[u32; N_LIMBS]) -> [u32; N_LIMBS] {
    write_operand(REG.op1, a);
    write_operand(REG.op2, b);
    execute(MODE_MODULAR_SUB);
    read_result(REG.result)
}

// ── Extern hook for bls12_381_pka fork ──────────────────────────────────

/// Entry point called by the `bls12_381_pka` fork's `Fp::mul_pka`.
/// The `#[no_mangle]` + `link_name` convention avoids a direct crate dependency.
#[no_mangle]
pub unsafe extern "Rust" fn bls12_381_pka_mont_mul(a: &[u32; N_LIMBS], b: &[u32; N_LIMBS]) -> [u32; N_LIMBS] {
    // SAFETY: forwarded from our own `unsafe` contract — caller must have
    // initialised PKA via `init()`.
    unsafe { mont_mul(a, b) }
}

// ── Conversion helpers ──────────────────────────────────────────────────

/// Convert from `[u64; 6]` (bls12_381 crate Fp internal format, LE limb order)
/// to `[u32; 12]` (PKA format, LE limb order).
///
/// Each u64 limb splits into (low_u32, high_u32) at the same index position.
#[inline]
pub fn fp_u64_to_u32(limbs: &[u64; 6]) -> [u32; N_LIMBS] {
    let mut out = [0u32; N_LIMBS];
    for i in 0..6 {
        out[2 * i] = limbs[i] as u32;
        out[2 * i + 1] = (limbs[i] >> 32) as u32;
    }
    out
}

/// Convert from `[u32; 12]` (PKA format) back to `[u64; 6]` (bls12_381 crate format).
#[inline]
pub fn fp_u32_to_u64(limbs: &[u32; N_LIMBS]) -> [u64; 6] {
    let mut out = [0u64; 6];
    for i in 0..6 {
        out[i] = limbs[2 * i] as u64 | ((limbs[2 * i + 1] as u64) << 32);
    }
    out
}

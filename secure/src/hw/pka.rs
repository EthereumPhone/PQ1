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
//! The PKA peripheral is memory-mapped and accessed via raw pointer writes.
//! It must be configured as a TrustZone secure peripheral via GTZC before use.
//! Only one operation may be in flight at a time (no concurrent access).

// ── PKA peripheral registers ────────────────────────────────────────────

/// PKA peripheral base address (STM32U585, AHB2 bus — secure alias).
/// NS alias is 0x420C_2000; TZSC_SECCFGRx config marks PKA secure, so
/// secure code must use 0x520C_2000.
const PKA_BASE: u32 = 0x520C_2000;

/// PKA control register
const PKA_CR: *mut u32 = PKA_BASE as *mut u32;
/// PKA status register
const PKA_SR: *const u32 = (PKA_BASE + 0x04) as *const u32;
/// PKA clear flag register
const PKA_CLRFR: *mut u32 = (PKA_BASE + 0x08) as *mut u32;

// CR bit fields
const CR_EN: u32 = 1 << 0;
const CR_START: u32 = 1 << 1;
const CR_MODE_SHIFT: u32 = 8;
const CR_MODE_MASK: u32 = 0x3F << CR_MODE_SHIFT;

// SR bit fields
const SR_INITOK: u32 = 1 << 0;
const SR_BUSY: u32 = 1 << 16;
const SR_PROCENDF: u32 = 1 << 17;

// CLRFR bit fields
const CLRFR_PROCENDFC: u32 = 1 << 17;

// ── PKA operation modes ─────────────────────────────────────────────────

const MODE_MONTGOMERY_PARAM: u32 = 0x01;
const MODE_MODULAR_INV: u32 = 0x08;
const MODE_MODULAR_ADD: u32 = 0x0E;
const MODE_MODULAR_SUB: u32 = 0x0F;
const MODE_MONTGOMERY_MUL: u32 = 0x10;

// ── PKA RAM offsets (word addresses from PKA_BASE + 0x400) ──────────────

/// PKA RAM base (operand storage area)
const PKA_RAM_BASE: u32 = PKA_BASE + 0x400;

/// Operand size in bits — word offset 2 → byte offset 0x0008 from RAM base
const RAM_NB_BITS: u32 = PKA_RAM_BASE + 0x0008;
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

// ── PKA driver interface ────────────────────────────────────────────────

/// Initialize the PKA peripheral. Must be called once at boot before any
/// PKA operation. Enables the peripheral clock, enables PKA, and preloads
/// the BLS12-381 modulus (which never changes across operations).
///
/// # Safety
/// - RCC and GTZC must be configured to allow secure access to PKA
/// - Must be called from the secure world
pub unsafe fn init() {
    // Enable PKA clock: RCC_AHB2ENR1, bit 15 = PKAEN
    const RCC_AHB2ENR1: *mut u32 = 0x4002_084C as *mut u32;
    let val = core::ptr::read_volatile(RCC_AHB2ENR1);
    core::ptr::write_volatile(RCC_AHB2ENR1, val | (1 << 15));

    // Small delay for clock stabilization
    cortex_m::asm::dsb();

    // Enable PKA
    core::ptr::write_volatile(PKA_CR, CR_EN);

    // Wait for INITOK
    while core::ptr::read_volatile(PKA_SR) & SR_INITOK == 0 {
        cortex_m::asm::nop();
    }

    // Preload the BLS12-381 modulus into PKA RAM (stays for all operations)
    write_operand(RAM_MODULUS, &BLS12_381_P);

    // Preload NB_BITS (stays constant for all BLS12-381 Fp operations)
    core::ptr::write_volatile(RAM_NB_BITS as *mut u32, BLS12_381_BITS);
}

/// Write a 12-word operand to PKA RAM at the given address.
#[inline]
unsafe fn write_operand(base: u32, limbs: &[u32; N_LIMBS]) {
    let ptr = base as *mut u32;
    for i in 0..N_LIMBS {
        core::ptr::write_volatile(ptr.add(i), limbs[i]);
    }
    // Clear any words beyond our operand (PKA RAM may have stale data)
    core::ptr::write_volatile(ptr.add(N_LIMBS), 0);
}

/// Read a 12-word result from PKA RAM.
#[inline]
unsafe fn read_result(base: u32) -> [u32; N_LIMBS] {
    let ptr = base as *const u32;
    let mut out = [0u32; N_LIMBS];
    for i in 0..N_LIMBS {
        out[i] = core::ptr::read_volatile(ptr.add(i));
    }
    out
}

/// Execute a PKA operation: set mode, start, poll until done.
#[inline]
unsafe fn execute(mode: u32) {
    // Set mode and start (keep EN set)
    let cr = CR_EN | ((mode << CR_MODE_SHIFT) & CR_MODE_MASK) | CR_START;
    core::ptr::write_volatile(PKA_CR, cr);

    // Poll for completion
    while core::ptr::read_volatile(PKA_SR) & SR_PROCENDF == 0 {
        cortex_m::asm::nop();
    }

    // Clear the completion flag
    core::ptr::write_volatile(PKA_CLRFR, CLRFR_PROCENDFC);

    // Reset mode (keep EN, clear START and MODE)
    core::ptr::write_volatile(PKA_CR, CR_EN);
}

/// Montgomery multiplication: result = a * b * R^{-1} mod p
///
/// Both operands must be in Montgomery form. The BLS12-381 modulus is
/// preloaded at init and does not need to be set per call.
///
/// # Safety
/// PKA must be initialized via `init()`.
pub unsafe fn mont_mul(a: &[u32; N_LIMBS], b: &[u32; N_LIMBS]) -> [u32; N_LIMBS] {
    write_operand(RAM_OP1, a);
    write_operand(RAM_OP2, b);
    execute(MODE_MONTGOMERY_MUL);
    read_result(RAM_RESULT)
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
    write_operand(RAM_OP1, a);
    // Modulus is already loaded at RAM_MODULUS from init()
    execute(MODE_MODULAR_INV);
    read_result(RAM_RESULT)
}

/// Modular addition: result = (a + b) mod p
///
/// # Safety
/// PKA must be initialized via `init()`.
pub unsafe fn mod_add(a: &[u32; N_LIMBS], b: &[u32; N_LIMBS]) -> [u32; N_LIMBS] {
    write_operand(RAM_OP1, a);
    write_operand(RAM_OP2, b);
    execute(MODE_MODULAR_ADD);
    read_result(RAM_RESULT)
}

/// Modular subtraction: result = (a - b) mod p
///
/// # Safety
/// PKA must be initialized via `init()`.
pub unsafe fn mod_sub(a: &[u32; N_LIMBS], b: &[u32; N_LIMBS]) -> [u32; N_LIMBS] {
    write_operand(RAM_OP1, a);
    write_operand(RAM_OP2, b);
    execute(MODE_MODULAR_SUB);
    read_result(RAM_RESULT)
}

// ── Extern hook for bls12_381_pka fork ──────────────────────────────────

/// Entry point called by the `bls12_381_pka` fork's `Fp::mul_pka`.
/// The `#[no_mangle]` + `link_name` convention avoids a direct crate dependency.
#[no_mangle]
pub unsafe extern "Rust" fn bls12_381_pka_mont_mul(a: &[u32; N_LIMBS], b: &[u32; N_LIMBS]) -> [u32; N_LIMBS] {
    mont_mul(a, b)
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

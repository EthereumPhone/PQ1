//! STM32U585 Secure AES (SAES) coprocessor driver.
//!
//! Provides AES-256 ECB block primitives under four key selectors:
//!
//! - `KeySel::Software` — key loaded into SAES_KEYR0..7 by firmware. Used
//!   for self-test and as a host-compatible fallback path.
//! - `KeySel::Dhuk`     — Device Hardware Unique Key, TRNG-burnt by ST at
//!   wafer sort, never exposed to firmware. SAES uses it as a selector;
//!   the 256-bit key bytes never appear on the AHB bus or in any memory.
//! - `KeySel::Bhk`      — Boot Hardware Key, software-loaded into TAMP
//!   backup registers at boot, then locked away from firmware via
//!   `TAMP_S->SECCFGR.BHKLOCK`. Not exercised by this driver at the
//!   Tier-1 landing — added to the enum for Tier 2 (`work-todo #7`).
//! - `KeySel::DhukXorBhk` — DHUK XOR BHK, same "selector, not bytes"
//!   property as the parent selectors.
//!
//! ## Higher-level modes
//!
//! This module intentionally exposes ONLY the ECB block primitive. CMAC
//! and any authenticated modes get wrapped in software (the `cmac` crate
//! is already a dependency of the `secure` crate) on top of
//! `encrypt_ecb_block`. Rationale — cut the verified register surface:
//! CMAC mode would add CHMOD/NPBLB/suspend-register bits that we cannot
//! cross-check here without hardware. ECB is the minimum needed for
//! key-selector-based derivations and matches the shape Trezor uses in
//! `core/embed/sec/secure_aes/stm32u5/secure_aes.c`.
//!
//! ## Register / bit sources
//!
//! Offsets + bit positions are taken from two authoritative sources:
//!
//! 1. The `stm32u5` PAC crate (machine-generated from ST's SVD) — see
//!    `stm32u5-0.16.0/src/stm32u585/saes/` for per-register field tables.
//! 2. STM32CubeU5 CMSIS header `stm32u585xx.h` + HAL driver
//!    `stm32u5xx_hal_cryp.c` for the init / encrypt-block flow.
//!
//! Both agree with the RM0456 §"Secure AES (SAES)" description.
//!
//! ## Feature gate
//!
//! Compiled only under the `saes-dhuk` feature, which is OFF by default.
//! Landing the driver under a dedicated gate lets us bench-test it on
//! silicon before flipping any `secret_keys::derive_into` call sites —
//! see task #31 for the flip. Self-test runs at boot under this feature.
//!
//! ## Safety model
//!
//! Peripheral access is funnelled through `hw::mmio::{Reg32, RoReg32}`, so
//! the only `unsafe` for register addresses lives in a single module-scope
//! `const REG` binding. The public API exposes safe functions; a peripheral
//! that has not been clock-enabled bus-faults on the first register access,
//! so "try to use uninit" fails loudly, not silently.

#![allow(clippy::module_name_repetitions)]

use crate::hw::mmio::{Reg32, RoReg32};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Register map — SAES secure-alias base 0x520C_0C00
// (AHB2PERIPH_BASE_S = 0x5202_0000, offset 0xA_0C00).
// ---------------------------------------------------------------------------
const SAES_BASE: u32 = 0x520C_0C00;

/// All MMIO registers this driver owns, bundled so the one-time
/// `unsafe { ... }` for `Reg32::new` happens once at module scope.
///
/// Note KEYR0..KEYR3 sit at 0x10..0x1C (contiguous), then IVR0..IVR3 at
/// 0x20..0x2C (the AES engine's init-vector register, not a key register),
/// then KEYR4..KEYR7 at 0x30..0x3C. Do NOT step across via pointer
/// arithmetic — iterations 4..7 would hit IVR, not high KEYRs.
struct SaesRegs {
    cr: Reg32,
    sr: RoReg32,
    dinr: Reg32,
    doutr: RoReg32,
    keyr0: Reg32,
    keyr1: Reg32,
    keyr2: Reg32,
    keyr3: Reg32,
    keyr4: Reg32,
    keyr5: Reg32,
    keyr6: Reg32,
    keyr7: Reg32,
    icr: Reg32,
    isr: RoReg32,
    rcc_cr: Reg32,
    rcc_ahb2enr1: Reg32,
    rcc_ahb2rstr1: Reg32,
}

// SAFETY: each address below is a real, 4-byte-aligned MMIO register
// exclusively owned by this driver (SAES peripheral + the RCC bits that
// gate it). The secure world is single-threaded and non-preemptive —
// nothing else races us. After this one-time construction every register
// touch is via safe `.read()` / `.write()`.
const REG: SaesRegs = unsafe {
    SaesRegs {
        cr: Reg32::new(SAES_BASE),
        sr: RoReg32::new(SAES_BASE + 0x04),
        dinr: Reg32::new(SAES_BASE + 0x08),
        doutr: RoReg32::new(SAES_BASE + 0x0C),
        keyr0: Reg32::new(SAES_BASE + 0x10),
        keyr1: Reg32::new(SAES_BASE + 0x14),
        keyr2: Reg32::new(SAES_BASE + 0x18),
        keyr3: Reg32::new(SAES_BASE + 0x1C),
        keyr4: Reg32::new(SAES_BASE + 0x30),
        keyr5: Reg32::new(SAES_BASE + 0x34),
        keyr6: Reg32::new(SAES_BASE + 0x38),
        keyr7: Reg32::new(SAES_BASE + 0x3C),
        icr: Reg32::new(SAES_BASE + 0x308),
        isr: RoReg32::new(SAES_BASE + 0x304),
        rcc_cr: Reg32::new(RCC),
        rcc_ahb2enr1: Reg32::new(RCC + 0x8C),
        rcc_ahb2rstr1: Reg32::new(RCC + 0x64),
    }
};

// CR bit positions (from PAC `saes/cr.rs`).
const CR_EN: u32 = 1 << 0;
const CR_MODE_POS: u32 = 3; // bits 3:4 — 0=encrypt, 2=decrypt
const CR_CHMOD_POS: u32 = 5; // bits 5:6 + bit 16 — 0b000=ECB
const CR_KEYSIZE_256: u32 = 1 << 18; // bit 18 — 0=128, 1=256
const CR_KMOD_NORMAL: u32 = 0; // bits 24:25 — 0=normal
const CR_KEYSEL_POS: u32 = 28; // bits 28:30 — KEYSEL selector
const CR_IPRST: u32 = 1 << 31;

// SR bit positions (from PAC `saes/sr.rs`).
const SR_CCF: u32 = 1 << 0;
const SR_RDERR: u32 = 1 << 1;
const SR_WRERR: u32 = 1 << 2;
const SR_BUSY: u32 = 1 << 3;
const SR_KEYVALID: u32 = 1 << 7;

// ISR / ICR bits.
const ICR_CCF: u32 = 1 << 0;
const ICR_RWEIF: u32 = 1 << 1;
const ICR_KEIF: u32 = 1 << 2;
const ICR_RNGEIF: u32 = 1 << 3;
const ISR_RNGEIF: u32 = 1 << 3;

// ---------------------------------------------------------------------------
// RCC registers — use the NS alias (matches `hw::rcc::init`). SAESEN lives
// on AHB2ENR1 bit 20 (per PAC `rcc/ahb2enr1.rs`); SHSI enable+ready live
// on CR bits 14/15. AHB2RSTR1 is at offset 0x64 (AHB1RSTR is at 0x60,
// AHB2RSTR2 at 0x68). Verified against `stm32u5-0.16.0/src/stm32u585/rcc.rs`
// lines 172/177.
// ---------------------------------------------------------------------------
const RCC: u32 = 0x4602_0C00;

const RCC_CR_SHSION: u32 = 1 << 14;
const RCC_CR_SHSIRDY: u32 = 1 << 15;
const RCC_AHB2ENR1_SAESEN: u32 = 1 << 20;
const RCC_AHB2RSTR1_SAESRST: u32 = 1 << 20;

// ~100 ms at 160 MHz ≈ 16_000_000 loop iterations (the body is 1..few
// cycles). We use a generous ceiling — SAES peripheral ops complete in
// tens of cycles; a failed handshake is almost always "never completes".
const TIMEOUT_ITERS: u32 = 16_000_000;

/// Key selector for SAES AES-256 operations. Bit pattern written into
/// `SAES_CR.KEYSEL[2:0]`.
///
/// Matches the STM32 HAL `CRYP_KEYSEL_*` macro values:
///
/// | Selector       | KEYSEL bits | HAL constant        |
/// |----------------|-------------|---------------------|
/// | Software       | 0b000       | `CRYP_KEYSEL_NORMAL`|
/// | Dhuk           | 0b001       | `CRYP_KEYSEL_HW`    |
/// | Bhk            | 0b010       | `CRYP_KEYSEL_SW`    |
/// | DhukXorBhk     | 0b100       | `CRYP_KEYSEL_HSW`   |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySel {
    Software = 0b000,
    Dhuk = 0b001,
    Bhk = 0b010,
    DhukXorBhk = 0b100,
}

/// Errors returned by SAES primitive operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaesError {
    /// `init()` timed out waiting for SHSI to become ready.
    ShsiTimeout,
    /// SAES peripheral reported RNG seed error (`ISR.RNGEIF`) during init.
    /// SAES uses an internal RNG seed for side-channel randomization; if
    /// it fails to seed, the peripheral refuses to operate.
    RngSeedError,
    /// SAES never reported `SR.BUSY=0` after init.
    BusyTimeout,
    /// Computation never completed (`SR.CCF=0`) within timeout.
    CcfTimeout,
    /// SAES reported a read or write bus error during a block op.
    BusError,
    /// SAES reported `SR.KEYVALID=0` when starting an operation against
    /// a hardware key selector (DHUK / BHK / DHUK^BHK). Common cause for
    /// BHK: the TAMP backup registers were not loaded before the op.
    KeyInvalid,
    /// `encrypt_ecb_block` / `decrypt_ecb_block` was called with
    /// `KeySel::Software` but `sw_key == None` (or vice-versa).
    KeyConfigMismatch,
    /// Self-test round-trip failed: decrypt(encrypt(P)) != P.
    SelfTestRoundTrip,
    /// Self-test domain separation failed: DHUK and a software key gave
    /// the same ciphertext on the same plaintext (indicates the KEYSEL
    /// field is NOT being honoured).
    SelfTestDomainCollision,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Enable SHSI, release SAES out of reset, gate its clock on, and clear
/// any stale status flags. Must be called once before any other entry
/// point in this module. Safe to call more than once — idempotent.
pub fn init() -> Result<(), SaesError> {
    // --- 1. Enable SHSI (Secure HSI, the SAES-dedicated 48 MHz source) ---
    // On STM32U5 RCC accepts both the S and NS aliases for most bits; we
    // mirror `hw::rcc` which uses the NS alias successfully.
    REG.rcc_cr.set_bits(RCC_CR_SHSION);

    let mut t = TIMEOUT_ITERS;
    while REG.rcc_cr.read() & RCC_CR_SHSIRDY == 0 {
        t -= 1;
        if t == 0 {
            return Err(SaesError::ShsiTimeout);
        }
    }

    // --- 2. Pulse SAES through reset, then enable its AHB2 clock ---
    // Reset pulse matches Trezor's `__HAL_RCC_SAES_FORCE_RESET /
    // RELEASE_RESET` pair in `secure_aes_init`.
    REG.rcc_ahb2rstr1.set_bits(RCC_AHB2RSTR1_SAESRST);
    cortex_m::asm::dsb();
    REG.rcc_ahb2rstr1.clear_bits(RCC_AHB2RSTR1_SAESRST);

    REG.rcc_ahb2enr1.set_bits(RCC_AHB2ENR1_SAESEN);
    // Dummy read per STM32 errata: ensures the clock-enable write
    // has fully propagated before the first peripheral register
    // access.
    let _ = REG.rcc_ahb2enr1.read();
    cortex_m::asm::dsb();

    // --- 3. Wait for SAES's internal RNG seeding to settle ---
    // HAL `HAL_CRYP_Init` polls SR.BUSY then ISR.RNGEIF before any config
    // write; we replicate that contract.
    let mut t = TIMEOUT_ITERS;
    while REG.sr.read() & SR_BUSY != 0 {
        t -= 1;
        if t == 0 {
            return Err(SaesError::BusyTimeout);
        }
    }
    if REG.isr.read() & ISR_RNGEIF != 0 {
        // Clear the latched error and surface it.
        REG.icr.write(ICR_RNGEIF);
        return Err(SaesError::RngSeedError);
    }

    // --- 4. Clear any stale CCF / error flags from a prior aborted run ---
    // ICR is write-1-to-clear; writing the flag bits is idempotent.
    REG.icr.write(ICR_CCF | ICR_RWEIF | ICR_KEIF | ICR_RNGEIF);

    Ok(())
}

/// Encrypt a single 16-byte block under the chosen key selector.
///
/// For `KeySel::Software`, pass the 32-byte key via `sw_key=Some(..)`.
/// For every other selector the key comes from silicon (DHUK) or TAMP
/// (BHK) and `sw_key` MUST be `None`.
///
/// Returns the 16-byte ciphertext. The caller owns `Zeroize` of both
/// `block_in` (if secret) and the returned array (if secret).
pub fn encrypt_ecb_block(
    keysel: KeySel,
    sw_key: Option<&[u8; 32]>,
    block_in: &[u8; 16],
) -> Result<[u8; 16], SaesError> {
    run_ecb_block(keysel, sw_key, block_in, Mode::Encrypt)
}

/// Decrypt a single 16-byte block under the chosen key selector. Same
/// key-mode contract as `encrypt_ecb_block`.
pub fn decrypt_ecb_block(
    keysel: KeySel,
    sw_key: Option<&[u8; 32]>,
    block_in: &[u8; 16],
) -> Result<[u8; 16], SaesError> {
    run_ecb_block(keysel, sw_key, block_in, Mode::Decrypt)
}

/// Runs two sanity checks against the freshly-initialised peripheral.
///
/// 1. **Software-key round-trip.** Loads an arbitrary 256-bit key,
///    encrypts a test block, decrypts the ciphertext, verifies the
///    recovered plaintext == original. Proves the driver drives the AES
///    engine correctly in ECB mode.
/// 2. **DHUK domain separation.** Encrypts a fixed block first with
///    `KeySel::Software` + an arbitrary key, then with `KeySel::Dhuk`,
///    verifies the two ciphertexts differ. A collision would mean the
///    KEYSEL field is being ignored (DHUK selector returning software-
///    key output, or vice-versa).
///
/// Also logs the DHUK ciphertext via `secure_log!` — operators can
/// cross-check across power cycles to verify DHUK is deterministic
/// per die (same bytes every boot, different between boards).
pub fn self_test() -> Result<(), SaesError> {
    let pt: [u8; 16] = *b"PQSIGNER-SAES-v1";
    let sw_key: [u8; 32] = *b"PQSIGNER-saes-self-test-sw-key!!";

    // (1) SW round-trip.
    secure_log!("[SAES] step 1.1 SW encrypt");
    let ct_sw = encrypt_ecb_block(KeySel::Software, Some(&sw_key), &pt)?;
    secure_log!("[SAES] step 1.2 SW decrypt");
    let pt_back = decrypt_ecb_block(KeySel::Software, Some(&sw_key), &ct_sw)?;
    if pt_back != pt {
        return Err(SaesError::SelfTestRoundTrip);
    }

    // (2) DHUK vs SW — must produce different ciphertexts.
    secure_log!("[SAES] step 2   DHUK encrypt");
    let ct_dhuk = encrypt_ecb_block(KeySel::Dhuk, None, &pt)?;
    if ct_dhuk == ct_sw {
        return Err(SaesError::SelfTestDomainCollision);
    }

    // (3) DHUK self-consistency — encrypt-decrypt round-trip.
    secure_log!("[SAES] step 3   DHUK decrypt");
    let pt_dhuk = decrypt_ecb_block(KeySel::Dhuk, None, &ct_dhuk)?;
    if pt_dhuk != pt {
        return Err(SaesError::SelfTestRoundTrip);
    }

    // Operator-visible fingerprint for cross-boot consistency check.
    // Same 8 bytes of DHUK(pt) across reboots ⇒ DHUK is stable; at
    // RDP0 identical across every STM32U585 (ST substitutes a constant
    // DHUK at RDP0); at RDP ≥ 1 unique per die.
    #[allow(unused_variables)]
    let fp: [u8; 8] = [
        ct_dhuk[0], ct_dhuk[1], ct_dhuk[2], ct_dhuk[3], ct_dhuk[4], ct_dhuk[5], ct_dhuk[6],
        ct_dhuk[7],
    ];
    secure_log!(
        "[SAES] self_test PASS  DHUK(fp)={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        fp[0],
        fp[1],
        fp[2],
        fp[3],
        fp[4],
        fp[5],
        fp[6],
        fp[7]
    );

    // Mirror the PASS line over UART (ST-LINK VCP) so it survives
    // RDP ≥ 1, where semihosting / probe-rs run can't reach us. The
    // caller is responsible for `hw::uart::init()` before this.
    #[cfg(feature = "uart-console")]
    {
        crate::hw::uart::write_str("[SAES] self_test PASS  DHUK(fp)=");
        crate::hw::uart::write_hex_8(&fp);
        crate::hw::uart::write_str("\r\n");
        crate::hw::uart::flush();
    }

    // RDP1 boot diagnostic: write fingerprint to OLED so the user can
    // read it visually even at RDP ≥ 1 where neither SWD nor (hopefully
    // not) UART work. The caller is responsible for `ui::init()`.
    #[cfg(feature = "ui-oled")]
    {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut buf = [0u8; 16];
        for (i, &b) in fp.iter().enumerate() {
            buf[i * 2] = HEX[(b >> 4) as usize];
            buf[i * 2 + 1] = HEX[(b & 0xF) as usize];
        }
        let d = crate::ui::display();
        d.draw_line(3, crate::ui::ascii_str(&buf));
        d.flush();
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Encrypt,
    Decrypt,
}

fn run_ecb_block(
    keysel: KeySel,
    sw_key: Option<&[u8; 32]>,
    block_in: &[u8; 16],
    mode: Mode,
) -> Result<[u8; 16], SaesError> {
    match (keysel, sw_key) {
        (KeySel::Software, Some(_)) | (KeySel::Dhuk | KeySel::Bhk | KeySel::DhukXorBhk, None) => {}
        _ => return Err(SaesError::KeyConfigMismatch),
    }

    // All SAES register touches below are routed through the safe
    // `Reg32` / `RoReg32` API. The peripheral must have been `init`-ed
    // before — hitting an un-clocked peripheral bus faults, so a missed
    // init fails loud.

    // Disable + software reset to wipe any residual state from a
    // prior operation (key registers, intermediate CCF).
    REG.cr.write(CR_IPRST);
    cortex_m::asm::dsb();
    REG.cr.write(0);
    REG.icr.write(ICR_CCF | ICR_RWEIF | ICR_KEIF);

    // Wait for the internal RNG seed after reset.
    let mut t = TIMEOUT_ITERS;
    while REG.sr.read() & SR_BUSY != 0 {
        t -= 1;
        if t == 0 {
            return Err(SaesError::BusyTimeout);
        }
    }
    if REG.isr.read() & ISR_RNGEIF != 0 {
        REG.icr.write(ICR_RNGEIF);
        return Err(SaesError::RngSeedError);
    }

    // Build the CR base: CHMOD=ECB (0), DATATYPE=no swap (0),
    // KEYSIZE=256, KMOD=normal (0), KEYSEL per-caller. MODE bits
    // stay 0 (encrypt) initially — we toggle MODE separately for
    // the KD pre-pass + final decrypt pass. EN stays OFF.
    let keysel_bits = (keysel as u32) << CR_KEYSEL_POS;
    let cr_base = CR_KEYSIZE_256 | keysel_bits | CR_KMOD_NORMAL;
    // CHMOD_POS bits stay 0 (ECB).
    let _ = CR_CHMOD_POS;
    REG.cr.write(cr_base);

    // Load the software key (reversed-high-word order per HAL
    // `CRYP_SetKey`) — only for KeySel::Software; for DHUK/BHK the
    // silicon drives the key registers.
    if let Some(key) = sw_key {
        // HAL contract: KEYR7 = first 4 bytes (MSB of key), KEYR0 =
        // last 4 bytes (LSB of key). Each u32 is read in native
        // little-endian from the source buffer.
        let k0 = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
        let k1 = u32::from_le_bytes([key[4], key[5], key[6], key[7]]);
        let k2 = u32::from_le_bytes([key[8], key[9], key[10], key[11]]);
        let k3 = u32::from_le_bytes([key[12], key[13], key[14], key[15]]);
        let k4 = u32::from_le_bytes([key[16], key[17], key[18], key[19]]);
        let k5 = u32::from_le_bytes([key[20], key[21], key[22], key[23]]);
        let k6 = u32::from_le_bytes([key[24], key[25], key[26], key[27]]);
        let k7 = u32::from_le_bytes([key[28], key[29], key[30], key[31]]);
        REG.keyr7.write(k0);
        REG.keyr6.write(k1);
        REG.keyr5.write(k2);
        REG.keyr4.write(k3);
        REG.keyr3.write(k4);
        REG.keyr2.write(k5);
        REG.keyr1.write(k6);
        REG.keyr0.write(k7);
    }

    // For the BHK selectors (`Bhk` = "software key" loaded from the
    // TAMP backup registers, `DhukXorBhk` = DHUK XOR that), the SAES
    // only latches the BHK after the CPU reads TAMP_BKP0R..BKP7R —
    // 8 dummy reads, a hardware side-effect even when `BHKLOCK` is
    // set (the reads return 0 to the CPU but trigger the SAES to
    // pull the real, hardware-visible BHK). This mirrors Trezor's
    // `secure_aes_load_bhk()` in `core/embed/sec/secure_aes/stm32u5/
    // secure_aes.c`, called between `HAL_CRYP_Init` (which programs
    // KEYSEL) and the encrypt/decrypt op. Without it, `SR.KEYVALID`
    // never asserts and the op times out with `KeyInvalid`.
    //
    // Only compiled under `bhk` — `KeySel::Bhk` is never used unless
    // the BHK lifecycle (`hw::bhk`) is in the build, which `bhk`
    // gates. TAMP secure-alias base 0x5600_7C00; BKP0R at +0x100.
    #[cfg(feature = "bhk")]
    if matches!(keysel, KeySel::Bhk | KeySel::DhukXorBhk) {
        const TAMP_BKP0R: u32 = 0x5600_7C00 + 0x100;
        // SAFETY: TAMP_BKP0R..BKP7R is a contiguous 8-word MMIO bank;
        // reading is side-effect-only (triggers SAES BHK latch). The
        // secure world is single-threaded.
        let bkp0r = unsafe { RoReg32::new(TAMP_BKP0R) };
        for i in 0..8usize {
            // SAFETY: offset i ∈ 0..8 stays inside the BKP0R..BKP7R bank.
            let _ = unsafe { bkp0r.read_at(i) };
        }
        cortex_m::asm::dsb();
    }

    // Wait for SR.KEYVALID — HAL polls this in CRYP_AES_Encrypt /
    // Decrypt for every SAES op, regardless of KEYSEL. For SW keys
    // it asserts after the KEYR writes settle; for DHUK/BHK it
    // asserts after the silicon pulls the selected key into the
    // engine's internal key path. Doing this BEFORE any KD or
    // encrypt pass is critical — starting EN without KEYVALID
    // leaves the engine waiting forever and CCF never sets.
    let mut t = TIMEOUT_ITERS;
    while REG.sr.read() & SR_KEYVALID == 0 {
        t -= 1;
        if t == 0 {
            return Err(SaesError::KeyInvalid);
        }
    }

    // For decrypt we first run MODE=key-derivation (0b01) so the
    // engine expands the last-round key for inverse cipher. HAL
    // keeps EN=1 across the MODE=KD → MODE=DECRYPT transition —
    // dropping EN between the two would lose the derived state.
    let mode_final = match mode {
        Mode::Encrypt => 0u32,                   // MODE = 0b00
        Mode::Decrypt => 0b10u32 << CR_MODE_POS, // MODE = 0b10
    };
    if mode == Mode::Decrypt {
        let cr_kd = cr_base | (0b01u32 << CR_MODE_POS);
        REG.cr.write(cr_kd | CR_EN);
        // Wait CCF — KD pass completes with no DINR/DOUTR traffic.
        let mut t = TIMEOUT_ITERS;
        loop {
            let sr = REG.sr.read();
            if sr & (SR_RDERR | SR_WRERR) != 0 {
                return Err(SaesError::BusError);
            }
            if sr & SR_CCF != 0 {
                break;
            }
            t -= 1;
            if t == 0 {
                return Err(SaesError::CcfTimeout);
            }
        }
        REG.icr.write(ICR_CCF);
        // Switch MODE to decrypt while EN stays set.
        let cr_dec = cr_base | mode_final;
        REG.cr.write(cr_dec | CR_EN);
    } else {
        // Encrypt: enable with the final MODE bits (which are 0).
        REG.cr.write(cr_base | mode_final | CR_EN);
    }

    // Everything below uses the final CR value for subsequent
    // MODIFY operations and clean-up.
    let cr = cr_base | mode_final;

    // Feed the plaintext block — 4 × u32 read from `block_in` in
    // native LE (matches HAL `CRYP_AES_ProcessData`).
    REG.dinr.write(u32::from_le_bytes([
        block_in[0], block_in[1], block_in[2], block_in[3],
    ]));
    REG.dinr.write(u32::from_le_bytes([
        block_in[4], block_in[5], block_in[6], block_in[7],
    ]));
    REG.dinr.write(u32::from_le_bytes([
        block_in[8], block_in[9], block_in[10], block_in[11],
    ]));
    REG.dinr.write(u32::from_le_bytes([
        block_in[12], block_in[13], block_in[14], block_in[15],
    ]));

    // Poll CCF / error flags.
    let mut t = TIMEOUT_ITERS;
    loop {
        let sr = REG.sr.read();
        if sr & (SR_RDERR | SR_WRERR) != 0 {
            return Err(SaesError::BusError);
        }
        if sr & SR_CCF != 0 {
            break;
        }
        t -= 1;
        if t == 0 {
            return Err(SaesError::CcfTimeout);
        }
    }

    // Drain DOUTR — 4 × u32 → 16 bytes back in LE order.
    let d0 = REG.doutr.read().to_le_bytes();
    let d1 = REG.doutr.read().to_le_bytes();
    let d2 = REG.doutr.read().to_le_bytes();
    let d3 = REG.doutr.read().to_le_bytes();

    // Clear CCF before disabling; keeps next run clean.
    REG.icr.write(ICR_CCF);
    REG.cr.write(cr); // drop EN

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&d0);
    out[4..8].copy_from_slice(&d1);
    out[8..12].copy_from_slice(&d2);
    out[12..16].copy_from_slice(&d3);

    // Zero the key registers on exit so a later op with a different
    // selector cannot accidentally pick up these bytes. KEYR4..7 sit
    // past IVR0..3, so enumerate each register explicitly — pointer
    // arithmetic across the non-contiguous region would hit IVR, not
    // high KEYR.
    if sw_key.is_some() {
        REG.keyr0.write(0);
        REG.keyr1.write(0);
        REG.keyr2.write(0);
        REG.keyr3.write(0);
        REG.keyr4.write(0);
        REG.keyr5.write(0);
        REG.keyr6.write(0);
        REG.keyr7.write(0);
    }

    // Scrub intermediate stack scratch.
    let mut d0z = d0;
    let mut d1z = d1;
    let mut d2z = d2;
    let mut d3z = d3;
    d0z.zeroize();
    d1z.zeroize();
    d2z.zeroize();
    d3z.zeroize();

    Ok(out)
}

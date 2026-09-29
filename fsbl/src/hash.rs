//! FSBL side of the shared STM32U585 HASH driver.
//!
//! The driver itself lives in [`pqsigner_hw::hash`] — one copy, shared with
//! the secure world. This file supplies the two things that differ here:
//!
//!   1. `pqsigner_hash_fault`, the unrecoverable-engine posture.
//!   2. Making HASH secure in GTZC before the driver touches it.
//!
//! WHY THIS EXISTS AT ALL. `sha2::sha256::compress256` was 7,202 B — 23.4% of
//! a 32 KiB image with 2,048 B free. Routing every SHA-256 consumer through
//! the peripheral removes it (measured: 30,720 -> 22,152 B with a stub) and is
//! also ~1.5 s faster, since software SHA-256 at HSI16 costs 1.167 s for the
//! secure image plus 0.375 s for the C10 manifest chain.

use pqsigner_hw::mmio::Reg32;

// ---------------------------------------------------------------------------
// GTZC: HASH must be made SECURE before the driver uses the secure alias
// ---------------------------------------------------------------------------
//
// THIS IS THE STEP THE SECURE WORLD NEVER NEEDED, and getting it wrong is the
// trap: HASH is a SECURABLE peripheral (RM0456 Rev 7, Table 4 "Securable
// peripherals by TZSC") and RM0456 §3.5 states that "Securable peripherals are
// nonsecure after reset" — GTZC1_TZSC_SECCFGR1 has reset value 0x0000_0000.
//
// `secure/src/hw/hash.rs` gets to use the secure alias because `sau.rs` sets
// GTZC1_TZSC_SECCFGR3 bit 12 (HASHSEC) long before anything hashes. The FSBL
// runs BEFORE `sau.rs` and configures no GTZC at all, so it inherits nothing
// and must set the bit itself.
//
// A driver that skipped this could still appear to work on a warm bench reset
// and fail from cold — the worst possible failure shape for the code that
// measures the firmware.

/// `GTZC_TZSC1_BASE_S` = PERIPH_BASE_S 0x5000_0000 + AHB1PERIPH 0x0002_0000 +
/// TZSC1 0x0001_2400. Same constant `secure/src/sau.rs` uses.
const TZSC_BASE: u32 = 0x5003_2400;

/// `GTZC1_TZSC_SECCFGR3` — the AHB2 bank carrying the crypto block.
const TZSC_SECCFGR3: u32 = TZSC_BASE + 0x18;

/// Bit 12 = HASHSEC. Matches `secure/src/sau.rs`'s `SECCFGR3_HASH_BIT`.
const SECCFGR3_HASH_BIT: u32 = 1 << 12;

/// Make HASH a secure peripheral, then bring the driver up and run its KAT.
///
/// Read-modify-write rather than a bare store: the FSBL has no business
/// deciding the security attribute of any peripheral it does not use, and a
/// wholesale write would silently clear bits a future stage had set.
///
/// # Safety
/// Boot-time, single-threaded, before any SHA-256 call. Requires TZEN = 1,
/// which holds by construction — the FSBL is the secure boot image and only
/// runs on a device whose option bytes enabled TrustZone.
pub unsafe fn init() {
    // SAFETY: one-time MMIO binding. `TZSC_SECCFGR3` is a real 4-byte-aligned
    // register in the GTZC1 TZSC block, and nothing else in the FSBL touches
    // GTZC.
    let seccfgr3 = unsafe { Reg32::new(TZSC_SECCFGR3) };
    seccfgr3.set_bits(SECCFGR3_HASH_BIT);
    cortex_m::asm::dsb();

    // SAFETY: forwarded contract — boot-time, single-threaded, no hash in
    // flight. Enables the HASH clock, pulses HASHRST and runs the
    // SHA-256("abc") known-answer test, halting on mismatch.
    unsafe { pqsigner_hw::hash::init_clock() };
}

/// Unrecoverable HASH engine — halt.
///
/// The secure world's version of this symbol zeroizes every in-SRAM secret and
/// resets, because it may be holding `master_secret` and a cached slot key.
/// The FSBL holds neither: it runs before PIN entry, so there is nothing to
/// wipe. It also must NOT reset — the FSBL is what runs after a reset, so
/// resetting here would spin forever with no diagnostic.
///
/// Halting is the honest outcome. A HASH engine that cannot complete a digest
/// cannot measure the firmware, and an FSBL that cannot measure the firmware
/// must not branch into it: that is invariant #10's whole premise.
#[no_mangle]
pub extern "C" fn pqsigner_hash_fault() -> ! {
    loop {
        cortex_m::asm::wfe();
    }
}

//! Hardware True Random Number Generator driver for STM32U585.
//!
//! Uses the RNG peripheral at 0x520C0800 (secure alias).
//! Requires HSI48 enabled and RNG clock selected (done by rcc::init).

use core::ptr::{read_volatile, write_volatile};

// RNG register base (SECURE alias — AHB2 bus). With TZEN=1 the GTZC
// secures the RNG peripheral by default; NS-alias accesses (0x420C_0800)
// are rejected by the bus fabric (reads return 0, writes are dropped)
// even from the secure master, which was the root cause of first-boot
// "rng::fill FAILED". Talk to the peripheral from the secure world
// via 0x52xx... instead.
const RNG: u32 = 0x520C_0800;

const RNG_CR: *mut u32 = (RNG + 0x00) as *mut u32;
const RNG_SR: *mut u32 = (RNG + 0x04) as *mut u32;
const RNG_DR: *const u32 = (RNG + 0x08) as *const u32;

// CR bits
const RNGEN: u32 = 1 << 2;
// CONDRST lives at bit 30 on STM32U5, not bit 6 (bit 6 is part of CONFIG1).
const CONDRST: u32 = 1 << 30;

// SR bits
const DRDY: u32 = 1 << 0;
const CECS: u32 = 1 << 1;
const SECS: u32 = 1 << 2;
const CEIS: u32 = 1 << 5;
const SEIS: u32 = 1 << 6;

// NIST-compliant default CR config for STM32U5 (from ST's LL driver —
// CONFIG3=0x0F, CONFIG1=0x34, NISTC=0). Using the wrong CR layout here is
// what caused the first-boot wizard to see `rng::fill FAILED`.
const RNG_CR_NIST_DEFAULT: u32 = 0x00F0_0D00;

/// Initialize the RNG peripheral. Must be called after `rcc::init()`.
pub unsafe fn init() {
    // 1. Enter config mode with the NIST-compliant CR value.
    write_volatile(RNG_CR, RNG_CR_NIST_DEFAULT | CONDRST);
    // 2. Leave config mode (clear CONDRST) while keeping the config bits.
    write_volatile(RNG_CR, RNG_CR_NIST_DEFAULT);
    // 3. Clear any latched seed / clock error interrupts from pre-init.
    write_volatile(RNG_SR, 0);
    // 4. Enable the RNG.
    write_volatile(RNG_CR, RNG_CR_NIST_DEFAULT | RNGEN);

    // 5. Wait for first random number, discard it (conditioning warmup).
    let mut timeout = 0u32;
    while read_volatile(RNG_SR) & DRDY == 0 {
        timeout += 1;
        if timeout > 1_000_000 {
            return;
        }
    }
    let _ = read_volatile(RNG_DR);
}

/// Fill `buf` with random bytes from the hardware TRNG.
/// Returns `Err(())` if the RNG reports a seed or clock error.
pub fn fill(buf: &mut [u8]) -> Result<(), ()> {
    unsafe {
        let sr0 = read_volatile(RNG_SR);
        let cr0 = read_volatile(RNG_CR);
        secure_log!(
            "[S] rng::fill entry: CR=0x{:08x} SR=0x{:08x}",
            cr0, sr0
        );

        // If the peripheral has latched a seed / clock error interrupt,
        // RM0456 requires clearing SEIS/CEIS and re-running the conditioning
        // reset. Do a best-effort recovery once before bailing.
        if sr0 & (SEIS | CEIS) != 0 {
            secure_log!("[S] rng::fill: latched SEIS/CEIS — recovering");
            write_volatile(RNG_SR, sr0 & !(SEIS | CEIS));
            init();
            let sr1 = read_volatile(RNG_SR);
            let cr1 = read_volatile(RNG_CR);
            secure_log!(
                "[S] rng::fill after recover: CR=0x{:08x} SR=0x{:08x}",
                cr1, sr1
            );
        }

        let mut i = 0;
        while i < buf.len() {
            let mut timeout = 0u32;
            loop {
                let sr = read_volatile(RNG_SR);
                if sr & (SECS | CECS) != 0 {
                    secure_log!(
                        "[S] rng::fill: SECS/CECS set SR=0x{:08x}", sr
                    );
                    return Err(());
                }
                if sr & DRDY != 0 {
                    break;
                }
                timeout += 1;
                if timeout > 1_000_000 {
                    let sr_end = read_volatile(RNG_SR);
                    let cr_end = read_volatile(RNG_CR);
                    secure_log!(
                        "[S] rng::fill: DRDY timeout CR=0x{:08x} SR=0x{:08x}",
                        cr_end, sr_end
                    );
                    return Err(());
                }
            }

            let word = read_volatile(RNG_DR);
            let bytes = word.to_le_bytes();
            for &b in &bytes {
                if i >= buf.len() {
                    break;
                }
                buf[i] = b;
                i += 1;
            }
        }
    }
    Ok(())
}

/// One-shot single-byte helper (mirrors host_rng::byte API).
pub fn byte() -> u8 {
    let mut b = [0u8; 1];
    fill(&mut b).expect("hw_rng: TRNG read failed");
    b[0]
}

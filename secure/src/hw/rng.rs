//! Hardware True Random Number Generator driver for STM32U585.
//!
//! Uses the RNG peripheral at 0x520C0800 (secure alias).
//! Requires HSI48 enabled and RNG clock selected (done by rcc::init).

use core::ptr::{read_volatile, write_volatile};

// RNG register base (S alias — AHB2 bus). Must use the secure alias
// from secure code: after CRIT-4 TZSC config, the RNG peripheral is
// marked SECURE in GTZC1_TZSC_SECCFGRx, so NS-alias accesses (0x420C_0800)
// are rejected by the bus fabric.
const RNG: u32 = 0x520C_0800;

const RNG_CR: *mut u32 = (RNG + 0x00) as *mut u32;
const RNG_SR: *const u32 = (RNG + 0x04) as *const u32;
const RNG_DR: *const u32 = (RNG + 0x08) as *const u32;

// CR bits
const RNGEN: u32 = 1 << 2;
const CONDRST: u32 = 1 << 6;

// SR bits
const DRDY: u32 = 1 << 0;
const SECS: u32 = 1 << 2;
const CECS: u32 = 1 << 1;

/// Initialize the RNG peripheral. Must be called after `rcc::init()`.
pub unsafe fn init() {
    // Conditioning soft reset + enable
    write_volatile(RNG_CR, CONDRST | RNGEN);
    // Release conditioning reset
    write_volatile(RNG_CR, RNGEN);

    // Wait for first random number to be ready (discarded internally)
    let mut timeout = 0u32;
    while read_volatile(RNG_SR) & DRDY == 0 {
        timeout += 1;
        if timeout > 1_000_000 {
            // RNG failed to start — caller will get an error on fill()
            return;
        }
    }
    // Discard first value (conditioning warmup)
    let _ = read_volatile(RNG_DR);
}

/// Fill `buf` with random bytes from the hardware TRNG.
/// Returns `Err(())` if the RNG reports a seed or clock error.
pub fn fill(buf: &mut [u8]) -> Result<(), ()> {
    unsafe {
        let mut i = 0;
        while i < buf.len() {
            // Wait for data ready
            let mut timeout = 0u32;
            loop {
                let sr = read_volatile(RNG_SR);
                if sr & (SECS | CECS) != 0 {
                    return Err(()); // seed error or clock error
                }
                if sr & DRDY != 0 {
                    break;
                }
                timeout += 1;
                if timeout > 1_000_000 {
                    return Err(());
                }
            }

            // Read 32 bits of entropy
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

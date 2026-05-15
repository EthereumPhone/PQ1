//! Hardware True Random Number Generator driver for STM32U585.
//!
//! Uses the RNG peripheral at 0x520C0800 (secure alias).
//! Requires HSI48 enabled and RNG clock selected (done by rcc::init).

use crate::hw::mmio::{Reg32, RoReg32};

// RNG register base (SECURE alias — AHB2 bus). With TZEN=1 the GTZC
// secures the RNG peripheral by default; NS-alias accesses (0x420C_0800)
// are rejected by the bus fabric (reads return 0, writes are dropped)
// even from the secure master, which was the root cause of first-boot
// "rng::fill FAILED". Talk to the peripheral from the secure world
// via 0x52xx... instead.
const RNG: u32 = 0x520C_0800;

struct RngRegs {
    cr: Reg32,
    sr: Reg32,
    dr: RoReg32,
}

// SAFETY: each address is a real, 4-byte-aligned MMIO register exclusively
// owned by the RNG driver in the single-threaded secure world.
const REG: RngRegs = unsafe {
    RngRegs {
        cr: Reg32::new(RNG + 0x00),
        sr: Reg32::new(RNG + 0x04),
        dr: RoReg32::new(RNG + 0x08),
    }
};

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
pub fn init() {
    // 1. Enter config mode with the NIST-compliant CR value.
    REG.cr.write(RNG_CR_NIST_DEFAULT | CONDRST);
    // 2. Leave config mode (clear CONDRST) while keeping the config bits.
    REG.cr.write(RNG_CR_NIST_DEFAULT);
    // 3. Clear any latched seed / clock error interrupts from pre-init.
    REG.sr.write(0);
    // 4. Enable the RNG.
    REG.cr.write(RNG_CR_NIST_DEFAULT | RNGEN);

    // 5. Wait for first random number, discard it (conditioning warmup).
    let mut timeout = 0u32;
    while REG.sr.read() & DRDY == 0 {
        timeout += 1;
        if timeout > 1_000_000 {
            return;
        }
    }
    let _ = REG.dr.read();
}

/// Fill `buf` with random bytes from the hardware TRNG.
/// Returns `Err(())` if the RNG reports a seed or clock error.
pub fn fill(buf: &mut [u8]) -> Result<(), ()> {
    let sr0 = REG.sr.read();
    let cr0 = REG.cr.read();
    secure_log!(
        "[S] rng::fill entry: CR=0x{:08x} SR=0x{:08x}",
        cr0, sr0
    );

    // If the peripheral has latched a seed / clock error interrupt,
    // RM0456 requires clearing SEIS/CEIS and re-running the conditioning
    // reset. Do a best-effort recovery once before bailing.
    if sr0 & (SEIS | CEIS) != 0 {
        secure_log!("[S] rng::fill: latched SEIS/CEIS — recovering");
        REG.sr.write(sr0 & !(SEIS | CEIS));
        init();
        let sr1 = REG.sr.read();
        let cr1 = REG.cr.read();
        secure_log!(
            "[S] rng::fill after recover: CR=0x{:08x} SR=0x{:08x}",
            cr1, sr1
        );
    }

    let mut i = 0;
    while i < buf.len() {
        let mut timeout = 0u32;
        loop {
            let sr = REG.sr.read();
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
                let sr_end = REG.sr.read();
                let cr_end = REG.cr.read();
                secure_log!(
                    "[S] rng::fill: DRDY timeout CR=0x{:08x} SR=0x{:08x}",
                    cr_end, sr_end
                );
                return Err(());
            }
        }

        let word = REG.dr.read();
        let bytes = word.to_le_bytes();
        for &b in &bytes {
            if i >= buf.len() {
                break;
            }
            buf[i] = b;
            i += 1;
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

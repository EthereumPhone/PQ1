//! I2C1 peripheral driver for STM32U585.
//!
//! Drives the SSD1306 OLED display over I2C1 on the B-U585I-IOT02A board.
//!
//! Pin mapping (from UM2839 Table 24, Arduino connector CN13):
//!   PB8 = I2C1_SCL (AF4)  — CN13 pin 10
//!   PB9 = I2C1_SDA (AF4)  — CN13 pin 9
//!
//! The AZDelivery SSD1306 module has on-board 4.7 kΩ pull-ups on SDA/SCL.

use crate::hw::mmio::{Reg32, RoReg32};

// ---------------------------------------------------------------------------
// RCC registers (secure alias — writes via NS alias are silently ignored
// when TZEN=1).
// ---------------------------------------------------------------------------
const RCC_S: u32 = 0x5602_0C00;

// ---------------------------------------------------------------------------
// GPIOB registers (secure alias)
// ---------------------------------------------------------------------------
const GPIOB_S: u32 = 0x5202_0400;

// ---------------------------------------------------------------------------
// I2C1 registers (secure alias — APB1 peripherals are secure with TZEN=1)
// Base: 0x4000_5400 (NS) / 0x5000_5400 (S)  — from stm32u585xx.h
// ---------------------------------------------------------------------------
const I2C1: u32 = 0x5000_5400;

struct I2cRegs {
    rcc_ahb2enr1: Reg32,
    rcc_apb1enr1: Reg32,
    rcc_apb1rstr1: Reg32,
    gpiob_moder: Reg32,
    gpiob_otyper: Reg32,
    gpiob_ospeedr: Reg32,
    gpiob_pupdr: Reg32,
    gpiob_afrh: Reg32,
    cr1: Reg32,
    cr2: Reg32,
    timingr: Reg32,
    isr: RoReg32,
    icr: Reg32,
    txdr: Reg32,
}

// SAFETY: each address is a real, 4-byte-aligned MMIO register owned by
// this I2C1 driver in the single-threaded secure world. Shared RCC and
// GPIOB registers are accessed via disjoint-bit RMW (PB8/PB9 here;
// other drivers touch other pins).
const REG: I2cRegs = unsafe {
    I2cRegs {
        rcc_ahb2enr1: Reg32::new(RCC_S + 0x8C),
        rcc_apb1enr1: Reg32::new(RCC_S + 0x9C),
        rcc_apb1rstr1: Reg32::new(RCC_S + 0x74),
        gpiob_moder: Reg32::new(GPIOB_S + 0x00),
        gpiob_otyper: Reg32::new(GPIOB_S + 0x04),
        gpiob_ospeedr: Reg32::new(GPIOB_S + 0x08),
        gpiob_pupdr: Reg32::new(GPIOB_S + 0x0C),
        gpiob_afrh: Reg32::new(GPIOB_S + 0x24),
        cr1: Reg32::new(I2C1 + 0x00),
        cr2: Reg32::new(I2C1 + 0x04),
        timingr: Reg32::new(I2C1 + 0x10),
        isr: RoReg32::new(I2C1 + 0x18),
        icr: Reg32::new(I2C1 + 0x1C),
        txdr: Reg32::new(I2C1 + 0x28),
    }
};

// ISR bit masks
const TXIS: u32 = 1 << 1;
const NACKF: u32 = 1 << 4;
const STOPF: u32 = 1 << 5;
const TCR: u32 = 1 << 7;
const BERR: u32 = 1 << 8;
const ARLO: u32 = 1 << 9;
const BUSY: u32 = 1 << 15;

/// Generous timeout (~60 ms at 160 MHz). If a single I2C flag poll exceeds
/// this, something is fundamentally broken and we bail out.
const TIMEOUT: u32 = 10_000_000;

/// Initialize I2C1: GPIO (PB8/PB9 AF4 open-drain), clock, timing (~100 kHz).
pub fn init(sysclk_mhz: u32) {
    // ---- 1. Enable GPIOB clock (AHB2ENR1 bit 1) ----
    REG.rcc_ahb2enr1.set_bits(1 << 1);
    cortex_m::asm::dsb();

    // ---- 2. Enable I2C1 clock (APB1ENR1 bit 21) ----
    REG.rcc_apb1enr1.set_bits(1 << 21);
    cortex_m::asm::dsb();

    // ---- 3. Reset I2C1 peripheral ----
    REG.rcc_apb1rstr1.set_bits(1 << 21);
    cortex_m::asm::dsb();
    REG.rcc_apb1rstr1.clear_bits(1 << 21);
    cortex_m::asm::dsb();

    // ---- 4. Configure PB8 (SCL) and PB9 (SDA) ----
    // MODER: AF mode (0b10) for pins 8 and 9
    REG.gpiob_moder.modify(|v| {
        (v & !(0b11 << 16) & !(0b11 << 18)) | (0b10 << 16) | (0b10 << 18)
    });

    // OTYPER: open-drain (1) for pins 8 and 9
    REG.gpiob_otyper.set_bits((1 << 8) | (1 << 9));

    // OSPEEDR: very-high speed for pins 8 and 9
    REG.gpiob_ospeedr.set_bits((0b11 << 16) | (0b11 << 18));

    // PUPDR: pull-up (0b01) — safety net alongside the module's 4.7 kΩ
    REG.gpiob_pupdr.modify(|v| {
        (v & !(0b11 << 16) & !(0b11 << 18)) | (0b01 << 16) | (0b01 << 18)
    });

    // AFRH: AF4 for PB8 (bits [3:0]) and PB9 (bits [7:4])
    REG.gpiob_afrh.modify(|v| {
        (v & !(0xF << 0) & !(0xF << 4)) | (4 << 0) | (4 << 4)
    });

    // ---- 5. Configure I2C1 timing ----
    // Disable I2C before writing TIMINGR.
    REG.cr1.write(0);
    cortex_m::asm::dsb();

    // Both presets prescale to 16 MHz, then use identical SCLH/SCLL for
    // ~100 kHz standard-mode operation.
    //   SCLDEL=4, SDADEL=2, SCLH=63 → t_HIGH≈4.0 µs, SCLL=79 → t_LOW≈5.0 µs
    let timing = if sysclk_mhz >= 160 {
        0x9042_3F4F // PRESC=9: 160/(9+1)=16 MHz
    } else {
        0x0042_3F4F // PRESC=0: 16/(0+1)=16 MHz
    };
    REG.timingr.write(timing);

    // ---- 6. Enable I2C1 (PE=1, analog filter on by default) ----
    REG.cr1.write(1);
    cortex_m::asm::dsb();

    #[cfg(feature = "debug-log")]
    secure_log!(
        "[S][I2C] I2C1 ready (CR1=0x{:08x} ISR=0x{:08x})",
        REG.cr1.read(),
        REG.isr.read(),
    );
}

/// Write `data` to I2C device at 7-bit address `addr`.
///
/// Handles transfers >255 bytes via the hardware RELOAD mechanism.
/// Returns `true` on success, `false` on NACK/timeout/bus error.
pub fn write(addr: u8, data: &[u8]) -> bool {
    let total = data.len();
    if total == 0 {
        return true;
    }

    // Wait for bus idle (with timeout).
    let mut t = TIMEOUT;
    while REG.isr.read() & BUSY != 0 {
        t -= 1;
        if t == 0 {
            // Bus stuck busy — attempt recovery by disabling/re-enabling PE.
            let cr1 = REG.cr1.read();
            REG.cr1.write(cr1 & !1);
            cortex_m::asm::dsb();
            REG.cr1.write(cr1 | 1);
            cortex_m::asm::dsb();
            return false;
        }
    }

    let mut offset = 0usize;
    let mut remaining = total;

    while remaining > 0 {
        let chunk = if remaining > 255 { 255 } else { remaining };
        let last_chunk = remaining <= 255;

        let mut cr2: u32 = (addr as u32) << 1; // SADD[7:1]
        cr2 |= (chunk as u32) << 16; // NBYTES
        if offset == 0 {
            cr2 |= 1 << 13; // START
        }
        if last_chunk {
            cr2 |= 1 << 25; // AUTOEND
        } else {
            cr2 |= 1 << 24; // RELOAD
        }
        REG.cr2.write(cr2);

        for _ in 0..chunk {
            // Wait for TXIS (transmit register empty) with timeout.
            t = TIMEOUT;
            loop {
                let isr = REG.isr.read();
                if isr & (NACKF | BERR | ARLO) != 0 {
                    // Clear all error flags.
                    REG.icr.write(NACKF | BERR | ARLO | STOPF);
                    return false;
                }
                if isr & TXIS != 0 {
                    break;
                }
                t -= 1;
                if t == 0 {
                    #[cfg(feature = "debug-log")]
                    secure_log!(
                        "[S][I2C] TXIS timeout! ISR=0x{:08x} CR2=0x{:08x}",
                        REG.isr.read(),
                        REG.cr2.read(),
                    );
                    // Abort: disable PE, clear, re-enable.
                    let cr1 = REG.cr1.read();
                    REG.cr1.write(cr1 & !1);
                    cortex_m::asm::dsb();
                    REG.cr1.write(cr1 | 1);
                    return false;
                }
            }
            REG.txdr.write(data[offset] as u32);
            offset += 1;
        }

        remaining -= chunk;

        if !last_chunk {
            // Wait for TCR (transfer complete reload) before next chunk.
            t = TIMEOUT;
            while REG.isr.read() & TCR == 0 {
                t -= 1;
                if t == 0 {
                    return false;
                }
            }
        }
    }

    // AUTOEND generates the STOP condition; wait for it.
    t = TIMEOUT;
    while REG.isr.read() & STOPF == 0 {
        t -= 1;
        if t == 0 {
            return false;
        }
    }
    REG.icr.write(STOPF);
    true
}

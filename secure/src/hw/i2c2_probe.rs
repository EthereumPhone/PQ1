//! I2C2 bus scanner for detecting on-board peripherals (STSAFE-A110, etc.)
//! on the B-U585I-IOT02A development board.
//!
//! The STSAFE-A110 is soldered on-board and connected to I2C2:
//!   PH4 = I2C2_SCL (AF4)
//!   PH5 = I2C2_SDA (AF4)
//!   Default 7-bit address: 0x20
//!
//! This module initializes I2C2 and scans the bus for responding devices.

use core::ptr::{read_volatile, write_volatile};

// ---------------------------------------------------------------------------
// RCC registers (secure alias)
// ---------------------------------------------------------------------------
const RCC_S: u32 = 0x5602_0C00;
const RCC_AHB2ENR1: *mut u32 = (RCC_S + 0x8C) as *mut u32;
const RCC_APB1ENR1: *mut u32 = (RCC_S + 0x9C) as *mut u32;
const RCC_APB1RSTR1: *mut u32 = (RCC_S + 0x74) as *mut u32;

// ---------------------------------------------------------------------------
// GPIOH registers (secure alias)
// Port H base = 0x5202_1C00
// ---------------------------------------------------------------------------
const GPIOH_S: u32 = 0x5202_1C00;
const GPIOH_MODER: *mut u32 = (GPIOH_S + 0x00) as *mut u32;
const GPIOH_OTYPER: *mut u32 = (GPIOH_S + 0x04) as *mut u32;
const GPIOH_OSPEEDR: *mut u32 = (GPIOH_S + 0x08) as *mut u32;
const GPIOH_PUPDR: *mut u32 = (GPIOH_S + 0x0C) as *mut u32;
const GPIOH_AFRL: *mut u32 = (GPIOH_S + 0x20) as *mut u32;

// ---------------------------------------------------------------------------
// I2C2 registers (secure alias)
// I2C2 base: 0x4000_5800 (NS) / 0x5000_5800 (S)
// ---------------------------------------------------------------------------
const I2C2: u32 = 0x5000_5800;
const I2C2_CR1: *mut u32 = (I2C2 + 0x00) as *mut u32;
const I2C2_CR2: *mut u32 = (I2C2 + 0x04) as *mut u32;
const I2C2_TIMINGR: *mut u32 = (I2C2 + 0x10) as *mut u32;
const I2C2_ISR: *const u32 = (I2C2 + 0x18) as *const u32;
const I2C2_ICR: *mut u32 = (I2C2 + 0x1C) as *mut u32;
const I2C2_RXDR: *const u32 = (I2C2 + 0x24) as *const u32;
const I2C2_TXDR: *mut u32 = (I2C2 + 0x28) as *mut u32;

// ISR bit masks
const ISR_TXIS: u32 = 1 << 1;
const ISR_RXNE: u32 = 1 << 2;
const ISR_NACKF: u32 = 1 << 4;
const ISR_STOPF: u32 = 1 << 5;
const ISR_TC: u32 = 1 << 6;
const ISR_BERR: u32 = 1 << 8;
const ISR_ARLO: u32 = 1 << 9;
const ISR_BUSY: u32 = 1 << 15;

// ICR bit masks
const ICR_NACKCF: u32 = 1 << 4;
const ICR_STOPCF: u32 = 1 << 5;
const ICR_BERRCF: u32 = 1 << 8;
const ICR_ARLOCF: u32 = 1 << 9;

// CR2 bits
const CR2_START: u32 = 1 << 13;
const CR2_STOP: u32 = 1 << 14;
const CR2_AUTOEND: u32 = 1 << 25;
const CR2_RD_WRN: u32 = 1 << 10;

const TIMEOUT: u32 = 500_000;

/// STSAFE-A110 default 7-bit I2C address.
const STSAFE_ADDR: u8 = 0x20;

/// Initialize I2C2 on PH4 (SCL) / PH5 (SDA) at ~100 kHz.
///
/// # Safety
/// Direct register access. Call after `rcc::init()`.
unsafe fn init_i2c2() {
    // ---- 1. Enable GPIOH clock (AHB2ENR1 bit 7) ----
    let ahb2 = read_volatile(RCC_AHB2ENR1);
    write_volatile(RCC_AHB2ENR1, ahb2 | (1 << 7));
    cortex_m::asm::dsb();

    // ---- 2. Enable I2C2 clock (APB1ENR1 bit 22) ----
    let apb1 = read_volatile(RCC_APB1ENR1);
    write_volatile(RCC_APB1ENR1, apb1 | (1 << 22));
    cortex_m::asm::dsb();

    // ---- 3. Reset I2C2 peripheral (APB1RSTR1 bit 22) ----
    let rstr = read_volatile(RCC_APB1RSTR1);
    write_volatile(RCC_APB1RSTR1, rstr | (1 << 22));
    cortex_m::asm::dsb();
    write_volatile(RCC_APB1RSTR1, rstr & !(1 << 22));
    cortex_m::asm::dsb();

    // ---- 4. Configure PH4 (SCL) and PH5 (SDA) as AF4, open-drain ----
    // MODER: bits [9:8] for PH4, [11:10] for PH5 → 10 (alternate function)
    let moder = read_volatile(GPIOH_MODER);
    let moder = (moder & !(0b11 << 8) & !(0b11 << 10)) | (0b10 << 8) | (0b10 << 10);
    write_volatile(GPIOH_MODER, moder);

    // OTYPER: bits 4,5 → 1 (open-drain, required for I2C)
    let otyper = read_volatile(GPIOH_OTYPER);
    write_volatile(GPIOH_OTYPER, otyper | (1 << 4) | (1 << 5));

    // OSPEEDR: bits [9:8],[11:10] → 11 (very high speed)
    let ospeedr = read_volatile(GPIOH_OSPEEDR);
    write_volatile(GPIOH_OSPEEDR, ospeedr | (0b11 << 8) | (0b11 << 10));

    // PUPDR: bits [9:8],[11:10] → 01 (pull-up)
    let pupdr = read_volatile(GPIOH_PUPDR);
    let pupdr = (pupdr & !(0b11 << 8) & !(0b11 << 10)) | (0b01 << 8) | (0b01 << 10);
    write_volatile(GPIOH_PUPDR, pupdr);

    // AFRL: PH4 = AF4 (bits [19:16]), PH5 = AF4 (bits [23:20])
    let afrl = read_volatile(GPIOH_AFRL);
    let afrl = (afrl & !(0xF << 16) & !(0xF << 20)) | (4 << 16) | (4 << 20);
    write_volatile(GPIOH_AFRL, afrl);

    // ---- 5. Configure I2C2 peripheral ----
    // Disable PE before writing TIMINGR
    write_volatile(I2C2_CR1, 0);
    cortex_m::asm::dsb();

    // Timing for ~100 kHz standard mode at 160 MHz PCLK:
    // PRESC=9 (÷10 → 16 MHz tick), SCLDEL=4, SDADEL=2, SCLH=63, SCLL=79
    write_volatile(I2C2_TIMINGR, 0x9042_3F4F);

    // Enable PE
    write_volatile(I2C2_CR1, 1);
    cortex_m::asm::dsb();
}

/// Probe a single 7-bit I2C address on I2C2.
/// Returns `true` if a device ACKs the address, `false` if NACK/timeout.
///
/// # Safety
/// Direct register access. I2C2 must be initialized.
unsafe fn probe_addr(addr: u8) -> bool {
    // Wait for bus idle
    let mut t = TIMEOUT;
    while read_volatile(I2C2_ISR) & ISR_BUSY != 0 {
        t -= 1;
        if t == 0 {
            return false;
        }
    }

    // Clear any stale flags
    write_volatile(I2C2_ICR, ICR_NACKCF | ICR_STOPCF | ICR_BERRCF | ICR_ARLOCF);

    // Send START + address (write mode), NBYTES=1, AUTOEND
    // We'll check if we get TXIS (ACK) or NACKF before the STOP.
    let cr2: u32 = ((addr as u32) << 1) // SADD[7:1]
        | (1 << 16)                      // NBYTES = 1
        | CR2_START
        | CR2_AUTOEND;
    write_volatile(I2C2_CR2, cr2);

    // Wait for either TXIS (device ACKed) or NACKF (no device)
    t = TIMEOUT;
    let found = loop {
        let isr = read_volatile(I2C2_ISR);
        if isr & ISR_NACKF != 0 {
            write_volatile(I2C2_ICR, ICR_NACKCF);
            break false;
        }
        if isr & ISR_TXIS != 0 {
            // Device ACKed. Write a dummy byte so AUTOEND can generate STOP.
            write_volatile(I2C2_TXDR, 0x00);
            break true;
        }
        if isr & (ISR_BERR | ISR_ARLO) != 0 {
            write_volatile(I2C2_ICR, ICR_BERRCF | ICR_ARLOCF);
            break false;
        }
        t -= 1;
        if t == 0 {
            break false;
        }
    };

    // Wait for STOP (AUTOEND generates it)
    t = TIMEOUT;
    while read_volatile(I2C2_ISR) & ISR_STOPF == 0 {
        t -= 1;
        if t == 0 {
            break;
        }
    }
    write_volatile(I2C2_ICR, ICR_STOPCF);

    // Small delay between probes
    for _ in 0..10_000 {
        cortex_m::asm::nop();
    }

    found
}

/// Try to read product data from the STSAFE-A110.
///
/// Sends a "get data" command (echo/product query) and reads back the response.
/// Returns the number of bytes read, or 0 on failure.
///
/// # Safety
/// Direct register access. I2C2 must be initialized.
unsafe fn try_read_stsafe_product(buf: &mut [u8; 64]) -> usize {
    // Wait for bus idle
    let mut t = TIMEOUT;
    while read_volatile(I2C2_ISR) & ISR_BUSY != 0 {
        t -= 1;
        if t == 0 {
            return 0;
        }
    }

    // STSAFE-A110 echo command: send 0x00 (data partition query)
    // The simplest command is just reading whatever the STSAFE sends
    // when addressed in read mode after a wakeup.
    write_volatile(I2C2_ICR, ICR_NACKCF | ICR_STOPCF | ICR_BERRCF | ICR_ARLOCF);

    // Try a read of a few bytes (STSAFE may send status/product info)
    let read_len: u8 = 4;
    let cr2: u32 = ((STSAFE_ADDR as u32) << 1)
        | CR2_RD_WRN
        | ((read_len as u32) << 16)
        | CR2_START
        | CR2_AUTOEND;
    write_volatile(I2C2_CR2, cr2);

    let mut count = 0usize;
    for _ in 0..read_len {
        t = TIMEOUT;
        loop {
            let isr = read_volatile(I2C2_ISR);
            if isr & ISR_NACKF != 0 {
                write_volatile(I2C2_ICR, ICR_NACKCF);
                // Wait for STOP
                let mut s = TIMEOUT;
                while read_volatile(I2C2_ISR) & ISR_STOPF == 0 {
                    s -= 1;
                    if s == 0 { break; }
                }
                write_volatile(I2C2_ICR, ICR_STOPCF);
                return count;
            }
            if isr & ISR_RXNE != 0 {
                buf[count] = read_volatile(I2C2_RXDR) as u8;
                count += 1;
                break;
            }
            if isr & (ISR_BERR | ISR_ARLO) != 0 {
                write_volatile(I2C2_ICR, ICR_BERRCF | ICR_ARLOCF);
                return count;
            }
            t -= 1;
            if t == 0 {
                return count;
            }
        }
    }

    // Wait for STOP
    t = TIMEOUT;
    while read_volatile(I2C2_ISR) & ISR_STOPF == 0 {
        t -= 1;
        if t == 0 { break; }
    }
    write_volatile(I2C2_ICR, ICR_STOPCF);

    count
}

/// Run the STSAFE-A110 / I2C2 bus probe.
///
/// Initializes I2C2 on PH4/PH5, scans addresses 0x08..0x77,
/// and reports findings via semihosting. Then halts.
///
/// # Safety
/// Direct register access. Must be called after `rcc::init()`.
pub unsafe fn run_probe() -> ! {
    cortex_m_semihosting::hprintln!("========================================");
    cortex_m_semihosting::hprintln!("[STSAFE PROBE] I2C2 bus scanner");
    cortex_m_semihosting::hprintln!("[STSAFE PROBE] PH4=SCL, PH5=SDA (AF4)");
    cortex_m_semihosting::hprintln!("========================================");

    init_i2c2();
    cortex_m_semihosting::hprintln!("[STSAFE PROBE] I2C2 initialized at ~100 kHz");

    // Scan the standard 7-bit address range
    cortex_m_semihosting::hprintln!("[STSAFE PROBE] Scanning addresses 0x08..0x77...");
    cortex_m_semihosting::hprintln!("");
    cortex_m_semihosting::hprintln!("     0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F");

    let mut found_count = 0u8;
    let mut found_addrs = [0u8; 16]; // Track up to 16 found devices

    for row in 0..8u8 {
        let base = row * 16;
        // Print row header
        let mut line = [b' '; 53];
        // Format: "0x_0: " then 16 entries of " XX" or " --" or "   "
        line[0] = b'0';
        line[1] = b'x';
        line[2] = hex_nibble(row);
        line[3] = b'0';
        line[4] = b':';

        for col in 0..16u8 {
            let addr = base + col;
            let pos = 5 + (col as usize) * 3;

            if addr < 0x08 || addr > 0x77 {
                // Reserved address
                line[pos] = b' ';
                line[pos + 1] = b' ';
                line[pos + 2] = b' ';
            } else if probe_addr(addr) {
                // Device found
                line[pos] = b' ';
                line[pos + 1] = hex_nibble(addr >> 4);
                line[pos + 2] = hex_nibble(addr & 0xF);
                if (found_count as usize) < found_addrs.len() {
                    found_addrs[found_count as usize] = addr;
                    found_count += 1;
                }
            } else {
                // No device
                line[pos] = b' ';
                line[pos + 1] = b'-';
                line[pos + 2] = b'-';
            }
        }

        cortex_m_semihosting::hprintln!("{}", crate::ui::ascii_str(&line));
    }

    cortex_m_semihosting::hprintln!("");
    cortex_m_semihosting::hprintln!("[STSAFE PROBE] Found {} device(s)", found_count);

    // Report known devices
    let mut stsafe_found = false;
    for i in 0..found_count as usize {
        let addr = found_addrs[i];
        let name = match addr {
            // STSAFE-A110 (U6 footprint — often unpopulated)
            0x20 => { stsafe_found = true; "STSAFE-A110 (secure element)" },
            // B-U585I-IOT02A on-board peripherals (I2C2, PH4/PH5)
            0x10 => "CS42L51 audio codec (U9)",
            0x1E => "IIS2MDC magnetometer (U15)",
            0x29 => "VL53L5CX ToF sensor (U14)",
            0x3C | 0x3D => "SSD1306/SH1106 OLED display",
            0x44 => "VEML6030 ambient light sensor (U16)",
            0x48 => "SE050 / STTS22H temp sensor",
            0x53 => "LPS22HH barometer",
            0x56 => "M24256-DF EEPROM (U4)",
            0x50..=0x57 => "EEPROM (24Cxx)",
            0x5D => "LPS22HH pressure sensor (U11)",
            0x5E => "HTS221 humidity+temp sensor (U12)",
            0x5F => "HTS221 / LPS22HH (alt addr)",
            0x6A | 0x6B => "ISM330DHCX 6-axis IMU (U10)",
            _ => "unknown",
        };
        cortex_m_semihosting::hprintln!(
            "  0x{}{} = {}",
            hex_char(addr >> 4), hex_char(addr & 0xF), name
        );
    }

    cortex_m_semihosting::hprintln!("");
    cortex_m_semihosting::hprintln!("========================================");
    if stsafe_found {
        cortex_m_semihosting::hprintln!("[STSAFE PROBE] STSAFE-A110 DETECTED at 0x20");

        // Try to read some data
        let mut buf = [0u8; 64];
        let n = try_read_stsafe_product(&mut buf);
        if n > 0 {
            cortex_m_semihosting::hprint!("[STSAFE PROBE] Read {} bytes:", n);
            for i in 0..n {
                cortex_m_semihosting::hprint!(" {:02X}", buf[i]);
            }
            cortex_m_semihosting::hprintln!("");
        }
    } else {
        cortex_m_semihosting::hprintln!("[STSAFE PROBE] STSAFE-A110 NOT FOUND at 0x20");
        cortex_m_semihosting::hprintln!("[STSAFE PROBE] Check: is the STSAFE soldered?");
        cortex_m_semihosting::hprintln!("[STSAFE PROBE] Note: some B-U585I-IOT02A revisions");
        cortex_m_semihosting::hprintln!("[STSAFE PROBE] may not populate the STSAFE-A110.");
    }
    cortex_m_semihosting::hprintln!("========================================");
    cortex_m_semihosting::hprintln!("[STSAFE PROBE] Done. Halting.");

    loop {
        cortex_m::asm::wfi();
    }
}

fn hex_nibble(n: u8) -> u8 {
    let n = n & 0xF;
    if n < 10 { b'0' + n } else { b'A' + n - 10 }
}

fn hex_char(n: u8) -> char {
    let n = n & 0xF;
    if n < 10 { (b'0' + n) as char } else { (b'A' + n - 10) as char }
}

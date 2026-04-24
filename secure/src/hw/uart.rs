//! Minimal USART1 driver routed to the B-U585I-IOT02A ST-LINK VCP (PA9 TX).
//!
//! Used by the RDP1 SAES self-test where semihosting is unavailable:
//! at `RDP=0xBB` the STM32U585 disables SWD debug access so `probe-rs
//! run` can no longer capture `hprintln!` output. The ST-LINK's USB
//! virtual-COM-port is a feature of the on-board debugger MCU (not the
//! target MCU) and forwards whatever bytes arrive on the target's PA9
//! UART TX pin over USB, regardless of the target's RDP level — giving
//! us a clean "debug channel that survives RDP ≥ 1".
//!
//! ## Register + pin map (cross-checked against `stm32u5-0.16.0` PAC +
//! STM32CubeU5 `stm32u585xx.h` + BSP `b_u585i_iot02a.h`)
//!
//! - USART1 base (secure alias): `0x5001_3800`
//! - CR1=+0x00, BRR=+0x0C, ISR=+0x1C, TDR=+0x28
//! - RCC_APB2ENR (NS alias): `0x4602_0C00 + 0xA4`, USART1EN = bit 14
//! - PA9 (TX) AF7, push-pull, high-speed — matches BSP macros
//!   `COM1_TX_PIN = GPIO_PIN_9 / COM1_TX_GPIO_PORT = GPIOA / COM1_TX_AF
//!   = GPIO_AF7_USART1`
//!
//! ## Clock / baud
//!
//! With `hw::rcc::init()` running at 160 MHz and default APB2 prescaler
//! = /1, PCLK2 = 160 MHz. Default USART1 clock source (CCIPR1 bits 1:0)
//! is PCLK2. 16× oversampling (OVER8=0): BRR = PCLK / baud = 160_000_000
//! / 115_200 = 1389 (0.064% error, inside the USART framing tolerance).
//!
//! ## Safety
//!
//! No interrupts, no critical-section, polling writes. Blocking.
//! Caller is responsible for calling `init()` before any `write_*`.

use core::ptr::{read_volatile, write_volatile};

// USART1 register map (secure alias).
const USART1: u32 = 0x5001_3800;
const USART1_CR1: *mut u32 = USART1 as *mut u32;
const USART1_BRR: *mut u32 = (USART1 + 0x0C) as *mut u32;
const USART1_ISR: *const u32 = (USART1 + 0x1C) as *const u32;
const USART1_TDR: *mut u32 = (USART1 + 0x28) as *mut u32;

const CR1_UE: u32 = 1 << 0;
const CR1_TE: u32 = 1 << 3;
const ISR_TXE_FNF: u32 = 1 << 7; // TX data register empty (legacy) / FIFO-not-full
const ISR_TC: u32 = 1 << 6;

// RCC APB2ENR (NS alias, matches `hw::rcc::init` convention).
const RCC_APB2ENR: *mut u32 = (0x4602_0C00 + 0xA4) as *mut u32;
const RCC_APB2ENR_USART1EN: u32 = 1 << 14;

// RCC AHB2ENR1 for GPIOA clock enable (bit 0 = GPIOAEN).
const RCC_AHB2ENR1: *mut u32 = (0x4602_0C00 + 0x8C) as *mut u32;
const RCC_AHB2ENR1_GPIOAEN: u32 = 1 << 0;

// GPIOA register map (secure alias). AHB2 at 0x5202_0000, GPIOA at +0.
const GPIOA: u32 = 0x5202_0000;
const GPIOA_MODER: *mut u32 = GPIOA as *mut u32;
const GPIOA_OTYPER: *mut u32 = (GPIOA + 0x04) as *mut u32;
const GPIOA_OSPEEDR: *mut u32 = (GPIOA + 0x08) as *mut u32;
const GPIOA_PUPDR: *mut u32 = (GPIOA + 0x0C) as *mut u32;
const GPIOA_AFRH: *mut u32 = (GPIOA + 0x24) as *mut u32;

/// Initialize USART1 for 115200 8N1 on PA9 TX. Safe to call multiple
/// times; every call re-programs the registers.
pub fn init() {
    // SAFETY: RCC / GPIOA / USART1 are memory-mapped; writes are bounded
    // bit-mask operations on well-defined register offsets taken from
    // the stm32u5 PAC + CMSIS header.
    unsafe {
        // --- 1. Enable GPIOA + USART1 clocks ---
        let ahb = read_volatile(RCC_AHB2ENR1);
        write_volatile(RCC_AHB2ENR1, ahb | RCC_AHB2ENR1_GPIOAEN);
        let apb = read_volatile(RCC_APB2ENR);
        write_volatile(RCC_APB2ENR, apb | RCC_APB2ENR_USART1EN);
        let _ = read_volatile(RCC_APB2ENR); // propagation barrier
        cortex_m::asm::dsb();

        // --- 2. Configure PA9 as AF7 (USART1_TX), push-pull, high speed ---
        // MODER[19:18] = 10 (AF mode)
        let moder = read_volatile(GPIOA_MODER);
        write_volatile(GPIOA_MODER, (moder & !(0b11 << 18)) | (0b10 << 18));
        // OTYPER bit 9 = 0 (push-pull)
        let otyper = read_volatile(GPIOA_OTYPER);
        write_volatile(GPIOA_OTYPER, otyper & !(1 << 9));
        // OSPEEDR[19:18] = 11 (very-high speed)
        let ospeedr = read_volatile(GPIOA_OSPEEDR);
        write_volatile(GPIOA_OSPEEDR, (ospeedr & !(0b11 << 18)) | (0b11 << 18));
        // PUPDR[19:18] = 00 (no pull)
        let pupdr = read_volatile(GPIOA_PUPDR);
        write_volatile(GPIOA_PUPDR, pupdr & !(0b11 << 18));
        // AFRH for pin 9 lives in AFRH[7:4] = AF7 (0b0111)
        let afrh = read_volatile(GPIOA_AFRH);
        write_volatile(GPIOA_AFRH, (afrh & !(0xF << 4)) | (0x7 << 4));

        // --- 3. Program USART1: disable → BRR → re-enable ---
        write_volatile(USART1_CR1, 0);
        // PCLK2 = 160 MHz, OVER8 = 0, BRR = 160_000_000 / 115_200 ≈ 1389 (0x56D).
        write_volatile(USART1_BRR, 1389);
        write_volatile(USART1_CR1, CR1_UE | CR1_TE);
    }
}

/// Blocking write of a single byte. Spin-waits until the peripheral
/// accepts it (TXE / TXFNF) — the PC side of the ST-LINK VCP pulls
/// bytes fast enough that this typically returns in one loop iteration.
pub fn write_byte(b: u8) {
    unsafe {
        while read_volatile(USART1_ISR) & ISR_TXE_FNF == 0 {}
        write_volatile(USART1_TDR, u32::from(b));
    }
}

/// Blocking write of an arbitrary byte slice.
pub fn write_bytes(bytes: &[u8]) {
    for &b in bytes {
        write_byte(b);
    }
}

/// Blocking write of a `&str`. CR+LF is NOT appended — caller supplies.
pub fn write_str(s: &str) {
    write_bytes(s.as_bytes());
}

/// Blocking write of an 8-byte array as lowercase hex (16 chars, no
/// separators, no newline). Used for the SAES DHUK fingerprint line.
pub fn write_hex_8(bytes: &[u8; 8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 16];
    for (i, &b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0xF) as usize];
    }
    write_bytes(&out);
}

/// Drain the transmit FIFO so pending bytes hit the wire before the
/// caller halts / resets. Spin-waits for `ISR.TC`.
pub fn flush() {
    unsafe {
        while read_volatile(USART1_ISR) & ISR_TC == 0 {}
    }
}

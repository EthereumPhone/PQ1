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

use crate::hw::mmio::{Reg32, RoReg32};

// USART1 register map — SECURE alias.
//
// Even though `sau::init` sets `GTZC1_TZSC_SECCFGR2=0` (making APB2
// peripherals NS), the Secure alias still works from Secure CPU state
// for USART1 on this silicon — the NS-alias theory was wrong, the
// actual silent-drop was GPIOA not being clocked. Keeping secure
// alias for consistency with `hw/i2c_hw.rs` which also uses S aliases
// (RCC 0x5602_0C00, GPIOB 0x5202_0400, I2C1 0x5000_5400).
const USART1: u32 = 0x5001_3800;

// RCC registers — SECURE alias.
//
// With TZEN=1 the Secure RCC alias (0x5602_0C00) is the only one that
// can clock-gate peripherals classified Secure-by-default. `pin_diag.rs`
// uses the same pattern and empirically works; `hw::rcc::init()` uses
// the NS alias but only touches PLL / SYSCLK / RNG, which happen to be
// tolerant of NS-alias writes on this silicon. Diagnostic runs showed
// that writing GPIOAEN via NS-alias AHB2ENR1 leaves the bit clear →
// GPIOA stays unclocked → all GPIOA reads return 0xABFFFFFF (bus junk)
// and all writes silently drop. Secure-alias writes land correctly.
const RCC_S: u32 = 0x5602_0C00;

// GPIOA register map — Secure alias (0x5202_0000).
// Matches `pin_diag.rs` and `i2c_hw.rs` which both use S-alias GPIO.
const GPIOA: u32 = 0x5202_0000;

struct UartRegs {
    cr1: Reg32,
    brr: Reg32,
    isr: RoReg32,
    tdr: Reg32,
    rcc_apb2enr: Reg32,
    rcc_ahb2enr1: Reg32,
    gpioa_moder: Reg32,
    gpioa_otyper: Reg32,
    gpioa_ospeedr: Reg32,
    gpioa_pupdr: Reg32,
    gpioa_afrh: Reg32,
}

// SAFETY: each address is a real, 4-byte-aligned MMIO register owned by
// this UART driver in the single-threaded secure world. RCC + GPIOA bits
// modified here are coordinated with `hw::rcc` and `hw::i2c_hw` via
// read-modify-write so the shared registers are safe to share.
const REG: UartRegs = unsafe {
    UartRegs {
        cr1: Reg32::new(USART1),
        brr: Reg32::new(USART1 + 0x0C),
        isr: RoReg32::new(USART1 + 0x1C),
        tdr: Reg32::new(USART1 + 0x28),
        rcc_apb2enr: Reg32::new(RCC_S + 0xA4),
        rcc_ahb2enr1: Reg32::new(RCC_S + 0x8C),
        gpioa_moder: Reg32::new(GPIOA),
        gpioa_otyper: Reg32::new(GPIOA + 0x04),
        gpioa_ospeedr: Reg32::new(GPIOA + 0x08),
        gpioa_pupdr: Reg32::new(GPIOA + 0x0C),
        gpioa_afrh: Reg32::new(GPIOA + 0x24),
    }
};

const RCC_APB2ENR_USART1EN: u32 = 1 << 14;
const RCC_AHB2ENR1_GPIOAEN: u32 = 1 << 0;

const CR1_UE: u32 = 1 << 0;
const CR1_TE: u32 = 1 << 3;
const ISR_TXE_FNF: u32 = 1 << 7; // TX data register empty (legacy) / FIFO-not-full
const ISR_TC: u32 = 1 << 6;
const ISR_TEACK: u32 = 1 << 21; // Transmit enable acknowledge

/// Initialize USART1 for 115200 8N1 on PA9 TX. Safe to call multiple
/// times; every call re-programs the registers.
pub fn init() {
    // --- 1. Enable GPIOA + USART1 clocks ---
    REG.rcc_ahb2enr1.set_bits(RCC_AHB2ENR1_GPIOAEN);
    REG.rcc_apb2enr.set_bits(RCC_APB2ENR_USART1EN);
    let _ = REG.rcc_apb2enr.read(); // propagation barrier
    cortex_m::asm::dsb();

    // --- 2. Configure PA9 as AF7 (USART1_TX), push-pull, high speed ---
    // MODER[19:18] = 10 (AF mode)
    REG.gpioa_moder.modify(|v| (v & !(0b11 << 18)) | (0b10 << 18));
    // OTYPER bit 9 = 0 (push-pull)
    REG.gpioa_otyper.clear_bits(1 << 9);
    // OSPEEDR[19:18] = 11 (very-high speed)
    REG.gpioa_ospeedr.modify(|v| (v & !(0b11 << 18)) | (0b11 << 18));
    // PUPDR[19:18] = 00 (no pull)
    REG.gpioa_pupdr.clear_bits(0b11 << 18);
    // AFRH for pin 9 lives in AFRH[7:4] = AF7 (0b0111)
    REG.gpioa_afrh.modify(|v| (v & !(0xF << 4)) | (0x7 << 4));

    // --- 3. Program USART1 ---
    // RM0456 init sequence: configure CR1 word length / parity while
    // UE=0, program BRR, set UE=1, THEN toggle TE 0→1 (the TE
    // enable edge must happen AFTER UE is high — setting both in a
    // single atomic write is ambiguous hardware behaviour).
    // Defaults after reset: M=00 (8-bit), OVER8=0 (16× oversampling),
    // STOP=00 (1 stop bit), parity off. We don't touch CR2/CR3.
    REG.cr1.write(0);
    // PCLK2 = 160 MHz, OVER8 = 0, BRR = 160_000_000 / 115_200 ≈ 1389 (0x56D).
    REG.brr.write(1389);
    REG.cr1.write(CR1_UE);
    REG.cr1.write(CR1_UE | CR1_TE);
    // Wait for the transmitter to acknowledge — empirically the
    // first byte is silently dropped on STM32U5 if we write TDR
    // before TEACK asserts. Bounded so we don't hang if the
    // peripheral is in a wedged state.
    let mut t: u32 = 10_000_000;
    while REG.isr.read() & ISR_TEACK == 0 {
        t -= 1;
        if t == 0 {
            return;
        }
    }
}

/// Blocking write of a single byte. Spin-waits until the peripheral
/// accepts it (TXE / TXFNF) — the PC side of the ST-LINK VCP pulls
/// bytes fast enough that this typically returns in one loop iteration.
pub fn write_byte(b: u8) {
    while REG.isr.read() & ISR_TXE_FNF == 0 {}
    REG.tdr.write(u32::from(b));
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
    while REG.isr.read() & ISR_TC == 0 {}
}

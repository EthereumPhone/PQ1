//! Minimal blocking UART TX driver for the board's debug console.
//!
//! Which USART, which pin and which alternate function all come from
//! `crate::board`, so this file has no board knowledge of its own:
//!
//! | | `iota2` | `pq1` |
//! |---|---|---|
//! | Peripheral | USART1 `0x5001_3800` | USART2 `0x5000_4400` |
//! | Clock enable | `RCC_APB2ENR` bit 14 | `RCC_APB1ENR1` bit 17 |
//! | TX pin | PA9, AF7 | PA2, AF7 |
//! | Reaches | ST-LINK VCP | header `J211` pin 1 |
//!
//! Used under `uart-console` for diagnostic output from builds that
//! cannot rely on semihosting — specifically the RDP1 SAES self-test.
//! At `RDP = 0xBB` the STM32U585 disables SWD debug access, so `probe-rs
//! run` can no longer capture `hprintln!` output; a UART channel that
//! survives RDP ≥ 1 is the only way to get a result out.
//!
//! On `iota2` that channel is the ST-LINK's USB virtual COM port, which
//! is a feature of the *debugger* MCU rather than the target and so keeps
//! forwarding whatever arrives on the target's TX pin regardless of the
//! target's RDP level. `pq1` has no on-board debugger at all: its TX pad
//! (`J211` pin 1) goes to whatever the operator has clipped to it, which
//! is likewise unaffected by RDP.
//!
//! Both boards land on the same `BRR`. `iota2`'s USART1 defaults to PCLK2
//! and `pq1`'s USART2 to PCLK1, but `hw::rcc::init` leaves both APB
//! prescalers at /1, so each sees SYSCLK = 160 MHz and 115200 8N1 needs
//! `BRR = 160_000_000 / 115_200 = 1389` (0.064 % error). See
//! `board::CONSOLE_BRR`.
//!
//! ## Safety
//!
//! No interrupts, no critical-section, polling writes. Blocking.
//! Caller is responsible for calling `init()` before any `write_*`.

use crate::board;
use crate::hw::mmio::{Reg32, RoReg32};

/// Register offsets within a USART block (identical for USART1/USART2).
const CR1_OFF: u32 = 0x00;
const BRR_OFF: u32 = 0x0C;
const ISR_OFF: u32 = 0x1C;
const TDR_OFF: u32 = 0x28;

/// The half of `GPIOx_AFR[]` that owns `CONSOLE_TX_PIN`, as a register
/// offset: pins 0-7 live in `AFRL` (+0x20), pins 8-15 in `AFRH` (+0x24).
/// `iota2` uses PA9 (high half) and `pq1` PA2 (low half), so this cannot
/// be a fixed offset the way it was before the board split.
const CONSOLE_TX_AFR_OFF: u32 = if board::CONSOLE_TX_PIN < 8 { 0x20 } else { 0x24 };
/// Bit position of this pin's 4-bit alternate-function field within that
/// half-register.
const CONSOLE_TX_AFR_SHIFT: u32 = (board::CONSOLE_TX_PIN % 8) * 4;
/// Bit position of this pin's 2-bit field in `MODER` / `OSPEEDR` / `PUPDR`.
const CONSOLE_TX_PIN2: u32 = board::CONSOLE_TX_PIN * 2;

struct UartRegs {
    cr1: Reg32,
    brr: Reg32,
    isr: RoReg32,
    tdr: Reg32,
    /// Whichever of `APB1ENR1` / `APB2ENR` holds this USART's enable bit.
    rcc_uart_enr: Reg32,
    rcc_ahb2enr1: Reg32,
    gpio_moder: Reg32,
    gpio_otyper: Reg32,
    gpio_ospeedr: Reg32,
    gpio_pupdr: Reg32,
    gpio_afr: Reg32,
}

// SAFETY: each address is a real, 4-byte-aligned MMIO register owned by
// this UART driver in the single-threaded secure world. RCC + GPIO bits
// modified here are coordinated with `hw::rcc` and `hw::i2c_hw` via
// read-modify-write so the shared registers are safe to share.
//
// All bases are SECURE aliases. With TZEN=1 the secure RCC alias is the
// only one that can clock-gate peripherals classified secure-by-default:
// writing GPIOAEN through the NS alias leaves the bit clear, GPIOA stays
// unclocked, reads return 0xABFFFFFF bus junk and writes silently drop.
// That was the actual cause of a long-standing "USART needs the NS alias"
// theory, which was wrong.
const REG: UartRegs = unsafe {
    UartRegs {
        cr1: Reg32::new(board::CONSOLE_UART_BASE + CR1_OFF),
        brr: Reg32::new(board::CONSOLE_UART_BASE + BRR_OFF),
        isr: RoReg32::new(board::CONSOLE_UART_BASE + ISR_OFF),
        tdr: Reg32::new(board::CONSOLE_UART_BASE + TDR_OFF),
        rcc_uart_enr: Reg32::new(board::RCC_S + board::CONSOLE_UART_RCC_ENR_OFF),
        rcc_ahb2enr1: Reg32::new(board::RCC_S + board::RCC_AHB2ENR1_OFF),
        gpio_moder: Reg32::new(board::CONSOLE_TX_PORT),
        gpio_otyper: Reg32::new(board::CONSOLE_TX_PORT + 0x04),
        gpio_ospeedr: Reg32::new(board::CONSOLE_TX_PORT + 0x08),
        gpio_pupdr: Reg32::new(board::CONSOLE_TX_PORT + 0x0C),
        gpio_afr: Reg32::new(board::CONSOLE_TX_PORT + CONSOLE_TX_AFR_OFF),
    }
};

const RCC_CONSOLE_UART_EN: u32 = board::CONSOLE_UART_RCC_EN_BIT;
const RCC_CONSOLE_GPIO_EN: u32 = board::gpio_rcc_bit(board::CONSOLE_TX_PORT);

const CR1_UE: u32 = 1 << 0;
const CR1_TE: u32 = 1 << 3;
const ISR_TXE_FNF: u32 = 1 << 7; // TX data register empty (legacy) / FIFO-not-full
const ISR_TC: u32 = 1 << 6;
const ISR_TEACK: u32 = 1 << 21; // Transmit enable acknowledge

/// Initialize the console USART for 115200 8N1 on the board's TX pin.
/// Safe to call multiple times; every call re-programs the registers.
pub fn init() {
    // --- 1. Enable the TX port's GPIO clock + the USART clock ---
    REG.rcc_ahb2enr1.set_bits(RCC_CONSOLE_GPIO_EN);
    REG.rcc_uart_enr.set_bits(RCC_CONSOLE_UART_EN);
    let _ = REG.rcc_uart_enr.read(); // propagation barrier
    cortex_m::asm::dsb();

    // --- 2. Configure the TX pin as its USART alternate function,
    //        push-pull, very-high speed, no pull ---
    REG.gpio_moder
        .modify(|v| (v & !(0b11 << CONSOLE_TX_PIN2)) | (0b10 << CONSOLE_TX_PIN2));
    REG.gpio_otyper.clear_bits(1 << board::CONSOLE_TX_PIN);
    REG.gpio_ospeedr
        .modify(|v| (v & !(0b11 << CONSOLE_TX_PIN2)) | (0b11 << CONSOLE_TX_PIN2));
    REG.gpio_pupdr.clear_bits(0b11 << CONSOLE_TX_PIN2);
    REG.gpio_afr.modify(|v| {
        (v & !(0xF << CONSOLE_TX_AFR_SHIFT)) | (board::CONSOLE_TX_AF << CONSOLE_TX_AFR_SHIFT)
    });

    // --- 3. Program the USART ---
    // RM0456 init sequence: configure CR1 word length / parity while
    // UE=0, program BRR, set UE=1, THEN toggle TE 0→1 (the TE
    // enable edge must happen AFTER UE is high — setting both in a
    // single atomic write is ambiguous hardware behaviour).
    // Defaults after reset: M=00 (8-bit), OVER8=0 (16× oversampling),
    // STOP=00 (1 stop bit), parity off. We don't touch CR2/CR3.
    REG.cr1.write(0);
    // 160 MHz PCLK, OVER8 = 0 — see the module header for why both boards
    // land on the same divisor.
    REG.brr.write(board::CONSOLE_BRR);
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
/// accepts it (TXE / TXFNF). With a reader attached this typically
/// returns in one loop iteration; with nothing attached the line is
/// still driven, so it does not stall.
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

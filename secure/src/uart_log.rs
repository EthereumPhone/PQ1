//! `core::fmt` sink over the board's debug USART (`uart-console`, bench only).
//!
//! **Why this exists.** `secure_log!` had exactly two backends: semihosting
//! (`debug-log`, gated at run time on `DHCSR.C_DEBUGEN` so it no-ops without a
//! debugger) and nothing. That makes the secure world **silent** on any build
//! without a probe attached — and on `pq1` there is no panel either, so a
//! secure world that halts before booting NS gives no signal at all. That is
//! the state the v1 image is in: the FSBL branches into it correctly (proved by
//! the `stage-marker` page) and then nothing observable happens.
//!
//! The UART is the one channel that works without a debugger and independently
//! of RDP level — `saes-self-test-hw-rdp1` already relies on exactly that,
//! routing its PASS line out the USART because SWD is dead at RDP-1. But the
//! only writers were ~10 hand-placed `hw::uart::write_str` calls inside the
//! self-test-and-halt paths. This module makes the *existing* `secure_log!`
//! call sites — hundreds of them, already threaded through the whole boot —
//! come out of that wire instead of requiring a new marker per question.
//!
//! **Structure mirrors [`crate::shio`]** deliberately: a `Sink` implementing
//! `fmt::Write` so `format_args!` renders straight into the peripheral with no
//! heap and no intermediate buffer. The difference is that a UART cannot wedge
//! the way QEMU's chardev can — `hw::uart::write_byte` spin-waits on
//! `TXE/TXFNF`, and with nothing attached the line is still driven, so it
//! drains regardless of whether anyone is listening. No retry/drop logic is
//! needed here.
//!
//! **Baud depends on the clock.** `hw::uart::init` programs
//! `board::CONSOLE_BRR`, which assumes `PCLK = 160 MHz` — i.e. after
//! `hw::rcc::init()`. Anything logged before that point would go out at the
//! wrong rate and read as line noise, which is why `main` initialises the
//! console immediately after the clock tree and not earlier.
//!
//! **Never ships.** `uart-console` is already in the `PROD_FORBIDDEN` denylist
//! (`Makefile`) and in the hardware-release `compile_error!` fence
//! (`nsc/mod.rs`), so nothing new is added to either list by using it. On
//! `pq1` the line is USART2/PA2 AF7 on the `J211` pad; on `iota2` USART1/PA9.

#![allow(dead_code)] // unused when `debug-log` is off but `uart-console` is on

use core::fmt;
use cortex_m::interrupt;

use crate::hw::uart;

/// Sink adapter so `core::fmt` can format directly into the USART without an
/// intermediate heap/stack buffer.
struct Sink;

impl fmt::Write for Sink {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        uart::write_str(s);
        Ok(())
    }
}

/// Bring the console USART up. Idempotent (`hw::uart::init` re-programs every
/// register on each call) and bounded (its `TEACK` wait returns on timeout
/// rather than spinning), so calling it early in boot cannot hang.
///
/// Must run **after** `hw::rcc::init()` — see the module header on baud.
pub fn init() {
    uart::init();
}

/// `hprintln!`-equivalent over the USART: formatted arguments followed by
/// CRLF. Wrapped in `interrupt::free` to keep a log line from being
/// interleaved by an interrupt handler's own logging, matching `shio`.
pub fn println(args: fmt::Arguments) {
    interrupt::free(|_| {
        let mut sink = Sink;
        let _ = fmt::Write::write_fmt(&mut sink, args);
        uart::write_str("\r\n");
        uart::flush();
    });
}

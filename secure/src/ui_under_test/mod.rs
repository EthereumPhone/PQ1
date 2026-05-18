//! Test-only scaffold for the `secure-ui` slice.
//!
//! The production `ui` module is `#[cfg(not(test))]` because every
//! file in it pulls in hardware-only crates: `cortex_m_semihosting`,
//! `embedded_graphics`, `ssd1306`, `rtt-target`, the GPIO button
//! driver, the `crate::timeout` / `crate::rng_strong` peers, and a
//! `static mut DISPLAY` / `static mut INPUT` singleton-pair that only
//! makes sense in a single-core M33 boot path. Re-mounting those files
//! under host test builds is therefore impractical.
//!
//! This scaffold hosts the host-runnable invariant suite for the
//! slice. The body is split into two test mechanisms:
//!
//!   1. **`include_str!` source-text pins.** Layout constants, ASCII
//!      filter ranges, F-20 RNG-scrambled PIN seeds, HIGH-13's "no
//!      reset_activity on confirm entry" rule, the "constant-time-ish"
//!      OR-folded PIN compare, BIP-39 page math, the `[UI-FP]` capture
//!      stream format, the SSD1306 0x40 data-control byte, the
//!      `0xFB 0x32` mirror frame magic, and the `noop` backend's
//!      auto-confirm semantics are all pinned against verbatim
//!      substrings in the file text. A silent rename / removal /
//!      flip fails the test before it ships.
//!
//!   2. **Reference-algorithm checks.** The progress-bar math,
//!      mnemonic page indexing, BIP-39 wrap-in-range cursor, ASCII
//!      filter mapping, and the `(target − start) mod 10` PIN-press
//!      relationship are re-implemented here and validated against
//!      the values the in-file formulas commit to. A future refactor
//!      that drifts the math fires a clear assertion citing the
//!      attacked invariant.
//!
//! Negative tests are framed by the assumption they attack: each
//! `negative_*` test names what an attacker would gain if the
//! assumption held, and asserts the precise outcome that proves the
//! slice enforces it. Per the test-writing brief, the negative suite
//! is the most important deliverable here.
//!
//! On-target coverage (real OLED I²C round-trip, the semihosting
//! READC blocking loop, the GPIO button event pump, the RTT mirror
//! channel, the splash animation timing, and the actual rendering of
//! pixels into `Framebuf`) lives behind QEMU + `make play` /
//! `make play-hw-display` and is documented in
//! `reports/tests/secure-ui.md` under "Coverage gaps".

#[cfg(test)]
mod pure_tests;

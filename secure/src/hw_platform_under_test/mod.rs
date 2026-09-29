//! Test-only scaffold for the `secure-hw-platform` slice.
//!
//! The production `hw` module is `#[cfg(not(test))]` because most of
//! its files depend on `cortex_m` / MMIO at STM32U585 hardware
//! addresses and cannot link on host. This scaffold hosts the
//! cross-file pure-logic + source-text invariant suite that pins the
//! platform peripheral layer:
//!
//!   * Flash page geometry + per-page sentinels (PIN counter, off-chain
//!     journal, boot-state, key page, admin page) — silent drift would
//!     either overlap a peripheral page or stop FSBL from finding the
//!     active slot.
//!   * Wire-format reference tests for the boot-state and off-chain
//!     journal entry encodings — bytes baked into flash for the device
//!     lifetime; a refactor that reshapes them is an on-chain breaking
//!     change.
//!   * Register addresses + bit positions for FLASH / RCC / RNG / PKA
//!     / TAMP / TIM2 / GPIO — wrong alias (NS vs S) or wrong offset
//!     would silently corrupt every read/write.
//!   * Production fences: `boot-pulse`, `sca-trigger`, `consumption-
//!     mask` are dev-only — their feature gates + module docstring
//!     warnings stay locked.
//!   * FI hardening / verify-before-release / monotonicity gates on
//!     the off-chain journal and PIN attempt counter.
//!
//! On-target tests (real flash erase/program round-trip, real RCC PLL
//! lock, TRNG entropy quality, PKA Montgomery KAT) live under the
//! corresponding `make`-targets (`make e2e-hw`, `make
//! optiga-hw-counter-e2e`, etc.) — they are not exercised by this
//! host-side cargo-test pass and are documented in
//! Hardware-only coverage gaps remain tracked in `docs/archive/work-todo-retired-2026-07-19.md`.

// #723: `hw/tamp_reason.rs` is the pure half of the TAMP driver, mounted here
// so its decode is exercised against the REAL function. `mod hw;` is
// `#[cfg(not(test))]` in main.rs, so this `#[path]` mount is the only route.
#[cfg(test)]
#[path = "../hw/tamp_reason.rs"]
mod tamp_reason;

#[cfg(test)]
mod pure_tests;

//! Test-only scaffold for the `secure-hw-crypto` slice.
//!
//! The production `hw` module is `#[cfg(not(test))]` because most of its
//! files depend on `cortex_m` / MMIO at STM32U585 hardware addresses and
//! cannot link on host. This scaffold hosts the cross-file pure-logic +
//! source-text invariant suite that pins:
//!
//!   * KDF / domain-tag stability (CLAUDE.md "no casual KDF tag changes")
//!   * Register address + bit-position constants (silent address drift
//!     would corrupt every signature)
//!   * Per-die / per-device key derivation algorithmic shape
//!   * FI-hardening, key-zeroization, and verify-before-release gates
//!     that exist as the whole point of the slice
//!
//! On-target tests (real HASH peripheral self-test, SAES round-trip,
//! BHK provisioning) live under the `saes-self-test` / `make
//! saes-self-test-hw` Makefile targets — they are not exercised by
//! this host-side cargo-test pass and are documented in
//! `reports/tests/secure-hw-crypto.md` under "Coverage gaps".

#[cfg(test)]
mod pure_tests;

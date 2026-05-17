//! Test-only scaffold for the `secure-optiga` slice.
//!
//! The production `optiga` module is `#[cfg(not(test))]` because most of
//! its files import `cortex_m` directly (`ifx_i2c::delay_1ms` and the
//! retry loops in `write_register` / `read_register`), or pull in
//! `crate::hw::i2c_hw` MMIO addresses (`i2c.rs`, `mod.rs`), or rely on
//! the OPTIGA Trust M secure-element being physically present on I²C1
//! (`mod.rs::OptigaTrustM`). None of that links on host.
//!
//! This scaffold provides the smallest set of stubs that lets the
//! pure-crypto and pure-logic files of the slice compile under
//! `cargo test`:
//!
//! * `ifx_i2c` — only the *types* (`IfxState`, `IfxError`) referenced by
//!   `apdu.rs`'s `From<IfxError> for OptigaError` and by `shield.rs`'s
//!   `establish()` signature. The transceive functions are stubbed; tests
//!   that exercise the *behaviour* of `establish` would need a real chip.
//! * `apdu.rs` and `shield.rs` are path-included verbatim from the
//!   production tree so the byte-exact algorithms (TLS-PRF, AES-128-CCM-8,
//!   metadata builders, APDU framing, response parser) run on host
//!   against reference vectors.
//!
//! Files that cannot be path-included (every cortex_m / MMIO-bound file)
//! are pinned via `include_str!` source-text assertions in
//! `pure_tests.rs`. A future refactor that silently shifts an I²C
//! address, drops a `CLEAR_LAST_ERROR` flag, or rewrites the IFX CRC-16
//! nibble algorithm will fail the source-text suite before it can reach
//! silicon.
//!
//! Per the test-writing brief, the negative tests in `pure_tests.rs` are
//! the primary deliverable: each one names the assumption being attacked
//! (replay window, nonce reuse, AAD coverage, OID range, CMD high-bit,
//! KDF tag stability, …) and asserts the precise outcome that proves
//! the guard fires.

#![allow(dead_code)]
#![allow(clippy::all)]

/// Minimal stub for the IFX I2C transport layer.
///
/// `apdu.rs` references `IfxState` as a type and `IfxError::Crc` as a
/// variant; `shield.rs` references `IfxState::transceive_prl` from
/// `establish()` (which we do not exercise under host tests because it
/// requires a real chip). The stub satisfies the types but every method
/// is intentionally a no-op or an immediate error — calling them from a
/// test is a logic bug in the test, not a path we want to make
/// convenient.
pub mod ifx_i2c {
    /// Mirrors the variants in `secure/src/optiga/ifx_i2c.rs`.
    /// `Crc` is the only variant the production `From<IfxError>` impl
    /// reads explicitly; the others exist so a future refactor that adds
    /// a new wire-error class doesn't silently get mapped to
    /// `Transport`.
    #[derive(Debug)]
    pub enum IfxError {
        I2c,
        Crc,
        Nack,
        Timeout,
        FrameTooLarge,
        BadResponse,
        ReSynch,
    }

    pub struct IfxState;

    impl IfxState {
        pub const fn new() -> Self {
            Self
        }

        /// # Safety
        /// Stub. The real implementation drives I²C MMIO; on host this is
        /// a never-call no-op.
        pub unsafe fn transceive(
            &mut self,
            _apdu: &[u8],
            _resp: &mut [u8],
        ) -> Result<usize, IfxError> {
            Err(IfxError::Timeout)
        }

        /// # Safety
        /// Stub. See `transceive` above.
        pub unsafe fn transceive_prl(
            &mut self,
            _msg: &[u8],
            _resp: &mut [u8],
        ) -> Result<usize, IfxError> {
            Err(IfxError::Timeout)
        }
    }
}

/// `apdu.rs` references `crate::iso7816::parse_pin_ctr` under the
/// `optiga-hw-counter` feature. The host test build keeps the feature
/// off, so this reference is never instantiated, but the path-included
/// file still has to *parse* successfully — and `crate::iso7816` is
/// always-compiled, so the path resolves regardless.
#[path = "../optiga/shield.rs"]
pub mod shield;

#[path = "../optiga/apdu.rs"]
pub mod apdu;

#[cfg(test)]
mod pure_tests;

//! CMAC-AES-256 with the STM32U585 SAES peripheral as the AES backend.
//!
//! Used by `hw::secret_keys` to derive per-purpose subkeys from the
//! hardware-bound DHUK (Device Hardware Unique Key) without ever loading
//! key bytes into CPU-visible registers.
//!
//! ## Why software CMAC on top of SAES-ECB?
//!
//! SAES on STM32U5 has a CMAC chaining mode in the silicon, but exposing
//! it would widen the register surface we have to verify (CHMOD[2:0]
//! including bit 16, NPBLB for partial blocks, suspend registers). We
//! already verified the ECB path thoroughly during Tier-1 bring-up;
//! implementing RFC 4493 CMAC on top of that block primitive is ~60
//! lines of straight-line code, no register trust required.
//!
//! ## Algorithm
//!
//! Delegated to `crate::cmac::cmac_generic` (RFC 4493 / NIST SP 800-38B),
//! which is host-testable against the NIST AES-256-CMAC KATs. This file
//! only supplies the SAES-DHUK closure.
//!
//! ## Key selector
//!
//! Drives `KeySel::Dhuk` via `cmac_dhuk` — the Tier 1 derivation
//! primitive. Shares the `cmac_generic` core in `crate::cmac` so the
//! NIST SP 800-38B KATs validate this path.

#![cfg(feature = "saes-dhuk")]

use crate::cmac::cmac_generic;
use crate::hw::saes::{self, KeySel, SaesError};

/// CMAC-AES-256 with the DHUK as the key. Writes the 16-byte MAC tag
/// into `tag`. `msg` can be any length including zero.
///
/// # Errors
///
/// Propagates `SaesError` from the underlying ECB block primitive —
/// usually a `CcfTimeout` (peripheral wedged) or `BusError` (access
/// denied via GTZC, indicating a config regression). `saes::init()`
/// must have been called before; lazy-initing here is possible but
/// callers typically want a single init at boot so failures surface
/// early.
pub fn cmac_dhuk(msg: &[u8], tag: &mut [u8; 16]) -> Result<(), SaesError> {
    cmac_generic(msg, |block| saes::encrypt_ecb_block(KeySel::Dhuk, None, block), tag)
}

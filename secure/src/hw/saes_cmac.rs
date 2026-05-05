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
//! ## Key selectors
//!
//! Two functions, two SAES KEYSEL values:
//! - `cmac_dhuk` — Tier 1 derivation primitive, drives `KeySel::Dhuk`.
//! - `cmac_bhk`  — Tier 2 derivation primitive, drives `KeySel::Bhk`.
//!
//! Both share the exact `cmac_generic` core in `crate::cmac` so the
//! NIST SP 800-38B KATs validate both paths. The two selectors are
//! independent SAES key sources — a hypothetical compromise of one
//! does not leak the other (defense-in-depth across two key axes).

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

/// CMAC-AES-256 with the BHK as the key. Drives `KeySel::Bhk` instead
/// of DHUK. Same shape as `cmac_dhuk`; the difference is the silicon
/// key source.
///
/// **Tier 2 phase 2B prerequisite.** The Tier-2 first-boot provisioning
/// step (work-todo #7 §"Tier 2 — BHK", phase 2B) must have run for the
/// BHK selector to produce stable output: TRNG fill → DHUK-ECB wrap →
/// flash write → on every subsequent boot, unwrap into TAMP backup
/// registers + lock `TAMP_S->SECCFGR` so SAES is the only consumer.
/// Without that boot-time setup, `KeySel::Bhk` reads back as zero on
/// some silicon revisions — output is well-defined but device-
/// independent (defeats the security claim).
///
/// # Errors
///
/// Same propagation as `cmac_dhuk` (`SaesError` from the ECB primitive).
pub fn cmac_bhk(msg: &[u8], tag: &mut [u8; 16]) -> Result<(), SaesError> {
    cmac_generic(msg, |block| saes::encrypt_ecb_block(KeySel::Bhk, None, block), tag)
}

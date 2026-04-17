//! One-shot OID recovery via SetObjectProtected (CMD 0x83).
//!
//! Gated behind the `optiga-reset-oids` feature. During the bring-up pass
//! that has left the `0xF1D0..0xF1DF` AUTHREF OID range locked (the chip
//! rejects SetDataObject after two successful writes per session, across
//! power cycles, for reasons outside this driver's control), we recover by
//! sending CBOR-signed reset manifests to each burned OID. The chip verifies
//! each manifest against a Trust Anchor certificate provisioned at OID
//! `0xE0E3`, and on success applies the payload while bypassing the target
//! OID's normal `Change` AC.
//!
//! The manifests are generated offline by
//! `tools/optiga_reset/gen_reset_manifests.py` (which drives the Infineon
//! `protected_update_data_set` tool) and compiled into the firmware as
//! `include_bytes!`. The signing key lives next to the tool; it is the
//! sample EC P-256 key from Infineon's example set. This is a dev-only
//! recovery path — once the OIDs are unburned and the real wallet
//! provisioning succeeds, builds drop the `optiga-reset-oids` feature.

use super::apdu::{self, OptigaError};
use super::ifx_i2c::IfxState;
use super::shield::ShieldedConnection;

/// OID to store the Trust Anchor cert. `0xE0E3..0xE0E8` are reserved for
/// Trust Anchors; `0xE0E3` is the default in Infineon's tool.
pub const TRUST_ANCHOR_OID: u16 = 0xE0E3;

/// Metadata for a Trust Anchor OID, verbatim from
/// `examples/optiga/example_optiga_util_protected_update.c` in the Infineon
/// reference: Execute=Always, DataType=TrustAnchor(0x11).
const TRUST_ANCHOR_METADATA: &[u8] = &[0x20, 0x06, 0xD3, 0x01, 0x00, 0xE8, 0x01, 0x11];

/// DER X.509 cert matching `samples/integrity/sample_ec_256_priv.pem` from
/// the Infineon protected-update tool. The matching private key signed every
/// manifest in `RESET_BLOB`; keeping the pairing in lockstep is what makes
/// the chip accept our manifests.
const TRUST_ANCHOR_CERT: &[u8] =
    include_bytes!("../../../tools/optiga_reset/out/trust_anchor_cert.bin");

/// Concatenated reset-manifest bundle. Layout (big-endian throughout):
///   u16 num_entries
///   repeat num_entries times:
///     u16 target_oid
///     u16 manifest_len
///     u16 fragment_len
///     u8[manifest_len] manifest_bytes    (COSE_Sign1 CBOR)
///     u8[fragment_len] fragment_bytes    (metadata payload)
const RESET_BLOB: &[u8] =
    include_bytes!("../../../tools/optiga_reset/out/reset_manifests.bin");

/// Write the Trust Anchor cert + matching metadata to `TRUST_ANCHOR_OID`.
///
/// Safe to call even if the OID has already been provisioned — the chip
/// will reject the writes and we bubble the error up so the caller can
/// decide whether that's fatal. Typical flow: call once per fresh chip,
/// ignore any "access denied" on subsequent runs.
///
/// Two SetDataObject writes total: metadata first (so DataType is set to
/// TrustAnchor(0x11) before the cert bytes land), then the cert payload.
/// Staying at two writes keeps us under the observed per-session write
/// throttle.
pub unsafe fn provision_trust_anchor(
    ifx: &mut IfxState,
    shield: &mut ShieldedConnection,
) -> Result<(), OptigaError> {
    // Dump current metadata first so we can tell if the slot is
    // already in a non-Creation LcsO (which would make Change AC
    // refuse the cert write) or dimensioned differently from what
    // we expect.
    let mut meta = [0u8; 128];
    let res = apdu::get_metadata(ifx, shield, TRUST_ANCHOR_OID, &mut meta);
    if let Ok(n) = res {
        let log_n = n.min(64);
        secure_log!(
            "[OPTIGA][reset] TA OID 0x{:04X} current metadata ({} bytes): {:02x?}",
            TRUST_ANCHOR_OID, n, &meta[..log_n]
        );
    } else if let Err(e) = res {
        secure_log!(
            "[OPTIGA][reset] TA OID 0x{:04X} get_metadata FAILED: {:?}",
            TRUST_ANCHOR_OID, e
        );
    }

    secure_log!(
        "[OPTIGA][reset] writing TA metadata ({} bytes) to OID 0x{:04X}",
        TRUST_ANCHOR_METADATA.len(), TRUST_ANCHOR_OID
    );
    apdu::set_metadata(ifx, shield, TRUST_ANCHOR_OID, TRUST_ANCHOR_METADATA)?;

    secure_log!(
        "[OPTIGA][reset] writing TA cert ({} bytes) to OID 0x{:04X}",
        TRUST_ANCHOR_CERT.len(), TRUST_ANCHOR_OID
    );
    apdu::set_data_object(ifx, shield, TRUST_ANCHOR_OID, TRUST_ANCHOR_CERT)?;

    // Deliberately no readback here — every extra APDU eats into the
    // per-session op budget before we get to the manifest sends.
    Ok(())
}

/// A single entry extracted from `RESET_BLOB`: the target OID, the
/// CBOR-signed manifest for it, and the fragment payload.
pub struct ResetEntry<'a> {
    pub oid: u16,
    pub manifest: &'a [u8],
    pub fragment: &'a [u8],
}

/// Iterator over the embedded reset bundle. Skips entries whose sizes
/// don't match the declared lengths — those are a sign of a regeneration
/// bug and we'd rather surface them loudly than silently send garbage.
pub fn iter_reset_entries() -> impl Iterator<Item = ResetEntry<'static>> {
    let mut pos = 2usize;
    let num = if RESET_BLOB.len() >= 2 {
        u16::from_be_bytes([RESET_BLOB[0], RESET_BLOB[1]]) as usize
    } else {
        0
    };
    let mut remaining = num;

    core::iter::from_fn(move || {
        if remaining == 0 || pos + 6 > RESET_BLOB.len() {
            return None;
        }
        remaining -= 1;

        let oid = u16::from_be_bytes([RESET_BLOB[pos], RESET_BLOB[pos + 1]]);
        let m_len = u16::from_be_bytes([RESET_BLOB[pos + 2], RESET_BLOB[pos + 3]]) as usize;
        let f_len = u16::from_be_bytes([RESET_BLOB[pos + 4], RESET_BLOB[pos + 5]]) as usize;
        pos += 6;
        if pos + m_len + f_len > RESET_BLOB.len() {
            return None;
        }
        let manifest = &RESET_BLOB[pos..pos + m_len];
        pos += m_len;
        let fragment = &RESET_BLOB[pos..pos + f_len];
        pos += f_len;

        Some(ResetEntry { oid, manifest, fragment })
    })
}

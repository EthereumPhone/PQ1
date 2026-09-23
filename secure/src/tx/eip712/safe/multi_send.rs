//! Strict decoder + classifier for Safe `MultiSendCallOnly` batches.
//!
//! The Safe web UI wraps any flow needing more than one action in
//! `SafeTx{to = MultiSendCallOnly, operation = 1 (DELEGATECALL),
//! data = multiSend(transactions)}` — e.g. a CoW order placement is
//! `[ERC-20 approve(GPv2VaultRelayer, amount), setPreSignature(uid,
//! true)]`. DELEGATECALL runs the target's code in the Safe's own
//! storage context, so the packed payload is only worth decoding when
//! the target is a known-good MultiSend implementation:
//!
//!   * **Address allowlist** — only the four canonical
//!     `MultiSendCallOnly` deployments (v1.3.0 canonical / v1.3.0
//!     eip155 / v1.4.1 / v1.5.0) are accepted as a DELEGATECALL target.
//!     Any other target keeps today's hard refusal at the Safe
//!     verifiers' operation gates.
//!   * **No `to == 0` record** — v1.5.0 rewrites a zero `to` to the
//!     Safe itself; refusing it for every target keeps the rendered
//!     record target equal to the address the chain calls.
//!   * **Per-record `operation == 0`** — mirrors MultiSendCallOnly's
//!     on-chain revert, so no nested DELEGATECALL can ride a record
//!     even if the allowlist were somehow wrong.
//!   * **Strict ABI framing** — canonical `multiSend(bytes)` encoding
//!     only: head offset exactly 0x20, exact total length, zero
//!     padding. Anything Solidity wouldn't emit is refused, so the
//!     on-device render can never disagree with on-chain decoding.
//!
//! ## One predicate, four call sites
//!
//! [`is_multisend_claim`] is THE acceptance predicate for
//! `operation == 1`, shared verbatim by (a) the `safe_v1` verifier's
//! operation gate, (b) the `execTransaction` verifier's operation
//! gate, (c) the CoW-binding resolver's multiSend arm, and (d) the
//! renderer's defensive re-check + `Op:` row. A divergence between
//! any two of those would let a DELEGATECALL SafeTx verify but fall
//! through to a render path that mislabels it — keeping them one
//! function makes that drift impossible.

use sphincs_tz_shared::{MULTISEND_CALL_ONLY_ADDRESSES, MULTI_SEND_SELECTOR};

use super::cow_binding::safe_inner_is_cow_presign;

// The strict outer-framing decoder, its 32-byte word reader, the refusal
// taxonomy, AND the inner packed-record walk (`MsRecord` + `MsRecordIter`)
// were extracted, verbatim and behaviour-identical, into the
// host-compilable `pqsigner-tx` crate so they can be bounded-verified
// (Kani canonical-acceptance / soundness on `decode_multisend` — see
// `pqsigner_tx::multisend::verification`) and exercised by the
// `revm`/MultiSendCallOnly bytecode differential over the record walk
// (`fuzz/tests/multisend_record_walk_differential.rs`). Re-exported here
// so every caller below (`is_multisend_claim`, `summarize`,
// `multisend_verdict`, the renderer, the test suite, …) and the external
// call sites (`safe_display`, `cowswap::e2e_decode_tests`) keep working
// unchanged.
pub use pqsigner_tx::multisend::{
    classify_record_kind, decode_multisend, read_u32_word, record_needs_value_page,
    records_pages_total, summarize, MsError, MsRecord, MsRecordIter, MsRecordKind, MsSummary,
};

/// Is `to` one of the canonical `MultiSendCallOnly` deployments?
#[must_use]
pub fn is_allowlisted_multisend(to: &[u8; 20]) -> bool {
    MULTISEND_CALL_ONLY_ADDRESSES.iter().any(|a| a == to)
}

/// Does this SafeTx inner call claim to be an allowlisted multiSend
/// batch?
///
/// `operation == 1` is part of the predicate on purpose: under
/// `operation == 0` (CALL) the MultiSend contract — not the Safe — is
/// `msg.sender` for every record, so none of the record semantics the
/// trusted UI would render (CoW `uid.owner == the Safe` above all)
/// hold. An op-0 call to a MultiSend address therefore stays on
/// the generic call path, where the pinned known-call filter still decides
/// whether an opaque display is allowed or must refuse.
///
/// Like [`safe_inner_is_cow_presign`], this deliberately does NOT
/// shape-check the payload — the claim must also fire for a malformed
/// blob so it refuses loudly instead of falling through to a
/// blind-sign page the user might habituate to confirming.
#[must_use]
pub fn is_multisend_claim(operation: u8, to: &[u8; 20], data: &[u8]) -> bool {
    operation == 1
        && is_allowlisted_multisend(to)
        && data.len() >= 4
        && data[..4] == MULTI_SEND_SELECTOR
}

// ---------------------------------------------------------------------------
// Strict decode + inner record walk — `decode_multisend`,
// `read_u32_word`, `MsError`, `MsRecord`, and `MsRecordIter` now live in
// `pqsigner_tx::multisend` (re-exported above) so the outer framing can
// be Kani-bounded and the inner record walk can be diffed against real
// MultiSendCallOnly bytecode in revm. The summary / classification below
// still consume them.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Summary + acceptance verdict
// ---------------------------------------------------------------------------

// `MsSummary`, `summarize`, and `summarize_packed` moved to
// `pqsigner_tx::multisend` (re-exported above) so the per-record
// `operation == 0` DELEGATECALL-refusal is Kani-bounded
// (`summarize_accept_implies_all_call`, finding 3b-1 in
// ADVERSARIAL_REVIEW_KANI_2026-07-01.md). Behaviour is byte-identical —
// the loop, including the op→count-cap→presign→count==0 precedence, moved
// verbatim.

/// The data slice of the unique presign-claiming record, when there is
/// exactly one. The CoW-binding resolver binds the cow_order trailer to
/// these bytes.
#[must_use]
pub fn presign_record_data(data: &[u8]) -> Option<&[u8]> {
    let packed = decode_multisend(data).ok()?;
    let mut found: Option<&[u8]> = None;
    for rec in MsRecordIter::new(packed) {
        let rec = rec.ok()?;
        if safe_inner_is_cow_presign(&rec.to, rec.data) {
            if found.is_some() {
                return None; // ambiguous — refused upstream anyway
            }
            found = Some(rec.data);
        }
    }
    found
}

/// Does any record target `contract`? Used by the handlers' ERC-20
/// metadata acceptance gate: an outer ERC-20 trailer attributed to a
/// token one of the records calls is allowed through to the renderer
/// (which re-checks the address per record before applying it).
#[must_use]
pub fn any_record_to_matches(data: &[u8], contract: &[u8; 20]) -> bool {
    let Ok(packed) = decode_multisend(data) else {
        return false;
    };
    for rec in MsRecordIter::new(packed) {
        match rec {
            Ok(r) if &r.to == contract => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
    false
}

/// Handler-level acceptance verdict for a verified Safe context's
/// inner call. One shared mapping so the single and batch handlers
/// cannot drift.
pub enum MsVerdict {
    /// Inner call is not a (claimed) allowlisted multiSend — not this
    /// module's business.
    NotMultiSend,
    /// Decodes cleanly under every hard rule; carry the shape facts.
    Accept(MsSummary),
    /// Claimed multiSend that violates a hard rule. The handler must
    /// refuse to sign — a DELEGATECALL payload has no degraded render.
    Reject(&'static str),
}

#[must_use]
pub fn multisend_verdict(operation: u8, to: &[u8; 20], raw: &[u8]) -> MsVerdict {
    if !is_multisend_claim(operation, to, raw) {
        return MsVerdict::NotMultiSend;
    }
    match summarize(raw) {
        Ok(s) if s.presign_claims >= 2 => MsVerdict::Reject("msend 2+ presign"),
        Ok(s) => MsVerdict::Accept(s),
        Err(e) => MsVerdict::Reject(e.as_status_str()),
    }
}

// ---------------------------------------------------------------------------
// Per-record display classification + page accounting (layer 3)
// ---------------------------------------------------------------------------
//
// `MsRecordKind`, `classify_record_kind`, `record_content_pages`,
// `record_needs_value_page`, and `records_pages_total` were extracted,
// verbatim and behaviour-identical, into `pqsigner_tx::multisend`
// (re-exported above) so the page-budget gate is host-compilable and
// Kani-bounded (panic/OOB-freedom + per-record page bound + the
// no-hidden-value soundness — see `pqsigner_tx::multisend::verification`).
// Their whole dependency closure is pure / already in `pqsigner-tx`
// (`safe_inner_is_cow_presign`, `classify_safe_mgmt`/`page_count`,
// `parse_erc20_calldata`); the verified-context glue (`resolve_cow_binding`,
// `VerifiedSafe*`) and the summary/verdict layer above stay here.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Host-test builders for canonical multiSend calldata, shared with the
/// `cow_binding` / `verify` / `extra_tests` suites so every test
/// constructs the wire shape through one encoder.
#[cfg(test)]
pub mod test_util {
    use sphincs_tz_shared::{
        GPV2_SETTLEMENT_ADDRESS, GPV2_VAULT_RELAYER_ADDRESS, MULTI_SEND_SELECTOR,
        SET_PRE_SIGNATURE_SELECTOR,
    };
    extern crate alloc;
    use alloc::vec::Vec;

    pub const ZERO_VALUE: [u8; 32] = [0u8; 32];

    /// Pack one record: `op || to || value || dataLen || data`.
    pub fn pack_record(op: u8, to: &[u8; 20], value: &[u8; 32], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(op);
        out.extend_from_slice(to);
        out.extend_from_slice(value);
        let mut len_word = [0u8; 32];
        len_word[28..32].copy_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&len_word);
        out.extend_from_slice(data);
        out
    }

    /// Canonical `multiSend(bytes)` calldata around a packed payload.
    pub fn encode_multisend(packed: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MULTI_SEND_SELECTOR);
        let mut offset_word = [0u8; 32];
        offset_word[31] = 0x20;
        out.extend_from_slice(&offset_word);
        let mut len_word = [0u8; 32];
        len_word[28..32].copy_from_slice(&(packed.len() as u32).to_be_bytes());
        out.extend_from_slice(&len_word);
        out.extend_from_slice(packed);
        // Zero-pad to a 32-byte boundary, like Solidity.
        let pad = (32 - packed.len() % 32) % 32;
        out.extend_from_slice(&alloc::vec![0u8; pad]);
        out
    }

    /// Selector-correct 164-byte presign calldata (zero body — the
    /// resolver and decoder don't shape-check; the CoW pipeline does).
    pub fn presign_calldata_stub() -> [u8; 164] {
        let mut cd = [0u8; 164];
        cd[..4].copy_from_slice(&SET_PRE_SIGNATURE_SELECTOR);
        cd
    }

    /// Strict 68-byte `approve(spender, amount)` calldata.
    pub fn approve_calldata(spender: &[u8; 20], amount_low: u8) -> [u8; 68] {
        let mut cd = [0u8; 68];
        cd[..4].copy_from_slice(&[0x09, 0x5e, 0xa7, 0xb3]);
        cd[16..36].copy_from_slice(spender);
        cd[67] = amount_low;
        cd
    }

    /// Strict 100-byte `transferFrom(from, to, amount)` calldata. The
    /// `from` is the debited account the renderer surfaces on its own page.
    pub fn transfer_from_calldata(from: &[u8; 20], to: &[u8; 20], amount_low: u8) -> [u8; 100] {
        let mut cd = [0u8; 100];
        cd[..4].copy_from_slice(&[0x23, 0xb8, 0x72, 0xdd]);
        cd[16..36].copy_from_slice(from);
        cd[48..68].copy_from_slice(to);
        cd[99] = amount_low;
        cd
    }

    /// The Safe-UI CoW flow: `[approve(vault relayer) on TOKEN,
    /// setPreSignature]`, both records op 0 / value 0, wrapped in
    /// canonical multiSend calldata. `presign` defaults to the stub.
    pub fn cow_flow_calldata_with(token: &[u8; 20], presign: &[u8]) -> Vec<u8> {
        let mut packed = pack_record(
            0,
            token,
            &ZERO_VALUE,
            &approve_calldata(&GPV2_VAULT_RELAYER_ADDRESS, 1),
        );
        packed.extend_from_slice(&pack_record(
            0,
            &GPV2_SETTLEMENT_ADDRESS,
            &ZERO_VALUE,
            presign,
        ));
        encode_multisend(&packed)
    }

    pub fn cow_flow_calldata() -> Vec<u8> {
        cow_flow_calldata_with(&[0x70u8; 20], &presign_calldata_stub())
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::{
        approve_calldata, cow_flow_calldata, encode_multisend, pack_record, transfer_from_calldata,
        ZERO_VALUE,
    };
    use super::*;
    use crate::erc20::calldata::Erc20Call;
    use sphincs_tz_shared::{
        GPV2_SETTLEMENT_ADDRESS, GPV2_VAULT_RELAYER_ADDRESS, MULTISEND_MAX_RECORDS,
        SET_PRE_SIGNATURE_SELECTOR,
    };
    extern crate alloc;
    use alloc::vec::Vec;

    const MS_CALL_ONLY_130: [u8; 20] = MULTISEND_CALL_ONLY_ADDRESSES[0];
    const SAFE_ADDR: [u8; 20] = [0x5a; 20];

    fn presign_calldata() -> [u8; 164] {
        super::test_util::presign_calldata_stub()
    }

    // ── claim predicate ────────────────────────────────────────────

    #[test]
    fn claim_true_for_allowlisted_op1_multisend() {
        let cd = cow_flow_calldata();
        for a in &MULTISEND_CALL_ONLY_ADDRESSES {
            assert!(is_multisend_claim(1, a, &cd));
        }
    }

    #[test]
    fn claim_false_for_op0() {
        // CALL to a MultiSend contract: the Safe is not msg.sender for
        // the records, so the claim must NOT fire (stays blind-sign).
        let cd = cow_flow_calldata();
        assert!(!is_multisend_claim(0, &MS_CALL_ONLY_130, &cd));
    }

    #[test]
    fn claim_false_for_non_allowlisted_target() {
        let cd = cow_flow_calldata();
        assert!(!is_multisend_claim(1, &[0xaa; 20], &cd));
        // Plain MultiSend v1.3.0 — deliberately NOT allowlisted.
        let plain: [u8; 20] = [
            0xa2, 0x38, 0xcb, 0xeb, 0x14, 0x2c, 0x10, 0xef, 0x7a, 0xd8, 0x44, 0x2c, 0x6d, 0x1f,
            0x9e, 0x89, 0xe0, 0x7e, 0x77, 0x61,
        ];
        assert!(!is_multisend_claim(1, &plain, &cd));
    }

    #[test]
    fn claim_false_for_wrong_selector_or_short_data() {
        let mut cd = cow_flow_calldata();
        cd[0] ^= 1;
        assert!(!is_multisend_claim(1, &MS_CALL_ONLY_130, &cd));
        assert!(!is_multisend_claim(1, &MS_CALL_ONLY_130, &[0x8d, 0x80, 0xff]));
    }

    #[test]
    fn claim_fires_even_for_malformed_tail() {
        // Selector + allowlist match with a garbage body: the claim
        // must fire so the refusal is loud, not a blind-sign fallback.
        let cd = [0x8d, 0x80, 0xff, 0x0a, 0xde, 0xad];
        assert!(is_multisend_claim(1, &MS_CALL_ONLY_130, &cd));
        assert!(matches!(
            multisend_verdict(1, &MS_CALL_ONLY_130, &cd),
            MsVerdict::Reject(_)
        ));
    }

    // ── strict decode ──────────────────────────────────────────────

    #[test]
    fn decode_happy_two_records() {
        let cd = cow_flow_calldata();
        let packed = decode_multisend(&cd).expect("decode");
        let recs: Vec<_> = MsRecordIter::new(packed)
            .collect::<Result<Vec<_>, _>>()
            .expect("records");
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].to, [0x70u8; 20]);
        assert_eq!(recs[0].data.len(), 68);
        assert_eq!(recs[1].to, GPV2_SETTLEMENT_ADDRESS);
        assert_eq!(recs[1].data.len(), 164);
        assert!(recs.iter().all(|r| r.operation == 0 && r.value_is_zero()));
    }

    #[test]
    fn decode_rejects_wrong_selector() {
        let mut cd = cow_flow_calldata();
        cd[3] ^= 1;
        assert_eq!(decode_multisend(&cd).unwrap_err(), MsError::WrongSelector);
    }

    #[test]
    fn decode_rejects_short_input() {
        assert_eq!(
            decode_multisend(&MULTI_SEND_SELECTOR).unwrap_err(),
            MsError::ShortInput
        );
    }

    #[test]
    fn decode_rejects_nonstandard_offset() {
        let mut cd = cow_flow_calldata();
        cd[4 + 31] = 0x40; // offset word low byte: 0x20 → 0x40
        assert_eq!(decode_multisend(&cd).unwrap_err(), MsError::BadOffset);
        let mut cd2 = cow_flow_calldata();
        cd2[4] = 0x01; // offset word high bits set
        assert_eq!(decode_multisend(&cd2).unwrap_err(), MsError::BadOffset);
    }

    #[test]
    fn decode_rejects_length_overrun() {
        let mut cd = cow_flow_calldata();
        // Inflate the declared bytes length past the calldata end.
        let len_off = 4 + 32 + 28;
        let huge = (u32::MAX / 2).to_be_bytes();
        cd[len_off..len_off + 4].copy_from_slice(&huge);
        assert_eq!(decode_multisend(&cd).unwrap_err(), MsError::BadLength);
    }

    #[test]
    fn decode_rejects_length_high_bits() {
        let mut cd = cow_flow_calldata();
        cd[4 + 32] = 0x01; // length word byte above the u32 range
        assert_eq!(decode_multisend(&cd).unwrap_err(), MsError::BadLength);
    }

    #[test]
    fn decode_rejects_trailing_garbage() {
        let mut cd = cow_flow_calldata();
        cd.extend_from_slice(&[0u8; 32]); // extra all-zero word after the padded tail
        assert_eq!(decode_multisend(&cd).unwrap_err(), MsError::BadPadding);
    }

    #[test]
    fn decode_rejects_nonzero_padding() {
        let token = [0x70u8; 20];
        // 68-byte approve record → packed len 85+68 = 153 → 7 pad bytes.
        let packed = pack_record(
            0,
            &token,
            &ZERO_VALUE,
            &approve_calldata(&GPV2_VAULT_RELAYER_ADDRESS, 1),
        );
        let mut cd = encode_multisend(&packed);
        assert_eq!(packed.len() % 32 != 0, true, "test needs a padded tail");
        let last = cd.len() - 1;
        cd[last] = 0xff;
        assert_eq!(decode_multisend(&cd).unwrap_err(), MsError::BadPadding);
    }

    #[test]
    fn iter_rejects_truncated_record_header() {
        let packed = [0u8; 50]; // < 85-byte header
        let err = MsRecordIter::new(&packed).next().unwrap().unwrap_err();
        assert_eq!(err, MsError::TruncatedRecord);
    }

    #[test]
    fn iter_rejects_record_data_overrun() {
        let mut packed = pack_record(0, &[0x11; 20], &ZERO_VALUE, &[0xaa; 4]);
        // Inflate the record's dataLen beyond the slice end.
        packed[53 + 28..53 + 32].copy_from_slice(&100u32.to_be_bytes());
        let err = MsRecordIter::new(&packed).next().unwrap().unwrap_err();
        assert_eq!(err, MsError::TruncatedRecord);
    }

    #[test]
    fn iter_rejects_record_datalen_high_bits() {
        let mut packed = pack_record(0, &[0x11; 20], &ZERO_VALUE, &[]);
        packed[53] = 0x01;
        let err = MsRecordIter::new(&packed).next().unwrap().unwrap_err();
        assert_eq!(err, MsError::BadRecordDataLen);
    }

    // ── summarize ──────────────────────────────────────────────────

    #[test]
    fn summarize_cow_flow() {
        let cd = cow_flow_calldata();
        let s = summarize(&cd).expect("summary");
        assert_eq!(s.record_count, 2);
        assert_eq!(s.presign_claims, 1);
        assert_eq!(s.presign_idx, 1);
    }

    #[test]
    fn summarize_presign_only() {
        let packed = pack_record(0, &GPV2_SETTLEMENT_ADDRESS, &ZERO_VALUE, &presign_calldata());
        let s = summarize(&encode_multisend(&packed)).expect("summary");
        assert_eq!(s.record_count, 1);
        assert_eq!(s.presign_claims, 1);
        assert_eq!(s.presign_idx, 0);
    }

    #[test]
    fn summarize_rejects_record_op1() {
        let token = [0x70u8; 20];
        let mut packed = pack_record(
            1, // nested DELEGATECALL record
            &token,
            &ZERO_VALUE,
            &approve_calldata(&GPV2_VAULT_RELAYER_ADDRESS, 1),
        );
        packed.extend_from_slice(&pack_record(
            0,
            &GPV2_SETTLEMENT_ADDRESS,
            &ZERO_VALUE,
            &presign_calldata(),
        ));
        assert_eq!(
            summarize(&encode_multisend(&packed)).unwrap_err(),
            MsError::RecordOpNotCall
        );
    }

    /// MultiSendCallOnly v1.5.0 rewrites `to == 0` to `address(this)` —
    /// the Safe itself under DELEGATECALL — so a zero-`to` record would
    /// render as a call to `0x0000…` while executing a Safe self-call
    /// (e.g. `addOwnerWithThreshold`). Refused for every allowlisted
    /// target, and the verdict surfaces the banner.
    #[test]
    fn summarize_rejects_record_to_zero() {
        let mut packed = pack_record(
            0,
            &[0x70u8; 20],
            &ZERO_VALUE,
            &approve_calldata(&GPV2_VAULT_RELAYER_ADDRESS, 1),
        );
        packed.extend_from_slice(&pack_record(0, &[0u8; 20], &ZERO_VALUE, &[0x0d, 0x58, 0x2f, 0x13]));
        let cd = encode_multisend(&packed);
        assert_eq!(summarize(&cd).unwrap_err(), MsError::RecordToZero);
        for a in &MULTISEND_CALL_ONLY_ADDRESSES {
            assert!(matches!(
                multisend_verdict(1, a, &cd),
                MsVerdict::Reject("msend rec to=0")
            ));
        }
    }

    #[test]
    fn summarize_rejects_zero_records() {
        assert_eq!(
            summarize(&encode_multisend(&[])).unwrap_err(),
            MsError::BadRecordCount
        );
    }

    #[test]
    fn summarize_rejects_too_many_records() {
        let mut packed = Vec::new();
        for i in 0..=MULTISEND_MAX_RECORDS {
            packed.extend_from_slice(&pack_record(0, &[i as u8 + 1; 20], &ZERO_VALUE, &[]));
        }
        assert_eq!(
            summarize(&encode_multisend(&packed)).unwrap_err(),
            MsError::BadRecordCount
        );
    }

    #[test]
    fn summarize_counts_two_presign_claims() {
        let mut packed = pack_record(
            0,
            &GPV2_SETTLEMENT_ADDRESS,
            &ZERO_VALUE,
            &presign_calldata(),
        );
        packed.extend_from_slice(&pack_record(
            0,
            &GPV2_SETTLEMENT_ADDRESS,
            &ZERO_VALUE,
            &presign_calldata(),
        ));
        let cd = encode_multisend(&packed);
        let s = summarize(&cd).expect("summary");
        assert_eq!(s.presign_claims, 2);
        // …and the verdict refuses the ambiguity.
        assert!(matches!(
            multisend_verdict(1, &MS_CALL_ONLY_130, &cd),
            MsVerdict::Reject("msend 2+ presign")
        ));
        // …and the binding extractor declines to pick one.
        assert!(presign_record_data(&cd).is_none());
    }

    // ── presign extraction + record-target scan ───────────────────

    #[test]
    fn presign_record_data_returns_the_record_slice() {
        let cd = cow_flow_calldata();
        let data = presign_record_data(&cd).expect("presign record");
        assert_eq!(data.len(), 164);
        assert_eq!(&data[..4], &SET_PRE_SIGNATURE_SELECTOR);
        // The slice borrows from inside `cd` (no copy).
        let cd_range = cd.as_ptr() as usize..cd.as_ptr() as usize + cd.len();
        assert!(cd_range.contains(&(data.as_ptr() as usize)));
    }

    #[test]
    fn any_record_to_matches_finds_token_and_settlement() {
        let cd = cow_flow_calldata();
        assert!(any_record_to_matches(&cd, &[0x70u8; 20]));
        assert!(any_record_to_matches(&cd, &GPV2_SETTLEMENT_ADDRESS));
        assert!(!any_record_to_matches(&cd, &[0xaa; 20]));
    }

    // ── verdict ────────────────────────────────────────────────────

    #[test]
    fn verdict_not_multisend_for_direct_presign() {
        let cd = presign_calldata();
        assert!(matches!(
            multisend_verdict(0, &GPV2_SETTLEMENT_ADDRESS, &cd),
            MsVerdict::NotMultiSend
        ));
    }

    #[test]
    fn verdict_accepts_cow_flow() {
        let cd = cow_flow_calldata();
        match multisend_verdict(1, &MS_CALL_ONLY_130, &cd) {
            MsVerdict::Accept(s) => {
                assert_eq!(s.record_count, 2);
                assert_eq!(s.presign_claims, 1);
            }
            _ => panic!("expected Accept"),
        }
    }

    // ── classification + page accounting ──────────────────────────

    #[test]
    fn classify_matrix() {
        // CoW claim
        assert!(matches!(
            classify_record_kind(&GPV2_SETTLEMENT_ADDRESS, true, &presign_calldata(), &SAFE_ADDR),
            MsRecordKind::CowPresignClaim
        ));
        // ERC-20 approve
        assert!(matches!(
            classify_record_kind(
                &[0x70; 20],
                true,
                &approve_calldata(&GPV2_VAULT_RELAYER_ADDRESS, 1),
                &SAFE_ADDR
            ),
            MsRecordKind::Erc20(Erc20Call::Approve { .. })
        ));
        // Safe self-call, recognised mgmt op (changeThreshold(2))
        let mut mgmt = [0u8; 36];
        mgmt[..4].copy_from_slice(&[0x69, 0x4e, 0x80, 0xc3]);
        mgmt[35] = 2;
        assert!(matches!(
            classify_record_kind(&SAFE_ADDR, true, &mgmt, &SAFE_ADDR),
            MsRecordKind::SafeMgmt(_)
        ));
        // Safe self-call, unknown selector
        assert!(matches!(
            classify_record_kind(&SAFE_ADDR, true, &[0xde, 0xad, 0xbe, 0xef], &SAFE_ADDR),
            MsRecordKind::UnknownSafeSelf
        ));
        // Empty / plain ETH
        assert!(matches!(
            classify_record_kind(&[0x11; 20], true, &[], &SAFE_ADDR),
            MsRecordKind::EmptyCall
        ));
        assert!(matches!(
            classify_record_kind(&[0x11; 20], false, &[], &SAFE_ADDR),
            MsRecordKind::PlainEth
        ));
        // Opaque
        assert!(matches!(
            classify_record_kind(&[0x11; 20], true, &[0xd0, 0xe3, 0x0d, 0xb0], &SAFE_ADDR),
            MsRecordKind::Blind
        ));
    }

    #[test]
    fn value_page_rules() {
        let blind = MsRecordKind::Blind;
        assert!(record_needs_value_page(&blind, false));
        assert!(!record_needs_value_page(&blind, true));
        assert!(!record_needs_value_page(&MsRecordKind::PlainEth, false));
        assert!(!record_needs_value_page(&MsRecordKind::EmptyCall, true));
    }

    #[test]
    fn pages_total_cow_flow() {
        let cd = cow_flow_calldata();
        // approve: 1 divider + 4 content; presign (native body 1+8=9):
        // 1 divider + 9 content → 15.
        assert_eq!(records_pages_total(&cd, &SAFE_ADDR, 9), Some(15));
        // With a seven-page native body: approve(5) + presign(8) = 13.
        assert_eq!(records_pages_total(&cd, &SAFE_ADDR, 7), Some(13));
    }

    #[test]
    fn pages_total_counts_value_pages() {
        // One blind record carrying ETH: divider + value page + 3 blind.
        let mut value = [0u8; 32];
        value[31] = 1;
        let packed = pack_record(0, &[0x11; 20], &value, &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(
            records_pages_total(&encode_multisend(&packed), &SAFE_ADDR, 9),
            Some(5)
        );
    }

    /// WYSIWYS lockstep (audit 2026-06-18 — transferFrom `from` page). A
    /// transferFrom record debits a third-party `from`, so it renders one
    /// extra "From (debited)" page: divider(1) + header+From+recipient+
    /// amount+contract(5) = 6. This pins `record_content_pages` against the
    /// `safe_display` renderer (which is `#[cfg(not(test))]` and so has no
    /// host coverage of its own) — if the two ever drift, the multiSend
    /// page-budget gate would mis-size and silently drop or blank a page.
    #[test]
    fn pages_total_transfer_from_adds_from_page() {
        let xfer_from = encode_multisend(&pack_record(
            0,
            &[0x70; 20], // token (not the Safe → classifies as Erc20)
            &ZERO_VALUE,
            &transfer_from_calldata(&[0xaa; 20], &[0xbb; 20], 7),
        ));
        assert_eq!(records_pages_total(&xfer_from, &SAFE_ADDR, 9), Some(6));

        // A plain `approve` (no `from`) stays at divider(1) + 4 = 5.
        let approve = encode_multisend(&pack_record(
            0,
            &[0x70; 20],
            &ZERO_VALUE,
            &approve_calldata(&[0xbb; 20], 7),
        ));
        assert_eq!(records_pages_total(&approve, &SAFE_ADDR, 9), Some(5));
    }
}

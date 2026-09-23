//! Strict outer-framing decoder for Safe `MultiSendCallOnly` calldata.
//!
//! This is the pure-logic core of the Safe multiSend WYSIWYS path
//! (layer 1 — outer ABI framing): the `multiSend(bytes)` argument
//! decoder and its 32-byte-word reader, plus the [`MsError`] refusal
//! taxonomy shared across the whole pipeline. It is extracted here,
//! verbatim and behaviour-identical, so it can be host-compiled and
//! bounded-verified with Kani (`cargo kani -p pqsigner-tx`) — the
//! firmware-side `secure/src/tx/eip712/safe/multi_send.rs` re-exports
//! these three items unchanged, so every existing caller, the record
//! iterator, the classifier, and the full test suite keep working.
//!
//! Dependency closure stays pure: `pqsigner-proto` constants plus the
//! already-extracted `crate::{erc20, safe_mgmt}` decoders. The per-record
//! display classification + page-budget accounting (layer 3 —
//! `MsRecordKind` / `classify_record_kind` / `record_content_pages` /
//! `record_needs_value_page` / `records_pages_total`) and the pure
//! `safe_inner_is_cow_presign` predicate live here too; only the
//! verified-context glue (`resolve_cow_binding`, `VerifiedSafe*`) and the
//! summary/verdict layer stay in `secure/`. No hashing, no zk.
//!
//! ## The proven property (canonical-acceptance / soundness)
//!
//! `decode_multisend(data) == Ok(payload)` ⟹ `data` is **byte-exactly**
//! the unique canonical Solidity encoding
//! `selector ‖ offset_word(==0x20) ‖ len_word(==payload.len())
//! ‖ payload ‖ zero-pad-to-32`, with nothing trailing and every pad
//! byte zero. So the on-device decode can never structurally disagree
//! with on-chain decoding, and no hidden trailing "second payload" can
//! ride a DELEGATECALL batch the user blind-confirms.
//!
//! The inner packed-record walk ([`MsRecordIter`]) is proven too: over
//! symbolic payloads, an all-`Ok` walk **exactly partitions** the payload
//! (`Σ (header + data) == payload.len()` — no hidden trailing record/data
//! the device never renders) and every displayed field (`operation`,
//! `to`, `value`, `data`) is the verbatim payload bytes. See the
//! `#[cfg(kani)] mod verification` harnesses at the bottom of this file.
//!
//! **Per-record DELEGATECALL refusal — now bounded-Kani-proven (finding 3b-1).**
//! The record-walk harnesses prove field *extraction* (the displayed `operation`
//! byte equals the verbatim payload byte); the *validation* that `operation == 0`
//! (no nested DELEGATECALL) is the [`summarize_packed`] gate. Harness
//! `summarize_accept_implies_all_call` proves `summarize_packed(p).is_ok()` ⟹
//! every record's `operation == 0` over symbolic payloads (≤ 2 records, the D1
//! bound — BOUNDED-∀, not full-∀), and `kani_mutations.json:
//! multisend_op0_delegatecall` guards it against vacuity. Backed defense-in-depth
//! by the on-chain `MultiSendCallOnly` revert (`is_multisend_claim` pins the batch
//! `to` to `MULTISEND_CALL_ONLY_ADDRESSES`). See
//! `ADVERSARIAL_REVIEW_KANI_2026-07-01.md` finding 3b-1.
//!
//! **Pointer-width scope (finding 3b-3).** These harnesses run under
//! `cargo kani` at the HOST target (64-bit `usize`); the shipped decoder runs on
//! thumbv8m (32-bit `usize`). The decode DECISIONS transfer because on the ACCEPT
//! path every length/offset is `≤ N` (the bounded symbolic buffer), well inside
//! 32-bit range, so no accept-vs-reject verdict differs between widths; on the
//! REJECT path the `checked_add`/`checked_mul` overflow guards fail-closed at
//! either width. Not mechanically re-proven at 32-bit — run kani with
//! `-C target-pointer-width=32` to close it.

use sphincs_tz_shared::{
    GPV2_SETTLEMENT_ADDRESS, MULTISEND_MAX_RECORDS, MULTI_SEND_SELECTOR, SET_PRE_SIGNATURE_SELECTOR,
};

use crate::erc20::calldata::{parse_erc20_calldata, Erc20Call};
use crate::safe_mgmt::{classify_safe_mgmt, page_count as mgmt_page_count, SafeMgmtOp};

/// Decode / classification failures. Every variant is a hard refusal —
/// there is no degraded render for a DELEGATECALL payload.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum MsError {
    /// Calldata shorter than `selector + offset word + length word`.
    ShortInput,
    /// `calldata[..4] != multiSend(bytes)`.
    WrongSelector,
    /// The `bytes` head offset is not exactly 32 (the only value the
    /// canonical Solidity encoding produces).
    BadOffset,
    /// The `bytes` length word has bits above u32, or the declared
    /// payload runs past the calldata end.
    BadLength,
    /// Calldata extends past the zero-padded payload end, or the
    /// padding bytes are non-zero. Trailing garbage could carry a
    /// second, undisplayed payload interpretation.
    BadPadding,
    /// A record header or its declared `data` runs past the packed
    /// slice end.
    TruncatedRecord,
    /// A record's `dataLen` word has bits above u32.
    BadRecordDataLen,
    /// A record's `operation` byte is not 0 (Call). MultiSendCallOnly
    /// reverts on-chain for these; we refuse on-device for the same
    /// reason — a nested DELEGATECALL is not honestly clear-signable.
    RecordOpNotCall,
    /// A record's `to` is the zero address. MultiSendCallOnly v1.5.0
    /// rewrites `to == 0` to `address(this)` — under the SafeTx
    /// DELEGATECALL that is the Safe itself — while v1.3.0/v1.4.1 call
    /// `0x0` literally. Refused for every target so the rendered `to`
    /// is always the address the chain actually calls.
    RecordToZero,
    /// Zero records, or more than `MULTISEND_MAX_RECORDS`.
    BadRecordCount,
}

impl MsError {
    /// Short (≤16 col) status-line reason for the refusal banner.
    #[must_use]
    pub fn as_status_str(self) -> &'static str {
        match self {
            MsError::ShortInput
            | MsError::WrongSelector
            | MsError::BadOffset
            | MsError::BadLength
            | MsError::BadPadding
            | MsError::TruncatedRecord
            | MsError::BadRecordDataLen => "msend malformed",
            MsError::RecordOpNotCall => "msend rec op!=0",
            MsError::RecordToZero => "msend rec to=0",
            MsError::BadRecordCount => "msend rec count",
        }
    }
}

/// Read a 32-byte ABI word as `usize`, requiring all bits above u32 to
/// be zero (calldata is u16-bounded upstream anyway).
pub fn read_u32_word(word: &[u8]) -> Result<usize, MsError> {
    debug_assert_eq!(word.len(), 32);
    if word[..28].iter().any(|&b| b != 0) {
        return Err(MsError::BadLength);
    }
    Ok(u32::from_be_bytes([word[28], word[29], word[30], word[31]]) as usize)
}

/// Strictly decode `multiSend(bytes)` calldata down to the packed
/// records slice.
///
/// Canonical-encoding-only: head offset must be exactly 0x20, the
/// total calldata length must equal `4 + 64 + ceil32(len)` and every
/// padding byte must be zero. Anything else is refused — the firmware
/// never renders a payload whose on-chain decoding could differ from
/// the on-device one.
pub fn decode_multisend(data: &[u8]) -> Result<&[u8], MsError> {
    if data.len() < 4 + 64 {
        return Err(MsError::ShortInput);
    }
    if data[..4] != MULTI_SEND_SELECTOR {
        return Err(MsError::WrongSelector);
    }
    let head = &data[4..];
    // Offset word: the canonical encoding of a single dynamic `bytes`
    // argument always places the tail immediately after the one-word
    // head, i.e. offset == 32.
    if read_u32_word(&head[0..32]).map_err(|_| MsError::BadOffset)? != 32 {
        return Err(MsError::BadOffset);
    }
    let len = read_u32_word(&head[32..64])?;
    let payload_start = 64usize;
    let payload_end = payload_start.checked_add(len).ok_or(MsError::BadLength)?;
    if payload_end > head.len() {
        return Err(MsError::BadLength);
    }
    // Exact-length + zero-padding: Solidity pads the bytes tail to a
    // 32-byte boundary with zeros and emits nothing after it.
    let padded_end = payload_end
        .checked_add(31)
        .ok_or(MsError::BadLength)?
        / 32
        * 32;
    if head.len() != padded_end {
        return Err(MsError::BadPadding);
    }
    if head[payload_end..padded_end].iter().any(|&b| b != 0) {
        return Err(MsError::BadPadding);
    }
    Ok(&head[payload_start..payload_end])
}

// ---------------------------------------------------------------------------
// Inner packed-record walk (layer 2)
// ---------------------------------------------------------------------------
//
// Extracted here, verbatim and behaviour-identical, alongside the
// outer-framing decoder so the per-record loop is host-runnable and can
// be exercised by the `revm`/MultiSendCallOnly bytecode differential
// (move 3 of the firmware bounded-verification plan) — the one layer the
// Kani canonical-acceptance proof on `decode_multisend` structurally
// cannot reach, because the packed-record encoding mirrors
// MultiSendCallOnly's hand-rolled assembly rather than standard ABI.
// `secure/src/tx/eip712/safe/multi_send.rs` re-exports `MsRecord` and
// `MsRecordIter` unchanged, so `summarize`, `classify_record_kind`, the
// renderer, and the full test suite keep working.

/// Fixed per-record header: `operation(1) || to(20) || value(32) ||
/// dataLen(32)`, followed by `data(dataLen)`. Packed encoding — no
/// padding between records.
pub const MS_RECORD_HEADER_LEN: usize = 1 + 20 + 32 + 32;

/// One packed multiSend record. `data` borrows from the same snapshot
/// the multiSend calldata lives in.
#[derive(Copy, Clone, Debug)]
pub struct MsRecord<'a> {
    /// Raw operation byte. `summarize` (and therefore every accepted
    /// payload) requires this to be 0; the iterator itself reports it
    /// verbatim so tests can probe the rejection.
    pub operation: u8,
    pub to: [u8; 20],
    /// Native value forwarded with the record's call, uint256 BE.
    pub value: [u8; 32],
    pub data: &'a [u8],
}

impl MsRecord<'_> {
    #[must_use]
    pub fn value_is_zero(&self) -> bool {
        self.value.iter().all(|&b| b == 0)
    }
}

/// Iterator over the packed records slice returned by
/// [`decode_multisend`]. Yields `Err` once on the first malformed
/// record, then `None`. The cursor must land exactly on the slice end
/// — a partial trailing record is [`MsError::TruncatedRecord`].
pub struct MsRecordIter<'a> {
    packed: &'a [u8],
    cursor: usize,
    failed: bool,
}

impl<'a> MsRecordIter<'a> {
    #[must_use]
    pub fn new(packed: &'a [u8]) -> Self {
        Self {
            packed,
            cursor: 0,
            failed: false,
        }
    }
}

impl<'a> Iterator for MsRecordIter<'a> {
    type Item = Result<MsRecord<'a>, MsError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.cursor == self.packed.len() {
            return None;
        }
        let rest = &self.packed[self.cursor..];
        if rest.len() < MS_RECORD_HEADER_LEN {
            self.failed = true;
            return Some(Err(MsError::TruncatedRecord));
        }
        let operation = rest[0];
        let mut to = [0u8; 20];
        to.copy_from_slice(&rest[1..21]);
        let mut value = [0u8; 32];
        value.copy_from_slice(&rest[21..53]);
        let data_len = match read_u32_word(&rest[53..85]) {
            Ok(l) => l,
            Err(_) => {
                self.failed = true;
                return Some(Err(MsError::BadRecordDataLen));
            }
        };
        let data_end = match MS_RECORD_HEADER_LEN.checked_add(data_len) {
            Some(e) if e <= rest.len() => e,
            _ => {
                self.failed = true;
                return Some(Err(MsError::TruncatedRecord));
            }
        };
        let data = &rest[MS_RECORD_HEADER_LEN..data_end];
        self.cursor += data_end;
        Some(Ok(MsRecord {
            operation,
            to,
            value,
            data,
        }))
    }
}

// ---------------------------------------------------------------------------
// Per-record display classification + page accounting (layer 3)
// ---------------------------------------------------------------------------
//
// Extracted here, verbatim and behaviour-identical, so the page-budget
// gate the renderer relies on is host-compilable and Kani-bounded. Its
// whole dependency closure is pure / already in this crate:
// `safe_inner_is_cow_presign` (the pure CoW-presign predicate, below),
// `classify_safe_mgmt` + `page_count` (`crate::safe_mgmt`),
// `parse_erc20_calldata` + `Erc20Call` (`crate::erc20::calldata`), and the
// outer/inner decode above. The verified-context glue
// (`resolve_cow_binding`, `VerifiedSafe*`, the summary/verdict layer) stays
// in `secure/`. The firmware re-exports these from
// `secure/src/tx/eip712/safe/{cow_binding,multi_send}.rs` unchanged, so the
// renderer (`safe_display`) and the test suite keep working.

/// Does this Safe inner call claim to be a CoW `setPreSignature`?
///
/// Mirrors the direct-path downgrade-gate predicate in `cmd_sign_userop`
/// (`cow_selector && cow_target`): target must be the GPv2Settlement
/// singleton (same CREATE2 address on every chain CoW supports) and the
/// selector must match. Deliberately does NOT check the full 164-byte
/// shape — the gate must also fire for a malformed or `signed == false`
/// calldata so those refuse loudly instead of falling through to a
/// blind-sign page the user might habituate to confirming.
#[must_use]
pub fn safe_inner_is_cow_presign(inner_to: &[u8; 20], raw_data: &[u8]) -> bool {
    *inner_to == GPV2_SETTLEMENT_ADDRESS
        && raw_data.len() >= 4
        && raw_data[..4] == SET_PRE_SIGNATURE_SELECTOR
}

/// Display classification of one record — the per-record analogue of
/// the Safe renderer's `InnerKind` ladder, factored here (host-
/// testable) so the page-budget gate and the renderer derive page
/// counts from the SAME classification and physically cannot disagree.
#[derive(Copy, Clone, Debug)]
pub enum MsRecordKind {
    /// Empty calldata, zero value.
    EmptyCall,
    /// Empty calldata, non-zero value — plain ETH transfer.
    PlainEth,
    /// Strict ERC-20 transfer / transferFrom / approve shape. Renders
    /// "known" (symbol + decimals) only if verified metadata address-
    /// matches; page count is identical either way.
    Erc20(Erc20Call),
    /// Record targets the Safe itself with a recognised singleton op.
    SafeMgmt(SafeMgmtOp),
    /// Record targets the Safe itself with an unrecognised selector.
    UnknownSafeSelf,
    /// Claims `setPreSignature` on GPv2Settlement. Renders as the full
    /// CoW order (banner + shared body) for the unique bound record;
    /// the gates guarantee a verified cow_order exists by render time.
    CowPresignClaim,
    /// Anything else — loud per-record blind-sign (selector + length +
    /// data hash), same trust level as today's single blind inner.
    Blind,
}

/// Classify one record for display. Mirrors the single-call ladder in
/// `display::safe_display`: CoW claim first (disjoint target), then
/// Safe self-calls, then empty/ERC-20/blind.
#[must_use]
pub fn classify_record_kind(
    to: &[u8; 20],
    value_is_zero: bool,
    data: &[u8],
    safe_address: &[u8; 20],
) -> MsRecordKind {
    if safe_inner_is_cow_presign(to, data) {
        return MsRecordKind::CowPresignClaim;
    }
    if to == safe_address && !data.is_empty() {
        return match classify_safe_mgmt(data) {
            Some(op) => MsRecordKind::SafeMgmt(op),
            None => MsRecordKind::UnknownSafeSelf,
        };
    }
    if data.is_empty() {
        return if value_is_zero {
            MsRecordKind::EmptyCall
        } else {
            MsRecordKind::PlainEth
        };
    }
    match parse_erc20_calldata(data) {
        Some(call) => MsRecordKind::Erc20(call),
        None => MsRecordKind::Blind,
    }
}

/// Content pages for one classified record (excluding its divider page
/// and any spliced value page). `cow_body_pages` = 1 banner + the
/// shared native eight-page order body.
#[must_use]
pub fn record_content_pages(kind: &MsRecordKind, cow_body_pages: usize) -> usize {
    match kind {
        MsRecordKind::EmptyCall => 1,
        MsRecordKind::PlainEth => 2,
        // header + recipient + amount + contract; +1 for the transferFrom
        // `From (debited)` page (lockstep with
        // `safe_display::{append_erc20_tail_pages, inner_kind_page_count}`).
        MsRecordKind::Erc20(call) => 4 + usize::from(matches!(call, Erc20Call::TransferFrom { .. })),
        MsRecordKind::SafeMgmt(op) => mgmt_page_count(op),
        MsRecordKind::UnknownSafeSelf | MsRecordKind::Blind => 3,
        MsRecordKind::CowPresignClaim => cow_body_pages,
    }
}

/// Does this record need a dedicated "record sends ETH" page? PlainEth
/// shows its value inline; EmptyCall is zero-value by definition; every
/// other kind would otherwise sign a hidden per-record `value`.
#[must_use]
pub fn record_needs_value_page(kind: &MsRecordKind, value_is_zero: bool) -> bool {
    !value_is_zero && !matches!(kind, MsRecordKind::PlainEth | MsRecordKind::EmptyCall)
}

/// Total inner pages a decoded multiSend payload renders: per record,
/// 1 divider page + optional value page + content pages. `None` when
/// the payload doesn't decode (callers gate on `multisend_verdict`
/// first, so `None` here is defensive).
///
/// This is exact, not an upper bound: the renderer classifies through
/// the same [`classify_record_kind`] and counts through the same
/// [`record_content_pages`], so gate and render agree by construction.
#[must_use]
pub fn records_pages_total(
    data: &[u8],
    safe_address: &[u8; 20],
    cow_body_pages: usize,
) -> Option<usize> {
    let packed = decode_multisend(data).ok()?;
    let mut total = 0usize;
    for rec in MsRecordIter::new(packed) {
        let rec = rec.ok()?;
        let value_is_zero = rec.value_is_zero();
        let kind = classify_record_kind(&rec.to, value_is_zero, rec.data, safe_address);
        total += 1; // divider
        if record_needs_value_page(&kind, value_is_zero) {
            total += 1;
        }
        total += record_content_pages(&kind, cow_body_pages);
    }
    Some(total)
}

// ---------------------------------------------------------------------------
// Summary + acceptance verdict (the per-record `operation == 0` gate)
// ---------------------------------------------------------------------------

/// Shape facts about a fully-decoded multiSend payload. Produced only for a
/// payload that passed every hard rule in [`summarize_packed`].
#[derive(Copy, Clone, Debug)]
pub struct MsSummary {
    pub record_count: usize,
    /// Number of records claiming to be a CoW `setPreSignature` (target ==
    /// GPv2Settlement, selector match). Only `0` (generic batch) and `1` (CoW
    /// flow) are signable; `>= 2` is refused upstream.
    pub presign_claims: usize,
    /// Record index of the (last) presign claim. Meaningful only when
    /// `presign_claims == 1`.
    pub presign_idx: usize,
}

/// Validate the packed-records slice's hard rules and summarise it: strict
/// record framing (via [`MsRecordIter`]), **every record `operation == 0`**
/// (no nested DELEGATECALL), no `to == 0` record (MultiSendCallOnly v1.5.0
/// rewrites it to the Safe itself), `1..=MULTISEND_MAX_RECORDS` records, and a
/// count of CoW `setPreSignature` claims.
///
/// This is the per-record DELEGATECALL-refusal gate. [`summarize`] composes it
/// with [`decode_multisend`]. The in-loop check order — `operation != 0`
/// before `to == 0` **before** the record-count cap before the presign count — is behaviour (a
/// `> MULTISEND_MAX_RECORDS` batch whose first record is a DELEGATECALL still
/// refuses with `RecordOpNotCall`, not `BadRecordCount`); do not reorder.
///
/// Kani-bounded by `summarize_accept_implies_all_call` (≤ 2 records):
/// `summarize_packed(p).is_ok()` ⟹ every record's `operation == 0`.
pub fn summarize_packed(packed: &[u8]) -> Result<MsSummary, MsError> {
    let mut record_count = 0usize;
    let mut presign_claims = 0usize;
    let mut presign_idx = 0usize;
    for rec in MsRecordIter::new(packed) {
        let rec = rec?;
        if rec.operation != 0 {
            return Err(MsError::RecordOpNotCall);
        }
        if rec.to == [0u8; 20] {
            return Err(MsError::RecordToZero);
        }
        if record_count == MULTISEND_MAX_RECORDS {
            return Err(MsError::BadRecordCount);
        }
        if safe_inner_is_cow_presign(&rec.to, rec.data) {
            presign_claims += 1;
            presign_idx = record_count;
        }
        record_count += 1;
    }
    if record_count == 0 {
        return Err(MsError::BadRecordCount);
    }
    Ok(MsSummary {
        record_count,
        presign_claims,
        presign_idx,
    })
}

/// Decode + validate `multiSend(bytes)` calldata: strict outer framing
/// ([`decode_multisend`]) then [`summarize_packed`]. Every render/sign path
/// that walks records for display or CoW-binding gates on this returning `Ok`
/// first (`safe_display` multiSend arm at :421, `cow_binding` at :110; the
/// divider walk at safe_display :1335 is "unreachable post-gate"), so the
/// `operation == 0` refusal is mandatory — an `op != 0` record makes this
/// `Err(RecordOpNotCall)`, which downgrades the whole batch to a loud
/// blind-sign page.
pub fn summarize(data: &[u8]) -> Result<MsSummary, MsError> {
    let packed = decode_multisend(data)?;
    summarize_packed(packed)
}

// ---------------------------------------------------------------------------
// Bounded verification (Kani)
// ---------------------------------------------------------------------------

#[cfg(kani)]
mod verification {
    use super::*;

    /// Canonical-acceptance (soundness): `decode_multisend(s) == Ok(payload)`
    /// ⟹ `s` is **byte-for-byte** the unique canonical Solidity encoding of
    /// `payload`:
    ///
    /// ```text
    /// selector(4) ‖ offset_word(==0x20)(32) ‖ len_word(==payload.len())(32)
    ///            ‖ payload ‖ zero-pad to a 32-byte multiple
    /// ```
    ///
    /// with NOTHING trailing and EVERY pad byte zero. We reconstruct that
    /// canonical buffer purely from the input length, the returned `payload`,
    /// and the proto selector constant, then assert byte equality against the
    /// accepted input — so a green run forecloses, over ALL symbolic calldata
    /// ≤ `N`, any non-canonical input the decoder might admit (a different
    /// offset, an over/under-length word, non-zero padding, or a hidden
    /// trailing second payload).
    ///
    /// Bound: `N = 100` covers the empty-payload frame (`len == 0` → 68 B) and
    /// non-empty payloads up to 32 B (`len ∈ 1..=32` → 100 B), exercising both
    /// the pad-empty and pad-non-empty branches of the `ceil32` rounding and
    /// the zero-pad scan. The property is sound at this bound; a larger `N`
    /// only re-runs the same rounding at the next 32-byte boundary.
    #[kani::proof]
    #[kani::unwind(101)] // ≥ N+1: bounds the ≤N-byte canonical-equality compare
    fn decode_multisend_canonical_acceptance() {
        const N: usize = 100;
        let data: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let s = &data[..len];

        if let Ok(payload) = decode_multisend(s) {
            let plen = payload.len();
            // Exact total length = 68 + ceil32(payload.len()).
            let total = 68 + plen.next_multiple_of(32);
            assert_eq!(s.len(), total);

            // Reconstruct the unique canonical framing from (input length,
            // payload, selector) — never from the decoder's internals.
            let mut expected = [0u8; N];
            expected[0..4].copy_from_slice(&MULTI_SEND_SELECTOR);
            expected[35] = 0x20; // offset word == 0x20 (all higher bytes zero)
            expected[64..68].copy_from_slice(&(plen as u32).to_be_bytes()); // len word
            expected[68..68 + plen].copy_from_slice(payload);
            // expected[68+plen .. total] stays zero — the canonical pad.

            assert_eq!(&expected[..total], s);
        }
    }

    /// Non-vacuity (positive control): a concrete, hand-built canonical frame
    /// with a 2-byte payload is ACCEPTED and yields exactly that payload.
    /// Without this, the acceptance proof above could pass vacuously (a
    /// decoder that rejected everything would satisfy it trivially).
    #[kani::proof]
    #[kani::unwind(40)]
    fn decode_multisend_accepts_canonical() {
        // total = 68 + ceil32(2) = 100
        let mut buf = [0u8; 100];
        buf[0..4].copy_from_slice(&MULTI_SEND_SELECTOR);
        buf[35] = 0x20; // offset == 0x20
        buf[67] = 2; // length word == 2
        buf[68] = 0xaa;
        buf[69] = 0xbb;
        // buf[70..100] zero pad
        match decode_multisend(&buf) {
            Ok(payload) => {
                assert_eq!(payload.len(), 2);
                assert_eq!(payload[0], 0xaa);
                assert_eq!(payload[1], 0xbb);
            }
            Err(_) => panic!("a canonical multiSend frame must be accepted"),
        }
    }

    /// Non-vacuity (negative control A — the on-point one): a frame whose
    /// declared payload is empty but which carries a NON-ZERO byte in the
    /// 32-byte pad must be refused with `BadPadding`. This is exactly the
    /// "hidden second payload riding in the padding" threat the
    /// canonical-acceptance property exists to foreclose.
    #[kani::proof]
    #[kani::unwind(40)]
    fn decode_multisend_rejects_nonzero_pad() {
        // Canonical empty-payload frame is 68 B; declare len = 1 so the
        // payload occupies one byte and the remaining 31 pad bytes must be
        // zero. Put a non-zero byte in the pad.
        let mut buf = [0u8; 100];
        buf[0..4].copy_from_slice(&MULTI_SEND_SELECTOR);
        buf[35] = 0x20; // offset == 0x20
        buf[67] = 1; // length word == 1
        buf[68] = 0x11; // the one payload byte
        buf[99] = 0xff; // non-zero PAD byte → must be refused
        assert_eq!(decode_multisend(&buf), Err(MsError::BadPadding));
    }

    /// Non-vacuity (negative control B): a canonical empty-payload frame
    /// (68 B) with one extra trailing byte must be refused with `BadPadding`
    /// (exact-length branch — nothing may follow the padded tail).
    #[kani::proof]
    #[kani::unwind(40)]
    fn decode_multisend_rejects_trailing_byte() {
        let mut buf = [0u8; 69];
        buf[0..4].copy_from_slice(&MULTI_SEND_SELECTOR);
        buf[35] = 0x20; // offset == 0x20, length word == 0 (empty payload)
        // one extra byte at [68] beyond the 68-byte canonical empty frame
        assert_eq!(decode_multisend(&buf), Err(MsError::BadPadding));
    }

    // -----------------------------------------------------------------------
    // Inner packed-record walk (`MsRecordIter`) — the layer the
    // canonical-acceptance proof above structurally cannot reach (the packed
    // encoding mirrors MultiSendCallOnly's hand-rolled assembly, not standard
    // ABI). Slice 3 sampled it differentially against the real deployed
    // bytecode in revm; these harnesses prove it as theorems over symbolic
    // payloads: the records exactly partition the payload (no hidden trailing
    // record/data the device never renders) and every displayed field is the
    // verbatim payload bytes.
    // -----------------------------------------------------------------------

    /// Exact tiling / partition soundness: if the walk over a symbolic packed
    /// slice yields a sequence of records that are all `Ok` and then `None`
    /// (never an `Err`), the records consume **every** payload byte —
    /// `Σ (MS_RECORD_HEADER_LEN + rec.data.len()) == packed.len()`, with
    /// nothing trailing and nothing overlapping.
    ///
    /// We track an independent record-start offset `off` and, on each accepted
    /// record, re-read the declared `dataLen` straight from the header bytes at
    /// `off` (`assert_eq!(rec.data.len(), dl)`). Over ALL symbolic input this
    /// forces the iterator's cursor to equal `off` (a divergent cursor would
    /// read a different `dataLen` word for some input), so `off += 85 + dl`
    /// provably tracks the cursor and the closing `off == len` is the real
    /// no-hidden-trailing-bytes statement — scalar-only, no pointer arithmetic.
    ///
    /// Bound: `N = 180` admits ≤ 2 records (`2 * 85 = 170 ≤ 180 < 255`). The
    /// per-record step is uniform, so two records exercise the cross-record
    /// induction; the `> MULTISEND_MAX_RECORDS` cap lives in `summarize`, not
    /// the iterator, and is out of scope here.
    #[kani::proof]
    #[kani::unwind(40)]
    fn record_walk_exact_tiling() {
        const N: usize = 180;
        let packed: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let p = &packed[..len];

        let mut iter = MsRecordIter::new(p);
        let mut off = 0usize;
        let mut all_ok = true;
        // ≤ 2 accepted records fit in N; +2 polls of headroom for the
        // terminating None/Err (a too-small loop would only ever make the
        // closing assert FAIL on a partial walk, never pass spuriously).
        for _ in 0..4 {
            match iter.next() {
                Some(Ok(rec)) => {
                    // A record is only yielded with its full header in-bounds
                    // at the cursor; pin `off` to it by matching the declared
                    // dataLen read directly from the header bytes at `off`.
                    assert!(off + MS_RECORD_HEADER_LEN <= p.len());
                    let dl = u32::from_be_bytes([
                        p[off + 81],
                        p[off + 82],
                        p[off + 83],
                        p[off + 84],
                    ]) as usize;
                    assert_eq!(rec.data.len(), dl);
                    off += MS_RECORD_HEADER_LEN + dl;
                    assert!(off <= p.len());
                }
                Some(Err(_)) => {
                    all_ok = false;
                    break;
                }
                None => break,
            }
        }
        if all_ok {
            // No hidden trailing record/data: an all-`Ok` walk consumes every
            // payload byte (the iterator returns `None` only at cursor == len,
            // and cursor == off was pinned per record above).
            assert_eq!(off, p.len());
        }
    }

    /// Field fidelity (soundness): every field the trusted UI would render from
    /// an accepted record — `operation`, `to`, `value`, and the `data` slice —
    /// is the **verbatim** payload bytes at the record's position, not a
    /// misaligned or corrupted copy. The declared `dataLen` is re-read
    /// independently from the header word so the `data` compare is anchored to
    /// the header position, not to the iterator's own length.
    ///
    /// Bound: `N = 120` (one record: 85-byte header + ≤ 35 data) at offset 0.
    /// The per-record field logic reads relative to the cursor, so offset 0 is
    /// representative; the concrete two-record control below pins a record at a
    /// non-zero offset, and `record_walk_exact_tiling` pins the cross-record
    /// offset advance.
    #[kani::proof]
    #[kani::unwind(121)]
    fn record_walk_field_fidelity() {
        const N: usize = 120;
        let packed: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let p = &packed[..len];

        let mut iter = MsRecordIter::new(p);
        if let Some(Ok(rec)) = iter.next() {
            // The first record sits at offset 0.
            assert_eq!(rec.operation, p[0]);
            let mut i = 0usize;
            while i < 20 {
                assert_eq!(rec.to[i], p[1 + i]);
                i += 1;
            }
            let mut j = 0usize;
            while j < 32 {
                assert_eq!(rec.value[j], p[21 + j]);
                j += 1;
            }
            let dl = u32::from_be_bytes([p[81], p[82], p[83], p[84]]) as usize;
            assert_eq!(rec.data.len(), dl);
            let mut k = 0usize;
            while k < dl {
                assert_eq!(rec.data[k], p[MS_RECORD_HEADER_LEN + k]);
                k += 1;
            }
        }
    }

    /// Non-vacuity (positive control): a concrete two-record payload — record A
    /// (`to = 0x11..`, `data = aa bb` → 87 B) then record B (`to = 0x22..`,
    /// empty data → 85 B), total 172 B with no trailing — is walked to exactly
    /// two records with the expected fields and then `None`. This also pins a
    /// record (B) at a non-zero offset (87), covering cross-boundary field
    /// reads the symbolic offset-0 harness cannot.
    #[kani::proof]
    #[kani::unwind(40)]
    fn record_walk_accepts_two_records() {
        let mut packed = [0u8; 172];
        // Record A header at 0: op 0, to = 0x11.., value 0, dataLen 2.
        let mut i = 1usize;
        while i < 21 {
            packed[i] = 0x11;
            i += 1;
        }
        packed[84] = 2; // dataLen word low byte
        packed[85] = 0xaa;
        packed[86] = 0xbb;
        // Record B header at 87: op 0, to = 0x22.., value 0, dataLen 0.
        let mut j = 88usize;
        while j < 108 {
            packed[j] = 0x22;
            j += 1;
        }

        let mut iter = MsRecordIter::new(&packed);
        match iter.next() {
            Some(Ok(r)) => {
                assert_eq!(r.operation, 0);
                assert_eq!(r.to, [0x11u8; 20]);
                assert!(r.value_is_zero());
                assert_eq!(r.data.len(), 2);
                assert_eq!(r.data[0], 0xaa);
                assert_eq!(r.data[1], 0xbb);
            }
            _ => panic!("record A must decode Ok"),
        }
        match iter.next() {
            Some(Ok(r)) => {
                assert_eq!(r.to, [0x22u8; 20]);
                assert_eq!(r.data.len(), 0);
            }
            _ => panic!("record B must decode Ok"),
        }
        // Exact tiling: nothing left after the two records.
        assert!(iter.next().is_none());
    }

    /// Non-vacuity (on-point negative control): one full 85-byte record
    /// followed by 10 trailing bytes — too few for another header — must be
    /// surfaced as `Err(TruncatedRecord)`, NOT silently dropped via `None`.
    /// This is exactly the "hidden trailing bytes the device never renders"
    /// threat that `record_walk_exact_tiling` forecloses.
    #[kani::proof]
    #[kani::unwind(40)]
    fn record_walk_rejects_trailing_partial() {
        let packed = [0u8; 95]; // 85-byte header (op 0, dataLen 0) + 10 trailing
        let mut iter = MsRecordIter::new(&packed);
        assert!(matches!(iter.next(), Some(Ok(_))));
        assert!(matches!(
            iter.next(),
            Some(Err(MsError::TruncatedRecord))
        ));
    }

    /// Non-vacuity (negative control): a lone header declaring `dataLen = 1`
    /// with no byte to back it must be refused (`TruncatedRecord`) rather than
    /// fabricating an out-of-bounds `data` slice.
    #[kani::proof]
    #[kani::unwind(40)]
    fn record_walk_rejects_data_overrun() {
        let mut packed = [0u8; 85];
        packed[84] = 1; // dataLen = 1, but the slice ends at the header
        let mut iter = MsRecordIter::new(&packed);
        assert!(matches!(
            iter.next(),
            Some(Err(MsError::TruncatedRecord))
        ));
    }

    // -----------------------------------------------------------------------
    // Per-record display classification + page accounting (layer 3) — the
    // page-budget gate `safe_display` relies on to refuse (never truncate) a
    // batch whose render would exceed MAX_PAGES. Kani proves the GATE's
    // accounting at the per-record granularity: a per-record page BOUND, the
    // no-hidden-value WYSIWYS soundness, and the CoW-first classification
    // precedence. Two scope notes:
    //
    //  * Gate == renderer equality is NOT Kani-proven — it rests on
    //    by-construction (gate and renderer call these same extracted fns) +
    //    the `safe_display`/`multi_send` host tests (`pages_total_*`); the
    //    renderer is `#[cfg(not(test))]`, out of Kani's reach.
    //  * `records_pages_total` is NOT given its own end-to-end harness (CBMC
    //    unwinds its whole decode+classify call graph, which doesn't converge
    //    affordably). Its panic/overflow/OOB-freedom is established
    //    COMPOSITIONALLY from its already-proven parts: `decode_multisend` over
    //    symbolic framing (`decode_multisend_canonical_acceptance`, slice 1),
    //    the inner walk (slice 9), `classify_record_kind` panic-freedom over
    //    symbolic records (`per_record_page_bound` / `no_hidden_value` below,
    //    `[u8; 100]` data covering every branch), and the per-record page bound
    //    (`per_record_page_bound`). The multi-record `total += ..` accumulation
    //    cannot `usize`-overflow, INDEPENDENT of the verdict count cap: the
    //    bound is payload-length-derived. (`records_pages_total` has TWO
    //    callers — `safe_display.rs:424` in the renderer, where the record
    //    count is applied via the `count > 0` guard *after* this call, and
    //    `safe_display.rs:873` in the multiSend sign-gate, where the
    //    `≤ MULTISEND_MAX_RECORDS` verdict runs *before* it; overflow-freedom
    //    holds at both sites regardless of ordering.) Not the verdict count —
    //    each record is ≥ 85 B, so a bounded multiSend payload holds only tens
    //    of records, each contributing ≤ `cow_body.max(5) + 2`; the
    //    `safe_display` caller then refuses any total `> MAX_PAGES`. The
    //    concrete end-to-end counts stay covered by the `pages_total_*` host
    //    tests.
    // -----------------------------------------------------------------------

    /// P1 — a single record never contributes more than `cow_body_pages.max(5)
    /// + 2` pages (1 divider + ≤ 1 value page + ≤ `max(5, cow_body)` content;
    /// the SafeMgmt arm's `page_count ≤ 3 ≤ 5` is discharged inside). This
    /// bounds ONE record; the multi-record sum's overflow-freedom rests on the
    /// bounded multiSend payload (each record ≥ 85 B → only tens of records),
    /// NOT on this per-record proof — see the module note above. A crafted
    /// record still can't inflate its own page count past the bound.
    #[cfg(feature = "kani-heavy")]
    #[kani::proof]
    #[kani::unwind(101)]
    fn per_record_page_bound() {
        const M: usize = 100;
        let to: [u8; 20] = kani::any();
        let safe_address: [u8; 20] = kani::any();
        let data: [u8; M] = kani::any();
        let dlen: usize = kani::any();
        kani::assume(dlen <= M);
        let value_is_zero: bool = kani::any();
        let cow_body_pages: usize = kani::any();
        kani::assume(cow_body_pages <= 9);

        let kind = classify_record_kind(&to, value_is_zero, &data[..dlen], &safe_address);
        let content = record_content_pages(&kind, cow_body_pages);
        assert!(content <= cow_body_pages.max(5));
        let per_record =
            1 + usize::from(record_needs_value_page(&kind, value_is_zero)) + content;
        assert!(per_record <= cow_body_pages.max(5) + 2);
    }

    /// P2 (load-bearing) — no hidden per-record value (WYSIWYS). A record
    /// carrying non-zero native `value` either gets a dedicated "sends ETH"
    /// page or classifies as `PlainEth` (which renders the value inline on its
    /// content pages); the value is NEVER silently dropped. `value_is_zero` is
    /// DERIVED from a symbolic 32-byte value exactly as `records_pages_total`
    /// derives it from `rec.value_is_zero()`, so the impossible
    /// `(EmptyCall, value≠0)` state — which `classify` never emits — cannot be
    /// spuriously constructed.
    #[cfg(feature = "kani-heavy")]
    #[kani::proof]
    #[kani::unwind(101)]
    fn no_hidden_value() {
        const M: usize = 100;
        let to: [u8; 20] = kani::any();
        let safe_address: [u8; 20] = kani::any();
        let data: [u8; M] = kani::any();
        let dlen: usize = kani::any();
        kani::assume(dlen <= M);
        let value: [u8; 32] = kani::any();
        let value_is_zero = value.iter().all(|&b| b == 0);

        let kind = classify_record_kind(&to, value_is_zero, &data[..dlen], &safe_address);
        if !value_is_zero {
            assert!(
                record_needs_value_page(&kind, value_is_zero)
                    || matches!(kind, MsRecordKind::PlainEth)
            );
        }
    }

    /// P3 — classification precedence: a record that is a CoW `setPreSignature`
    /// claim classifies as `CowPresignClaim` even in the conflicting case where
    /// it ALSO targets the Safe itself (`to == safe_address`). The CoW arm is
    /// checked first, so such a record renders as the full CoW order, never as
    /// a Safe-mgmt / unknown-self blob.
    /// HIGH-MEMORY — excluded from the default `make kani` run.
    ///
    /// Measured 2026-07-31 on this exact harness: **VERIFICATION SUCCESSFUL**,
    /// 3m56s wall, **peak RSS 11.5 GiB**. It is not broken and it is not
    /// weakened here; it simply does not fit a 16 GB hosted runner that is also
    /// holding the build tree, so it OOM-killed the nightly Kani job (the job
    /// died mid-solve at 8.5M program-expression steps / 119,654 VCCs with
    /// "The runner has received a shutdown signal", which reads as
    /// infrastructure noise rather than as a memory limit).
    ///
    /// Same precedent as `verify-extracted-heavy` (53c19f21): a step that can
    /// terminate the runner is worse than a step that is absent, because the
    /// kill also suppresses every later mandatory gate in the same job. Not
    /// even `continue-on-error` helps.
    ///
    /// Run it with `make kani-heavy` (locally, or on a >=32 GB runner). The
    /// 100-byte symbolic bound is deliberately NOT reduced to fit CI — shrinking
    /// a proof's bound to satisfy a runner is a real loss of coverage disguised
    /// as a green check.
    #[cfg(feature = "kani-heavy")]
    #[kani::proof]
    #[kani::unwind(101)]
    fn cow_presign_precedence() {
        const M: usize = 100;
        let data: [u8; M] = kani::any();
        let dlen: usize = kani::any();
        kani::assume(dlen <= M);
        let to: [u8; 20] = kani::any();
        let value_is_zero: bool = kani::any();
        kani::assume(safe_inner_is_cow_presign(&to, &data[..dlen]));
        // The conflict: the record both is a CoW presign claim AND targets the
        // Safe itself.
        let safe_address = to;
        assert!(matches!(
            classify_record_kind(&to, value_is_zero, &data[..dlen], &safe_address),
            MsRecordKind::CowPresignClaim
        ));
    }

    /// Non-vacuity (positive control): the classification arms the soundness
    /// harnesses constrain are reachable — a CoW presign record classifies as
    /// `CowPresignClaim` (content = `cow_body_pages`), and a non-zero-value
    /// opaque record is `Blind` and requires a value page.
    #[kani::proof]
    #[kani::unwind(40)]
    fn classify_concrete_controls() {
        let mut presign = [0u8; 4];
        presign.copy_from_slice(&SET_PRE_SIGNATURE_SELECTOR);
        let cow_kind = classify_record_kind(&GPV2_SETTLEMENT_ADDRESS, true, &presign, &[0x5a; 20]);
        assert!(matches!(cow_kind, MsRecordKind::CowPresignClaim));
        assert_eq!(record_content_pages(&cow_kind, 9), 9);

        let blind = [0xde, 0xad, 0xbe, 0xef];
        let blind_kind = classify_record_kind(&[0x11; 20], false, &blind, &[0x5a; 20]);
        assert!(matches!(blind_kind, MsRecordKind::Blind));
        assert!(record_needs_value_page(&blind_kind, false));
    }

    /// **DELEGATECALL-refusal soundness (finding 3b-1).** The per-record
    /// `operation == 0` gate in [`summarize_packed`] is the one keeping a nested
    /// DELEGATECALL out of a clear-signed batch. This proves the security
    /// direction over a symbolic packed payload: **acceptance implies no
    /// DELEGATECALL** — `summarize_packed(p).is_ok()` ⟹ every record the walk
    /// yields has `operation == 0`. The re-walk of `MsRecordIter` (itself proven
    /// exact-tiling / field-fidelity above) is an INDEPENDENT oracle: it never
    /// consults `summarize_packed`'s rejection logic, so deleting the
    /// `operation != 0` check makes an `op != 0` record accept here and this
    /// assertion FAIL (`kani_mutations.json: multisend_op0_delegatecall`).
    ///
    /// Bound: `N = 180` admits ≤ 2 records (the same D1 bound as
    /// `record_walk_exact_tiling`) — BOUNDED-∀, not full-∀. The per-record op
    /// check is uniform, so ≤ 2 records exercise it; the `> MULTISEND_MAX_RECORDS`
    /// count cap is a separate (`BadRecordCount`) gate, not under test here.
    #[kani::proof]
    #[kani::unwind(40)]
    fn summarize_accept_implies_all_call() {
        const N: usize = 180;
        let packed: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let p = &packed[..len];

        if summarize_packed(p).is_ok() {
            // Independent re-walk: every accepted record is a CALL (op == 0)
            // to a non-zero `to` (MultiSendCallOnly v1.5.0 rewrites `to == 0`
            // to the Safe itself, so it must never reach the renderer).
            let mut iter = MsRecordIter::new(p);
            for _ in 0..4 {
                match iter.next() {
                    Some(Ok(rec)) => {
                        assert_eq!(rec.operation, 0);
                        assert!(rec.to != [0u8; 20]);
                    }
                    _ => break,
                }
            }
        }
    }

    /// Non-vacuity (negative control): a concrete two-record payload whose
    /// SECOND record declares `operation = 1` (DELEGATECALL) is refused with
    /// `RecordOpNotCall`. The accept branch of the symbolic harness above is
    /// therefore reachable-but-excluded for an `op != 0` record — the
    /// implication is not vacuously true.
    #[kani::proof]
    #[kani::unwind(40)]
    fn summarize_rejects_delegatecall_record() {
        // Record A at 0: op 0, to = 0x11.., empty data (85 B). Record B at 85:
        // op 1 (DELEGATECALL), to = 0x22.., empty data (85 B). Total 170 B.
        let mut packed = [0u8; 170];
        let mut i = 1usize;
        while i < 21 {
            packed[i] = 0x11;
            i += 1;
        }
        packed[85] = 1; // record B operation byte = DELEGATECALL
        let mut j = 86usize;
        while j < 106 {
            packed[j] = 0x22;
            j += 1;
        }
        assert!(matches!(
            summarize_packed(&packed),
            Err(MsError::RecordOpNotCall)
        ));
    }

    /// Non-vacuity (positive control): a concrete two-record all-CALL payload is
    /// accepted (`Ok`) with `record_count == 2` — the accept branch is reachable.
    #[kani::proof]
    #[kani::unwind(40)]
    fn summarize_accepts_two_call_records() {
        // Two op-0 records, 85 B each (empty data), total 170 B.
        let mut packed = [0u8; 170];
        let mut i = 1usize;
        while i < 21 {
            packed[i] = 0x11;
            i += 1;
        }
        let mut j = 86usize;
        while j < 106 {
            packed[j] = 0x22;
            j += 1;
        }
        let s = summarize_packed(&packed).expect("two call records accepted");
        assert_eq!(s.record_count, 2);
    }
}

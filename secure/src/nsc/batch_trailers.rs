//! TLV-tagged trailer parser for `CMD_SIGN_USEROP_BATCH` wire v2.
//!
//! ## Wire format
//!
//! After the existing batch header + N × inner-tx blocks, the payload
//! terminates in a TLV-tagged trailer list:
//!
//! ```text
//!   [ u8 trailer_count ]            (0..=MAX_TRAILERS_PER_BATCH)
//!   [ trailer_count × {
//!       u8  kind                    (1..=8, see proto::TRAILER_KIND_*)
//!       u8  tx_idx                  (0..batch_count-1 for kinds 1..=7;
//!                                    TRAILER_TX_IDX_BATCH_WIDE for kind 8)
//!       u16 BE len                  (per-kind cap, see MAX_LEN_PER_KIND)
//!       [len bytes]                 trailer payload
//!   } ]
//! ```
//!
//! ## What this module does
//!
//! [`parse_all`] walks the trailer block, validates every parse-time
//! invariant (kind enum, `tx_idx` range, per-kind length cap, duplicate
//! suppression, mutual exclusion of curated/self-attest, total-bytes
//! budget, snapshot bounds), and records each trailer's
//! `(kind, tx_idx, start, len)` into a fixed-size array. It does not
//! invoke any verifier — Phase 3 of the handler walks the parsed
//! records and dispatches per-kind verifiers in the appropriate
//! FI-hardened envelope.
//!
//! ## Hardening
//!
//! * `trailer_count` is double-read with a `wait_random` jitter and
//!   sentinel-compared, so a single-fault glitch on the count byte
//!   can't open the iteration window past the array.
//! * `kind` and `tx_idx` are double-validated: once on first read,
//!   and again after recording into the descriptor array, so a fault
//!   that flips the routing fields between parse and record lands on
//!   a sentinel mismatch.
//! * Dispatch on `kind` uses an exhaustive `match` with `_ =>` reject,
//!   not an `if/else` ladder — Rust lowers this to a jump table that's
//!   harder to glitch into a "fall through to no-op" path.
//! * Refusals route through `crate::ui::show_status` then return
//!   `NscStatus::InvalidPointer` — same shape as every other
//!   parse-time refusal in the gateway.

use sphincs_tz_shared::{
    NscStatus, MAX_BATCH_TXS, MAX_TRAILERS_PER_BATCH, SAFE_V1_PAYLOAD_MAX,
    SIGN_USEROP_BATCH_TRAILER_HEADER_LEN, TRAILERS_TOTAL_MAX_LEN, TRAILER_KIND_ERC20,
    TRAILER_KIND_ERC7730, TRAILER_KIND_NAME, TRAILER_KIND_SAFE_V1, TRAILER_KIND_SEL_CURATED,
    TRAILER_KIND_SEL_SELFATTEST, TRAILER_KIND_ZK_V1, TRAILER_KIND_ZK_V3,
    TRAILER_TX_IDX_BATCH_WIDE, ZK_CLEAR_SIGN_FIXED_LEN, ZK_V3_FIXED_LEN, ZK_VK_BUNDLE_MAX_LEN,
    ERC7730_MAX_TRAILER_LEN,
};

use crate::erc20::bundle::MAX_ERC20_BUNDLE_LEN;
use crate::names::{MAX_NAME_BUNDLES, MAX_NAME_BUNDLE_LEN};
use crate::selectors::{MAX_SELECTOR_BUNDLE_LEN, MAX_SELF_ATTEST_BUNDLE_LEN};
use crate::ui;

/// Per-kind max payload length, indexed by kind (kind 0 unused; sentinel `0`).
///
/// Quoting these as a flat table makes the dispatch in [`parse_all`] a
/// single bounded array index after `kind ∈ 1..=8` is validated, and
/// keeps the per-kind caps in one auditable place. All values come from
/// the relevant verifier crate's own `MAX_*_LEN` constant, so the table
/// drifts only if the verifier-side cap drifts.
pub const MAX_LEN_PER_KIND: [usize; 9] = [
    0,                                              // 0 — unused
    MAX_ERC20_BUNDLE_LEN,                           // 1 — ERC-20 metadata
    ZK_CLEAR_SIGN_FIXED_LEN + ZK_VK_BUNDLE_MAX_LEN, // 2 — ZK v1
    ZK_V3_FIXED_LEN + ZK_VK_BUNDLE_MAX_LEN,         // 3 — ZK v3 CoW
    SAFE_V1_PAYLOAD_MAX,                            // 4 — Safe v1
    MAX_SELECTOR_BUNDLE_LEN,                        // 5 — selector curated
    MAX_SELF_ATTEST_BUNDLE_LEN,                     // 6 — selector self-attest
    ERC7730_MAX_TRAILER_LEN,                        // 7 — ERC-7730 descriptor
    MAX_NAME_BUNDLE_LEN,                            // 8 — address-name bundle
];

/// Highest valid kind value (inclusive). Anchors the dispatch match.
pub const MAX_TRAILER_KIND: u8 = 8;

/// One parsed trailer descriptor: kind/route + slice coordinates into
/// the secure-side snapshot buffer. The verifier dispatch (Phase 3)
/// re-slices `snap[start..start+len]` per record.
#[derive(Clone, Copy, Debug)]
pub struct ParsedTrailer {
    pub kind: u8,
    pub tx_idx: u8,
    pub start: usize,
    pub len: usize,
}

/// Collected output of [`parse_all`]. `records[..count]` is populated;
/// the remainder are `None`. `next_cursor` is `total_len` on success
/// (the parser refuses any payload that has bytes past the last trailer).
pub struct ParsedTrailers {
    pub records: [Option<ParsedTrailer>; MAX_TRAILERS_PER_BATCH],
    pub count: usize,
    pub next_cursor: usize,
}

impl ParsedTrailers {
    /// Empty collection — no records, cursor at the seed value. Used
    /// when the trailer-list byte is `0` (companion sent no trailers).
    pub const fn empty(cursor: usize) -> Self {
        Self {
            records: [None; MAX_TRAILERS_PER_BATCH],
            count: 0,
            next_cursor: cursor,
        }
    }

    /// Iterate trailers of a specific kind. The handler uses this to
    /// dispatch per-kind verifiers (e.g., walk every kind-1 record and
    /// hand each to `verify_erc20_bundle`).
    pub fn iter_kind(&self, kind: u8) -> impl Iterator<Item = &ParsedTrailer> {
        self.records
            .iter()
            .filter_map(|r| r.as_ref())
            .filter(move |r| r.kind == kind)
    }
}

/// Compile-time sanity: the worst-case record count
/// (`MAX_BATCH_TXS × 6 + MAX_NAME_BUNDLES`) must fit inside
/// `MAX_TRAILERS_PER_BATCH`. Six per-tx kinds because selector-curated
/// and selector-self-attest are mutually exclusive per tx.
const _: () = assert!(MAX_TRAILERS_PER_BATCH >= MAX_BATCH_TXS * 6 + MAX_NAME_BUNDLES);

/// Parse the TLV-tagged trailer list starting at `cursor`.
///
/// Contract:
/// * `snap` is the TOCTOU-snapshotted batch payload.
/// * `cursor` points at the `trailer_count` byte.
/// * `total_len` is the length of valid bytes in `snap` (NS-supplied,
///   already bounds-checked).
/// * `batch_count` is the validated inner-tx count from the header
///   (1..=MAX_BATCH_TXS).
///
/// Returns the populated [`ParsedTrailers`] on success. Every refusal
/// shows a `"Batch sign"` status on the trusted UI and returns
/// `Err(NscStatus::InvalidPointer as u32)`.
pub fn parse_all(
    snap: &[u8],
    cursor: usize,
    total_len: usize,
    batch_count: usize,
) -> Result<ParsedTrailers, u32> {
    // ── 1. Trailer count + FI double-read ────────────────────────────
    //
    // `trailer_count == 0` is the legal "no trailers" wire encoding;
    // we still verify the cursor consumed exactly one byte. Refusing
    // an absent count byte at all means the companion must always
    // emit at least the `[0x00]` terminator.
    if cursor + 1 > total_len {
        ui::show_status("Batch sign", "trailer hdr trunc");
        return Err(NscStatus::InvalidPointer as u32);
    }
    let count_a = snap[cursor];
    crate::fi::wait_random();
    let count_b = snap[cursor];
    if crate::fi::check_true_into_sentinel(|| core::hint::black_box(count_a == count_b))
        != crate::fi::OK_SENTINEL
    {
        ui::show_status("Batch sign", "count glitch");
        return Err(NscStatus::InvalidPointer as u32);
    }
    let trailer_count = count_a as usize;
    if trailer_count > MAX_TRAILERS_PER_BATCH {
        ui::show_status("Batch sign", "trailer_count >cap");
        return Err(NscStatus::InvalidPointer as u32);
    }
    let mut walk = cursor + 1;

    // ── 2. Record array + bookkeeping ───────────────────────────────
    //
    // `seen_per_tx[i]` carries a kind bitmask for per-tx records on
    // inner-tx `i` (bits 0..7 ≡ kinds 1..8). Kind 8 is batch-wide and
    // uses `seen_batch_wide_names_count` for its own cap check.
    let mut records: [Option<ParsedTrailer>; MAX_TRAILERS_PER_BATCH] =
        [None; MAX_TRAILERS_PER_BATCH];
    let mut seen_per_tx: [u8; MAX_BATCH_TXS] = [0u8; MAX_BATCH_TXS];
    let mut seen_batch_wide_names_count: usize = 0;
    let mut total_payload_bytes: usize = 0;

    // ── 3. Parse loop ───────────────────────────────────────────────
    for slot in 0..trailer_count {
        // 3a. Record header: kind(1) + tx_idx(1) + len(u16 BE) = 4 B.
        if walk + SIGN_USEROP_BATCH_TRAILER_HEADER_LEN > total_len {
            ui::show_status("Batch sign", "rec hdr trunc");
            return Err(NscStatus::InvalidPointer as u32);
        }
        let kind = snap[walk];
        let tx_idx = snap[walk + 1];
        let len = u16::from_be_bytes([snap[walk + 2], snap[walk + 3]]) as usize;

        // 3b. Kind enum check.
        if kind == 0 || kind > MAX_TRAILER_KIND {
            ui::show_status("Batch sign", "bad trailer kind");
            return Err(NscStatus::InvalidPointer as u32);
        }

        // 3c. tx_idx range.
        //
        // Kinds 1..=7 are per-tx; kind 8 (names) is batch-wide. An
        // attacker-supplied mis-routed `tx_idx` falls into the "no
        // matching tx" bucket and would be silently ignored at render
        // time, so refuse here instead.
        if kind == TRAILER_KIND_NAME {
            if tx_idx != TRAILER_TX_IDX_BATCH_WIDE {
                ui::show_status("Batch sign", "name not bw");
                return Err(NscStatus::InvalidPointer as u32);
            }
        } else if (tx_idx as usize) >= batch_count {
            ui::show_status("Batch sign", "tx_idx oor");
            return Err(NscStatus::InvalidPointer as u32);
        }

        // 3d. Per-kind length cap (constant-table dispatch).
        let kind_cap = MAX_LEN_PER_KIND[kind as usize];
        if len > kind_cap {
            ui::show_status("Batch sign", "trailer len>cap");
            return Err(NscStatus::InvalidPointer as u32);
        }

        // 3e. Snapshot bounds for the payload.
        let payload_start = walk + SIGN_USEROP_BATCH_TRAILER_HEADER_LEN;
        if payload_start + len > total_len {
            ui::show_status("Batch sign", "rec payload trunc");
            return Err(NscStatus::InvalidPointer as u32);
        }

        // 3f. Outer budget cap on aggregate payload bytes.
        total_payload_bytes = match total_payload_bytes.checked_add(len) {
            Some(s) => s,
            None => {
                ui::show_status("Batch sign", "len sum ovf");
                return Err(NscStatus::InvalidPointer as u32);
            }
        };
        if total_payload_bytes > TRAILERS_TOTAL_MAX_LEN {
            ui::show_status("Batch sign", "trailers >budget");
            return Err(NscStatus::InvalidPointer as u32);
        }

        // 3g. Duplicate / mutual-exclusion check.
        //
        // Per-tx kinds 1..=7: at most one record per (kind, tx_idx).
        // Selector curated XOR self-attest per tx — refuse if both
        // appear on the same tx_idx. Batch-wide names: capped at
        // MAX_NAME_BUNDLES total.
        if kind == TRAILER_KIND_NAME {
            seen_batch_wide_names_count += 1;
            if seen_batch_wide_names_count > MAX_NAME_BUNDLES {
                ui::show_status("Batch sign", "names >cap");
                return Err(NscStatus::InvalidPointer as u32);
            }
        } else {
            let row = tx_idx as usize;
            let bit = 1u8 << (kind - 1);
            if seen_per_tx[row] & bit != 0 {
                ui::show_status("Batch sign", "dup trailer");
                return Err(NscStatus::InvalidPointer as u32);
            }
            // Mutual exclusion between curated and self-attest selectors.
            if kind == TRAILER_KIND_SEL_CURATED
                && seen_per_tx[row] & (1u8 << (TRAILER_KIND_SEL_SELFATTEST - 1)) != 0
            {
                ui::show_status("Batch sign", "cur+self mxe");
                return Err(NscStatus::InvalidPointer as u32);
            }
            if kind == TRAILER_KIND_SEL_SELFATTEST
                && seen_per_tx[row] & (1u8 << (TRAILER_KIND_SEL_CURATED - 1)) != 0
            {
                ui::show_status("Batch sign", "cur+self mxe");
                return Err(NscStatus::InvalidPointer as u32);
            }
            seen_per_tx[row] |= bit;
        }

        // 3h. Route — exhaustive match so a glitched kind value can't
        // fall through to a no-op path. The match is over the kind we
        // already validated; the body just guarantees we cover every
        // case before recording.
        match kind {
            TRAILER_KIND_ERC20
            | TRAILER_KIND_ZK_V1
            | TRAILER_KIND_ZK_V3
            | TRAILER_KIND_SAFE_V1
            | TRAILER_KIND_SEL_CURATED
            | TRAILER_KIND_SEL_SELFATTEST
            | TRAILER_KIND_ERC7730
            | TRAILER_KIND_NAME => {
                records[slot] = Some(ParsedTrailer {
                    kind,
                    tx_idx,
                    start: payload_start,
                    len,
                });
            }
            _ => {
                // Unreachable post-step-3b; defence in depth.
                ui::show_status("Batch sign", "kind dispatch");
                return Err(NscStatus::InvalidPointer as u32);
            }
        }

        // 3i. Re-read (kind, tx_idx) from the snapshot and sentinel-
        // compare against what we routed on. A fault that flipped the
        // routing fields between first parse and record lands here.
        let kind_b = snap[walk];
        let tx_idx_b = snap[walk + 1];
        crate::fi::wait_random();
        if crate::fi::check_true_into_sentinel(|| {
            core::hint::black_box(kind_b == kind && tx_idx_b == tx_idx)
        }) != crate::fi::OK_SENTINEL
        {
            ui::show_status("Batch sign", "rec glitch");
            return Err(NscStatus::InvalidPointer as u32);
        }

        walk = payload_start + len;
    }

    // ── 4. Trailing-bytes check ─────────────────────────────────────
    //
    // The trailer block consumes the rest of the payload exactly. Any
    // residual bytes mean either a wire-version mismatch or a malformed
    // companion — refuse rather than silently ignore.
    if walk != total_len {
        ui::show_status("Batch sign", "trailing bytes");
        return Err(NscStatus::InvalidPointer as u32);
    }

    Ok(ParsedTrailers {
        records,
        count: trailer_count,
        next_cursor: walk,
    })
}

// ─────────────────────────────────────────────────────────────────────
// Pure-logic tests — exercise every refusal path on the host. Live
// in-file (rather than a separate `nsc_batch_trailers_pure_tests.rs`)
// because they need internal access to `parse_all` and the kind/length
// dispatch table, which would force a wider re-export surface
// otherwise.
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid trailer payload framed at offset 0.
    /// Returns `(snap, total_len)` ready for `parse_all(_, 0, total_len, batch_count)`.
    fn build(records: &[(u8, u8, &[u8])]) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec::Vec::new();
        buf.push(records.len() as u8);
        for &(kind, tx_idx, bytes) in records {
            buf.push(kind);
            buf.push(tx_idx);
            let len = bytes.len() as u16;
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(bytes);
        }
        buf
    }

    extern crate alloc;

    #[test]
    fn parses_zero_trailers() {
        let snap = build(&[]);
        let p = parse_all(&snap, 0, snap.len(), 2).expect("zero trailers ok");
        assert_eq!(p.count, 0);
        assert_eq!(p.next_cursor, 1);
    }

    #[test]
    fn parses_one_erc20_routed_to_tx0() {
        let payload = [0u8; 64];
        let snap = build(&[(TRAILER_KIND_ERC20, 0, &payload)]);
        let p = parse_all(&snap, 0, snap.len(), 1).expect("ok");
        assert_eq!(p.count, 1);
        let r = p.records[0].as_ref().unwrap();
        assert_eq!(r.kind, TRAILER_KIND_ERC20);
        assert_eq!(r.tx_idx, 0);
        assert_eq!(r.len, 64);
    }

    #[test]
    fn parses_batch_wide_name() {
        let payload = [0u8; 64];
        let snap = build(&[(TRAILER_KIND_NAME, TRAILER_TX_IDX_BATCH_WIDE, &payload)]);
        let p = parse_all(&snap, 0, snap.len(), 1).expect("ok");
        assert_eq!(p.count, 1);
        assert_eq!(p.records[0].as_ref().unwrap().tx_idx, TRAILER_TX_IDX_BATCH_WIDE);
    }

    #[test]
    fn refuses_oversized_count() {
        // count = MAX_TRAILERS_PER_BATCH + 1; body would be ignored.
        let mut snap = alloc::vec::Vec::new();
        snap.push((MAX_TRAILERS_PER_BATCH + 1) as u8);
        let r = parse_all(&snap, 0, snap.len(), 1);
        assert!(r.is_err());
    }

    #[test]
    fn refuses_zero_kind() {
        let snap = build(&[(0, 0, &[])]);
        assert!(parse_all(&snap, 0, snap.len(), 1).is_err());
    }

    #[test]
    fn refuses_kind_nine() {
        let snap = build(&[(9, 0, &[])]);
        assert!(parse_all(&snap, 0, snap.len(), 1).is_err());
    }

    #[test]
    fn refuses_tx_idx_at_batch_count() {
        let snap = build(&[(TRAILER_KIND_ERC20, 2, &[])]);
        assert!(parse_all(&snap, 0, snap.len(), 2).is_err());
    }

    #[test]
    fn refuses_name_not_batch_wide() {
        let snap = build(&[(TRAILER_KIND_NAME, 0, &[])]);
        assert!(parse_all(&snap, 0, snap.len(), 1).is_err());
    }

    #[test]
    fn refuses_per_tx_kind_marked_batch_wide() {
        let snap = build(&[(TRAILER_KIND_ERC20, TRAILER_TX_IDX_BATCH_WIDE, &[])]);
        assert!(parse_all(&snap, 0, snap.len(), 1).is_err());
    }

    #[test]
    fn refuses_duplicate_same_kind_tx_idx() {
        let snap = build(&[
            (TRAILER_KIND_ERC20, 0, &[]),
            (TRAILER_KIND_ERC20, 0, &[]),
        ]);
        assert!(parse_all(&snap, 0, snap.len(), 1).is_err());
    }

    #[test]
    fn refuses_curated_plus_self_attest_same_tx() {
        let snap = build(&[
            (TRAILER_KIND_SEL_CURATED, 0, &[]),
            (TRAILER_KIND_SEL_SELFATTEST, 0, &[]),
        ]);
        assert!(parse_all(&snap, 0, snap.len(), 1).is_err());
    }

    #[test]
    fn allows_curated_and_self_attest_on_different_txs() {
        let snap = build(&[
            (TRAILER_KIND_SEL_CURATED, 0, &[]),
            (TRAILER_KIND_SEL_SELFATTEST, 1, &[]),
        ]);
        parse_all(&snap, 0, snap.len(), 2).expect("ok");
    }

    #[test]
    fn refuses_per_kind_length_cap_exceeded() {
        // ERC-20 cap is MAX_ERC20_BUNDLE_LEN (1120). 1121 bytes refused.
        let payload = alloc::vec![0u8; MAX_ERC20_BUNDLE_LEN + 1];
        let snap = build(&[(TRAILER_KIND_ERC20, 0, &payload)]);
        assert!(parse_all(&snap, 0, snap.len(), 1).is_err());
    }

    #[test]
    fn refuses_total_payload_budget_exceeded() {
        // 4 × ERC-7730 (5130 each, one per inner tx) + 1 × Safe v1
        // (4379) = 24899 B > 24576 B. Refuses the fifth record.
        let max_7730 = alloc::vec![0u8; ERC7730_MAX_TRAILER_LEN];
        let max_safe = alloc::vec![0u8; SAFE_V1_PAYLOAD_MAX];
        let snap = build(&[
            (TRAILER_KIND_ERC7730, 0, &max_7730),
            (TRAILER_KIND_ERC7730, 1, &max_7730),
            (TRAILER_KIND_ERC7730, 2, &max_7730),
            (TRAILER_KIND_ERC7730, 3, &max_7730),
            (TRAILER_KIND_SAFE_V1, 0, &max_safe),
        ]);
        assert!(parse_all(&snap, 0, snap.len(), 4).is_err());
    }

    #[test]
    fn refuses_record_header_truncated() {
        let mut snap = alloc::vec::Vec::new();
        snap.push(1); // count=1
        snap.push(TRAILER_KIND_ERC20); // only kind byte, missing tx_idx + len
        assert!(parse_all(&snap, 0, snap.len(), 1).is_err());
    }

    #[test]
    fn refuses_record_payload_truncated() {
        let mut snap = alloc::vec::Vec::new();
        snap.push(1); // count=1
        snap.push(TRAILER_KIND_ERC20);
        snap.push(0); // tx_idx
        snap.extend_from_slice(&100u16.to_be_bytes()); // declared len 100
        snap.extend_from_slice(&[0u8; 50]); // only 50 bytes provided
        assert!(parse_all(&snap, 0, snap.len(), 1).is_err());
    }

    #[test]
    fn refuses_trailing_bytes() {
        let mut snap = build(&[(TRAILER_KIND_ERC20, 0, &[])]);
        snap.push(0xff); // extra byte after the list
        assert!(parse_all(&snap, 0, snap.len(), 1).is_err());
    }

    #[test]
    fn refuses_more_than_max_name_bundles() {
        // MAX_NAME_BUNDLES = 4. Five batch-wide names → refused.
        let snap = build(&[
            (TRAILER_KIND_NAME, TRAILER_TX_IDX_BATCH_WIDE, &[]),
            (TRAILER_KIND_NAME, TRAILER_TX_IDX_BATCH_WIDE, &[]),
            (TRAILER_KIND_NAME, TRAILER_TX_IDX_BATCH_WIDE, &[]),
            (TRAILER_KIND_NAME, TRAILER_TX_IDX_BATCH_WIDE, &[]),
            (TRAILER_KIND_NAME, TRAILER_TX_IDX_BATCH_WIDE, &[]),
        ]);
        assert!(parse_all(&snap, 0, snap.len(), 1).is_err());
    }

    #[test]
    fn accepts_max_name_bundles() {
        let snap = build(&[
            (TRAILER_KIND_NAME, TRAILER_TX_IDX_BATCH_WIDE, &[]),
            (TRAILER_KIND_NAME, TRAILER_TX_IDX_BATCH_WIDE, &[]),
            (TRAILER_KIND_NAME, TRAILER_TX_IDX_BATCH_WIDE, &[]),
            (TRAILER_KIND_NAME, TRAILER_TX_IDX_BATCH_WIDE, &[]),
        ]);
        let p = parse_all(&snap, 0, snap.len(), 1).expect("4 names ok");
        assert_eq!(p.count, 4);
    }

    #[test]
    fn iter_kind_returns_only_matching_records() {
        let snap = build(&[
            (TRAILER_KIND_ERC20, 0, &[]),
            (TRAILER_KIND_ERC7730, 0, &[]),
            (TRAILER_KIND_ERC20, 1, &[]),
        ]);
        let p = parse_all(&snap, 0, snap.len(), 2).expect("ok");
        let erc20s: alloc::vec::Vec<_> = p.iter_kind(TRAILER_KIND_ERC20).collect();
        assert_eq!(erc20s.len(), 2);
        let erc7730s: alloc::vec::Vec<_> = p.iter_kind(TRAILER_KIND_ERC7730).collect();
        assert_eq!(erc7730s.len(), 1);
    }

    #[test]
    fn refuses_missing_count_byte() {
        // Empty snap, cursor at 0 — even the count byte is missing.
        let snap: [u8; 0] = [];
        assert!(parse_all(&snap, 0, 0, 1).is_err());
    }

    #[test]
    fn max_len_per_kind_table_matches_constants() {
        // Drift guard: bump kind caps in the table whenever the
        // verifier-side const bumps.
        assert_eq!(MAX_LEN_PER_KIND[TRAILER_KIND_ERC20 as usize], MAX_ERC20_BUNDLE_LEN);
        assert_eq!(
            MAX_LEN_PER_KIND[TRAILER_KIND_ZK_V1 as usize],
            ZK_CLEAR_SIGN_FIXED_LEN + ZK_VK_BUNDLE_MAX_LEN
        );
        assert_eq!(
            MAX_LEN_PER_KIND[TRAILER_KIND_ZK_V3 as usize],
            ZK_V3_FIXED_LEN + ZK_VK_BUNDLE_MAX_LEN
        );
        assert_eq!(MAX_LEN_PER_KIND[TRAILER_KIND_SAFE_V1 as usize], SAFE_V1_PAYLOAD_MAX);
        assert_eq!(
            MAX_LEN_PER_KIND[TRAILER_KIND_SEL_CURATED as usize],
            MAX_SELECTOR_BUNDLE_LEN
        );
        assert_eq!(
            MAX_LEN_PER_KIND[TRAILER_KIND_SEL_SELFATTEST as usize],
            MAX_SELF_ATTEST_BUNDLE_LEN
        );
        assert_eq!(
            MAX_LEN_PER_KIND[TRAILER_KIND_ERC7730 as usize],
            ERC7730_MAX_TRAILER_LEN
        );
        assert_eq!(MAX_LEN_PER_KIND[TRAILER_KIND_NAME as usize], MAX_NAME_BUNDLE_LEN);
    }
}

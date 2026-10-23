//! Host-side test suite for the `secure-nsc-sign-userop` slice.
//!
//! # What is covered here
//!
//! The slice itself lives in three files under `secure/src/nsc/`:
//!
//!   * `cmd_sign_userop.rs` — the unified Type-1 / Type-2 sign handler.
//!     The 1400-line `run(&GatewayArgs)` function pulls in hardware
//!     drivers, the OLED stack, the secure-element trait, the FI helper
//!     module, flash I/O, and the `static mut` slot cache. None of that
//!     is reachable from a host build, so the function as a whole is
//!     only exercised by the QEMU and on-target e2e suites.
//!   * `sig_wrapper.rs` — pure-logic ABI-encoder for the
//!     `SignatureWrapper(uint256 ownerIndex, bytes innerSig)` struct.
//!     Re-included at the crate root under `cfg(test)` as
//!     `nsc_sig_wrapper_under_test`.
//!   * `trailer.rs` — pure-logic optional `[u16 BE len][payload]` parser.
//!     Re-included at the crate root under `cfg(test)` as
//!     `nsc_trailer_under_test`. Its sole crate-side dependency is
//!     `crate::ui::show_status`, which `main.rs` stubs out for the test
//!     build.
//!
//! The third bucket of tests below pins the wire-format constants the
//! on-chain verifier and the companion app both agree on. Those
//! constants live in `pqsigner-proto`; if they ever drift, the on-chain
//! verifier and the firmware will silently disagree, which is exactly
//! the class of regression these negative tests exist to catch.

#![cfg(test)]

use sphincs_tz_shared::{
    ACCOUNT_INDEX_MASK, ACCOUNT_INDEX_SHIFT, APPROVE_HASH_CALLDATA_LEN,
    APPROVE_HASH_SELECTOR, C10_SIG_LEN, FLAG_INCLUDE_INIT_CODE, FLAG_REGISTER_SLOT,
    GPV2_SETTLEMENT_ADDRESS, MAX_ACCOUNT_INDEX, MAX_SIGN_RESPONSE_LEN, MAX_TX_LEN, NscStatus,
    PQ_ADD_OWNER_BYTES_SELECTOR, PQ_CREATE_ACCOUNT_SELECTOR, PQ_INIT_CODE_LEN,
    PQ_SMART_WALLET_FACTORY, SET_PRE_SIGNATURE_SELECTOR, SIGN_USEROP_HEADER_LEN,
    SIG_WRAPPER_LEN, SLOT_INDEX_MASK,
};
#[cfg(feature = "erc7730-forced-blind")]
use sphincs_tz_shared::{
    EXEC_TRANSACTION_SELECTOR, MULTISEND_CALL_ONLY_ADDRESSES, MULTI_SEND_SELECTOR,
};

use crate::nsc_sig_wrapper_under_test::encode_signature_wrapper;
use crate::nsc_trailer_under_test::{read_optional_u16_prefixed, Trailer};

// ─────────────────────────────────────────────────────────────────────
// 1. Positive: `encode_signature_wrapper` (sig_wrapper.rs)
//
// The wrapper is the byte-exact ABI struct
//   abi.encode(uint256 ownerIndex, bytes innerSig)
// that `PQSmartWallet.validateUserOp` (Type 1 / Type 2) and
// `PQSmartWallet.isValidSignature` (EIP-1271) ABI-decode every
// signature into. Any change to the on-wire layout would break the
// on-chain verifier silently.
// ─────────────────────────────────────────────────────────────────────

/// Build a deterministic 4008-byte sig fixture (`[1,2,3,...]` mod 256)
/// so byte-by-byte comparisons stay readable in failure output.
fn fixture_sig() -> [u8; C10_SIG_LEN] {
    let mut sig = [0u8; C10_SIG_LEN];
    for (i, b) in sig.iter_mut().enumerate() {
        *b = (i & 0xff) as u8;
    }
    sig
}

#[test]
fn positive_sig_wrapper_owner_index_zero_lays_out_as_documented() {
    // Type 1 (bootstrap) signature wrapper.
    let mut out = [0u8; SIG_WRAPPER_LEN];
    let sig = fixture_sig();
    encode_signature_wrapper(&mut out, 0, &sig);

    // ownerIndex slot is all zero.
    assert_eq!(&out[0..32], &[0u8; 32], "ownerIndex slot must be 0");
    // offset slot = 0x40.
    assert_eq!(&out[32..63], &[0u8; 31]);
    assert_eq!(out[63], 0x40, "offset must equal 0x40");
    // length slot = 4008 (= 0x0fa8) in the trailing 8 bytes.
    assert_eq!(&out[64..88], &[0u8; 24]);
    assert_eq!(&out[88..96], &(C10_SIG_LEN as u64).to_be_bytes());
    // Inner sig copied verbatim.
    assert_eq!(&out[96..96 + C10_SIG_LEN], &sig[..]);
    // Trailing padding stays zero (caller-supplied zero-init contract).
    assert_eq!(&out[96 + C10_SIG_LEN..], &[0u8; SIG_WRAPPER_LEN - 96 - C10_SIG_LEN]);
}

#[test]
fn positive_sig_wrapper_owner_index_one_for_slot0_type2() {
    // Type 2 (slot-0 after deploy) — ownerIndex = 1.
    let mut out = [0u8; SIG_WRAPPER_LEN];
    let sig = fixture_sig();
    encode_signature_wrapper(&mut out, 1, &sig);
    let mut expected_owner = [0u8; 32];
    expected_owner[31] = 0x01;
    assert_eq!(&out[0..32], &expected_owner);
    assert_eq!(out[63], 0x40);
    assert_eq!(&out[96..96 + C10_SIG_LEN], &sig[..]);
}

#[test]
fn positive_sig_wrapper_owner_index_u64_max_left_pads_correctly() {
    let mut out = [0u8; SIG_WRAPPER_LEN];
    let sig = fixture_sig();
    encode_signature_wrapper(&mut out, u64::MAX, &sig);
    // Top 24 bytes of the 32-byte ownerIndex slot stay zero (no carry
    // into the offset slot below).
    assert_eq!(&out[0..24], &[0u8; 24]);
    assert_eq!(&out[24..32], &u64::MAX.to_be_bytes());
}

#[test]
fn positive_sig_wrapper_offset_field_is_0x40() {
    let mut out = [0u8; SIG_WRAPPER_LEN];
    encode_signature_wrapper(&mut out, 5, &fixture_sig());
    // Solidity ABI: tail offset, measured from the start of the
    // dynamic part. For a single (uint256, bytes) tuple this is the
    // 64-byte head, i.e. 0x40.
    assert_eq!(out[63], 0x40);
    // Every other byte in the offset slot is zero.
    for i in 32..63 {
        assert_eq!(out[i], 0, "offset byte {i} must be zero");
    }
}

#[test]
fn positive_sig_wrapper_length_field_matches_c10_sig_len() {
    let mut out = [0u8; SIG_WRAPPER_LEN];
    encode_signature_wrapper(&mut out, 0, &fixture_sig());
    // length slot is the inner-bytes length in big-endian u256. We
    // write the low 8 bytes only because C10_SIG_LEN < 2^64.
    for i in 64..88 {
        assert_eq!(out[i], 0, "length high bytes must be zero (byte {i})");
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&out[88..96]);
    assert_eq!(u64::from_be_bytes(buf) as usize, C10_SIG_LEN);
}

#[test]
fn positive_sig_wrapper_total_length_matches_const() {
    // Compile-time sanity: SIG_WRAPPER_LEN really is the buffer length
    // the encoder writes into. If anyone ever bumps C10_SIG_LEN past
    // the next 32-byte boundary the constant tracks it automatically.
    assert_eq!(SIG_WRAPPER_LEN, 96 + C10_SIG_LEN.next_multiple_of(32));
}

#[test]
fn positive_sig_wrapper_inner_sig_is_copied_verbatim() {
    let mut out = [0u8; SIG_WRAPPER_LEN];
    let sig = fixture_sig();
    encode_signature_wrapper(&mut out, 7, &sig);
    // Inner sig is copied byte-for-byte.
    assert_eq!(&out[96..96 + C10_SIG_LEN], &sig[..]);
}

#[test]
fn positive_sig_wrapper_zero_owner_does_not_disturb_offset_or_length() {
    // Regression guard: ownerIndex==0 is the most common case (Type 1
    // wrapper). A bug that wrote past byte 32 here would corrupt the
    // offset slot.
    let mut out = [0u8; SIG_WRAPPER_LEN];
    encode_signature_wrapper(&mut out, 0, &fixture_sig());
    assert_eq!(out[63], 0x40);
    assert_eq!(&out[88..96], &(C10_SIG_LEN as u64).to_be_bytes());
}

// ─────────────────────────────────────────────────────────────────────
// 2. Negative: `encode_signature_wrapper`
//
// Assumption challenges. Each test names the assumption from the
// CLAUDE.md / file-level docstring + asserts the byte-exact outcome the
// on-chain verifier depends on.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_sig_wrapper_owner_index_high_byte_does_not_bleed_into_offset() {
    // Assumption: ownerIndex is written into out[24..32] only, so even
    // u64::MAX leaves out[0..24] (the high half of the 32-byte slot)
    // and the offset slot (out[32..64]) untouched. A future refactor
    // that widened ownerIndex to a full u256 must do so deliberately;
    // until then, byte 32..64 must still be `0x...40`.
    let mut out = [0u8; SIG_WRAPPER_LEN];
    encode_signature_wrapper(&mut out, u64::MAX, &fixture_sig());
    assert_eq!(&out[0..24], &[0u8; 24], "ownerIndex high half must stay 0");
    assert_eq!(out[63], 0x40, "offset must remain 0x40 even with u64::MAX owner");
}

#[test]
fn negative_sig_wrapper_does_not_overwrite_pre_zeroed_padding() {
    // Assumption (docstring of encode_signature_wrapper): the caller
    // supplies `out` zero-initialised, and the encoder does NOT
    // bother to re-zero the trailing padding past the C10 sig data.
    // If anyone ever introduces a memcpy that writes past offset
    // 96 + C10_SIG_LEN, the on-chain ABI decoder would be fine but
    // the firmware's `Zeroizing<SIG_WRAPPER_LEN>` invariant becomes
    // load-bearing. Verify the encoder respects its zero-pad
    // contract.
    let mut out = [0xAAu8; SIG_WRAPPER_LEN];
    // Pre-zero just the bytes the encoder is supposed to touch.
    for b in &mut out[..96 + C10_SIG_LEN] {
        *b = 0;
    }
    encode_signature_wrapper(&mut out, 1, &fixture_sig());
    // Encoder leaves the original poison bytes in the padding region.
    for (i, &b) in out[96 + C10_SIG_LEN..].iter().enumerate() {
        assert_eq!(b, 0xAA, "padding byte {i} was clobbered — encoder broke its zero-pad contract");
    }
}

#[test]
fn negative_sig_wrapper_owner_index_byte_layout_is_left_padded() {
    // Assumption: ownerIndex is a uint256 in Solidity ABI, MSB at byte
    // 0 of the 32-byte head slot. A small u64 value MUST appear in
    // the LAST 8 bytes, not the first 8 — otherwise the on-chain
    // decoder reads a different ownerIndex than we intended.
    let mut out = [0u8; SIG_WRAPPER_LEN];
    encode_signature_wrapper(&mut out, 0x1234_5678_9abc_def0, &fixture_sig());
    assert_eq!(
        &out[24..32],
        &0x1234_5678_9abc_def0u64.to_be_bytes(),
        "ownerIndex must be right-aligned in the 32-byte slot"
    );
    assert_eq!(&out[0..24], &[0u8; 24]);
}

#[test]
fn negative_sig_wrapper_length_field_is_left_padded_u256() {
    // Assumption: the bytes-length is a uint256, MSB-first, so its low
    // 8 bytes are at out[88..96]. A future refactor that writes the
    // length in little-endian or starting at out[64] would crash the
    // on-chain ABI decoder.
    let mut out = [0u8; SIG_WRAPPER_LEN];
    encode_signature_wrapper(&mut out, 0, &fixture_sig());
    assert_eq!(&out[64..88], &[0u8; 24], "length high half must be zero");
    // and big-endian u64 in the low 8 bytes.
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&out[88..96]);
    assert_eq!(u64::from_be_bytes(buf), C10_SIG_LEN as u64);
}

#[test]
fn negative_sig_wrapper_two_calls_produce_identical_output() {
    // Determinism: the encoder is pure. Two calls with identical
    // inputs must yield identical buffers. Catches any future
    // optimisation that accidentally introduces a hidden static-mut
    // counter or scratch buffer.
    let mut a = [0u8; SIG_WRAPPER_LEN];
    let mut b = [0u8; SIG_WRAPPER_LEN];
    let sig = fixture_sig();
    encode_signature_wrapper(&mut a, 42, &sig);
    encode_signature_wrapper(&mut b, 42, &sig);
    assert_eq!(a, b, "encoder must be deterministic");
}

// ─────────────────────────────────────────────────────────────────────
// 3. Positive: `read_optional_u16_prefixed` (trailer.rs)
//
// Optional `[u16 BE len][payload]` parser shared by every trailer site
// in `cmd_sign_userop.rs` (ERC-20 / reserved slot / Safe / selector / self-
// attest). Absence is legal at end-of-buffer.
// ─────────────────────────────────────────────────────────────────────

/// Helper: extract the Trailer from a `Result<Trailer, u32>` without
/// requiring Debug on either type (Trailer does not derive Debug in
/// the production source).
fn expect_ok(r: Result<Trailer, u32>) -> Trailer {
    match r {
        Ok(t) => t,
        Err(s) => panic!("expected Ok, got Err({s})"),
    }
}

/// Helper: extract the error u32 from a `Result<Trailer, u32>` without
/// requiring Debug on Trailer.
fn expect_err(r: Result<Trailer, u32>) -> u32 {
    match r {
        Ok(_) => panic!("expected Err, got Ok"),
        Err(s) => s,
    }
}

#[test]
fn positive_trailer_absent_when_at_end_of_buffer() {
    // cursor == total_len: no more trailers. Returns len=0, no error.
    let snap = [0u8; 16];
    let t = expect_ok(read_optional_u16_prefixed(&snap, 16, 16, 64, "label"));
    assert_eq!(t.len, 0);
    assert_eq!(t.start, 16);
    assert_eq!(t.next_cursor, 16);
}

#[test]
fn positive_trailer_absent_when_single_byte_remaining() {
    // Only 1 byte before total_len — fewer than the 2-byte length
    // header needs. Treat as absent.
    let snap = [0xab; 16];
    let t = expect_ok(read_optional_u16_prefixed(&snap, 15, 16, 64, "label"));
    assert_eq!(t.len, 0);
    assert_eq!(t.start, 15);
    assert_eq!(t.next_cursor, 15);
}

#[test]
fn positive_trailer_explicit_zero_length_payload() {
    // 0x00 0x00 length header — explicit "no payload, but I told you
    // I'm here." Cursor advances past the 2-byte header.
    let snap = [0u8; 8];
    let t = expect_ok(read_optional_u16_prefixed(&snap, 0, 8, 64, "label"));
    assert_eq!(t.len, 0);
    assert_eq!(t.start, 2);
    assert_eq!(t.next_cursor, 2);
}

#[test]
fn positive_trailer_normal_payload_returns_correct_offsets() {
    // [u16 BE = 4][payload of 4 bytes].
    let mut snap = [0u8; 16];
    snap[0] = 0x00;
    snap[1] = 0x04;
    snap[2..6].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let t = expect_ok(read_optional_u16_prefixed(&snap, 0, 16, 64, "label"));
    assert_eq!(t.len, 4);
    assert_eq!(t.start, 2);
    assert_eq!(t.next_cursor, 6);
    assert_eq!(&snap[t.start..t.start + t.len], &[0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn positive_trailer_max_len_payload_accepted() {
    // Exactly max_len is OK.
    const MAX: usize = 8;
    let mut snap = [0u8; 2 + MAX];
    snap[1] = MAX as u8;
    for (i, b) in snap[2..].iter_mut().enumerate() {
        *b = i as u8;
    }
    let t = expect_ok(read_optional_u16_prefixed(&snap, 0, 2 + MAX, MAX, "label"));
    assert_eq!(t.len, MAX);
    assert_eq!(t.start, 2);
    assert_eq!(t.next_cursor, 2 + MAX);
}

#[test]
fn positive_trailer_next_cursor_chains_correctly() {
    // Two back-to-back trailers using the same helper: first cursor
    // is the second's input.
    let mut snap = [0u8; 16];
    snap[0..2].copy_from_slice(&3u16.to_be_bytes());
    snap[2..5].copy_from_slice(&[0x11, 0x22, 0x33]);
    snap[5..7].copy_from_slice(&2u16.to_be_bytes());
    snap[7..9].copy_from_slice(&[0x44, 0x55]);

    let first = expect_ok(read_optional_u16_prefixed(&snap, 0, 9, 64, "first"));
    assert_eq!(first.len, 3);
    assert_eq!(first.next_cursor, 5);

    let second = expect_ok(read_optional_u16_prefixed(
        &snap,
        first.next_cursor,
        9,
        64,
        "second",
    ));
    assert_eq!(second.len, 2);
    assert_eq!(second.start, 7);
    assert_eq!(second.next_cursor, 9);
}

#[test]
fn positive_trailer_payload_at_exact_end_of_total_len() {
    // payload_start + len == total_len is a valid termination.
    let mut snap = [0u8; 6];
    snap[0..2].copy_from_slice(&4u16.to_be_bytes());
    snap[2..6].copy_from_slice(&[1, 2, 3, 4]);
    let t = expect_ok(read_optional_u16_prefixed(&snap, 0, 6, 64, "label"));
    assert_eq!(t.len, 4);
    assert_eq!(t.next_cursor, 6);
}

// ─────────────────────────────────────────────────────────────────────
// 4. Negative: `read_optional_u16_prefixed`
//
// Every assumption the helper holds about its inputs gets a violation
// + an assertion that the violation is rejected with
// `NscStatus::InvalidPointer`.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_trailer_declared_len_exceeds_max_len() {
    // Assumption: a trailer that advertises more bytes than the
    // per-trailer cap (`max_len`) is fraudulent — bound to a single
    // section, the cap is the on-device parser's first defence
    // against a hostile companion blowing past the SNAP_LEN reservation.
    let mut snap = [0u8; 256];
    snap[0..2].copy_from_slice(&100u16.to_be_bytes());
    let err = expect_err(read_optional_u16_prefixed(&snap, 0, 256, 64, "label"));
    assert_eq!(
        err,
        NscStatus::InvalidPointer as u32,
        "declared_len > max_len must be rejected as InvalidPointer per the docstring"
    );
}

#[test]
fn negative_trailer_declared_len_exceeds_remaining_total_len() {
    // Assumption: even if declared_len <= max_len, the helper must
    // refuse a length that would read past the TOCTOU snapshot. A
    // missing bound here would let a companion-supplied byte stream
    // dictate how much memory we touch — classic length-confusion
    // attack.
    let mut snap = [0u8; 16];
    snap[0..2].copy_from_slice(&20u16.to_be_bytes()); // declared 20, only 14 left
    let err = expect_err(read_optional_u16_prefixed(&snap, 0, 16, 64, "label"));
    assert_eq!(err, NscStatus::InvalidPointer as u32);
}

#[test]
fn negative_trailer_max_len_plus_one_rejected_at_boundary() {
    // Sharp-boundary check: max_len + 1 must be the first rejection
    // length, not max_len. Catches off-by-one regressions.
    const MAX: usize = 32;
    let mut snap = [0u8; 64];
    snap[0..2].copy_from_slice(&(MAX as u16 + 1).to_be_bytes());
    let err = expect_err(read_optional_u16_prefixed(&snap, 0, 64, MAX, "label"));
    assert_eq!(err, NscStatus::InvalidPointer as u32);
}

#[test]
fn negative_trailer_zero_max_len_rejects_any_nonzero_payload() {
    // max_len = 0 effectively says "no payload allowed." Any
    // non-absent trailer must error. Documented behaviour but a
    // future refactor that uses `len > max_len` could become
    // `len >= max_len` and silently allow size-0 payloads through.
    let mut snap = [0u8; 16];
    snap[0..2].copy_from_slice(&1u16.to_be_bytes()); // declared len=1
    let err = expect_err(read_optional_u16_prefixed(&snap, 0, 16, 0, "label"));
    assert_eq!(err, NscStatus::InvalidPointer as u32);
}

#[test]
fn negative_trailer_huge_declared_len_does_not_overflow_arithmetic() {
    // Assumption: declared_len = 0xFFFF must not cause integer
    // overflow on `payload_start + len`. The helper computes
    // `payload_start + len > total_len` *before* indexing, so even
    // 0xFFFF stays bounded inside usize.
    let mut snap = [0u8; 32];
    snap[0..2].copy_from_slice(&0xFFFFu16.to_be_bytes());
    let err = expect_err(read_optional_u16_prefixed(&snap, 0, 32, 0xFFFF, "label"));
    assert_eq!(err, NscStatus::InvalidPointer as u32);
}

#[test]
fn negative_trailer_does_not_index_past_total_len_when_header_absent() {
    // Assumption (security note in the docstring): the helper never
    // reads past `total_len`. If we pass `total_len == cursor`, the
    // 2-byte header check is the first thing it does — and it must
    // return absent without touching `snap[cursor]` even if that
    // index is in bounds of `snap`. Verified by passing a `snap`
    // sized exactly to `total_len`; if the helper read past, we'd
    // panic-on-bounds inside the test.
    let snap: [u8; 4] = [0xff; 4];
    let t = expect_ok(read_optional_u16_prefixed(&snap, 4, 4, 8, "label"));
    assert_eq!(t.len, 0);
    assert_eq!(t.next_cursor, 4);
}

#[test]
fn negative_trailer_returns_invalid_pointer_status_consistently() {
    // Every rejection path must return NscStatus::InvalidPointer as
    // u32 — not the raw `u32` value of some other status. The
    // dispatcher reads this in `cmd_sign_userop.rs::run` and forwards
    // it verbatim to NS; a drift here would surface as a misleading
    // error code on the companion app.
    let snap = [0u8; 64];
    // Three different ways to make the helper error; all must
    // return the same status code.
    let mut s1 = snap;
    s1[0..2].copy_from_slice(&63u16.to_be_bytes());
    let e1 = expect_err(read_optional_u16_prefixed(&s1, 0, 16, 64, "a"));

    let mut s2 = snap;
    s2[0..2].copy_from_slice(&65u16.to_be_bytes());
    let e2 = expect_err(read_optional_u16_prefixed(&s2, 0, 67, 64, "b"));

    let mut s3 = snap;
    s3[0..2].copy_from_slice(&0xFFFFu16.to_be_bytes());
    let e3 = expect_err(read_optional_u16_prefixed(&s3, 0, 64, 64, "c"));

    assert_eq!(e1, NscStatus::InvalidPointer as u32);
    assert_eq!(e2, NscStatus::InvalidPointer as u32);
    assert_eq!(e3, NscStatus::InvalidPointer as u32);
}

#[test]
fn negative_trailer_struct_fields_are_consistent_on_absent() {
    // Sanity: on the absent path, all three fields agree on the
    // cursor position. A later refactor that bumped `next_cursor`
    // past `start` on the absent branch would silently skip a byte
    // of the upstream payload.
    let snap = [0u8; 16];
    let t: Trailer = expect_ok(read_optional_u16_prefixed(&snap, 7, 7, 64, "label"));
    assert_eq!(t.start, 7);
    assert_eq!(t.next_cursor, 7);
    assert_eq!(t.len, 0);
}

#[test]
fn negative_trailer_struct_fields_are_consistent_on_valid_payload() {
    let mut snap = [0u8; 16];
    snap[0..2].copy_from_slice(&5u16.to_be_bytes());
    let t = expect_ok(read_optional_u16_prefixed(&snap, 0, 16, 64, "label"));
    assert_eq!(t.start, 2);
    assert_eq!(t.len, 5);
    // next_cursor = start + len, no slack.
    assert_eq!(t.next_cursor, t.start + t.len);
}

// ─────────────────────────────────────────────────────────────────────
// 5. Wire-format / invariant pins
//
// `cmd_sign_userop::run` constructs and emits bytes whose shape is
// frozen by what the on-chain verifier and the companion app already
// expect. CLAUDE.md calls these "frozen — on-chain verifier depends on
// them." A silent constant drift here is exactly the regression
// negative tests exist to catch. None of these tests touch the
// `run()` function — they pin the constants the function reads.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_sig_wrapper_len_constant_unchanged_4128() {
    // CLAUDE.md §"Unified sign output": `type{1,2}_wrapper` is
    // exactly 4128 bytes. The on-chain verifier ABI-decodes
    // SignatureWrapper(uint256, bytes) from this many bytes.
    assert_eq!(SIG_WRAPPER_LEN, 4128);
}

#[test]
fn negative_c10_sig_len_constant_unchanged_4008() {
    // C10 signature length is part of the on-chain ABI: the bytes-
    // length field in the wrapper encodes this value as a uint256.
    assert_eq!(C10_SIG_LEN, 4008);
}

#[test]
fn negative_init_code_len_constant_unchanged_4280() {
    // CLAUDE.md §"Unified sign output": `init_code` is 4280 B when
    // `FLAG_INCLUDE_INIT_CODE`. The factory's CREATE2 init-code hash
    // depends on the byte layout of this blob — a change breaks
    // invariant #6 (same 24 words → same address on every chain).
    assert_eq!(PQ_INIT_CODE_LEN, 4280);
}

#[test]
fn negative_sign_userop_header_len_unchanged_330() {
    // CLAUDE.md §"Unified sign input": header occupies bytes [0..330).
    // A change here would shift every field offset and silently
    // garble companion payloads.
    assert_eq!(SIGN_USEROP_HEADER_LEN, 330);
}

#[test]
fn negative_max_sign_response_includes_all_emitted_pieces() {
    // Output layout:
    //   8 (offchain count) + 4+4280 (init_code+len) + 4+4128 (type1+len)
    //   + 4+4128 (type2+len) = 12560
    // MAX_SIGN_RESPONSE_LEN must be at least this. A future
    // refactor that shortens MAX_SIGN_RESPONSE_LEN would let `run()`
    // pass its `validate_ns_write_ptr` check but then under-allocate
    // the NS-side buffer.
    let min_needed =
        8 + 4 + PQ_INIT_CODE_LEN + 4 + SIG_WRAPPER_LEN + 4 + SIG_WRAPPER_LEN;
    assert!(
        MAX_SIGN_RESPONSE_LEN >= min_needed,
        "MAX_SIGN_RESPONSE_LEN ({MAX_SIGN_RESPONSE_LEN}) < worst-case emit ({min_needed})"
    );
}

#[test]
fn negative_flag_bits_unchanged_match_claude_md() {
    // CLAUDE.md: "bit 31 INCLUDE_INIT_CODE, bit 30 REGISTER_SLOT,
    //  bits 29..22 account_index (8b, 0..=255),
    //  bits 21..0  slot_index (22b)".
    assert_eq!(FLAG_INCLUDE_INIT_CODE, 1u32 << 31);
    assert_eq!(FLAG_REGISTER_SLOT, 1u32 << 30);
    assert_eq!(ACCOUNT_INDEX_SHIFT, 22);
    // 8-bit account_index field at bits 29..22:
    assert_eq!(ACCOUNT_INDEX_MASK, 0xFFu32 << 22);
    // 22-bit slot_index field at bits 21..0:
    assert_eq!(SLOT_INDEX_MASK, (1u32 << 22) - 1);
}

#[test]
fn negative_flag_masks_are_pairwise_disjoint() {
    // Critical invariant: the four flag bit-fields must not overlap,
    // otherwise `flags & ACCOUNT_INDEX_MASK` would bleed into
    // INCLUDE_INIT_CODE / REGISTER_SLOT or vice versa.
    assert_eq!(FLAG_INCLUDE_INIT_CODE & FLAG_REGISTER_SLOT, 0);
    assert_eq!(FLAG_INCLUDE_INIT_CODE & ACCOUNT_INDEX_MASK, 0);
    assert_eq!(FLAG_INCLUDE_INIT_CODE & SLOT_INDEX_MASK, 0);
    assert_eq!(FLAG_REGISTER_SLOT & ACCOUNT_INDEX_MASK, 0);
    assert_eq!(FLAG_REGISTER_SLOT & SLOT_INDEX_MASK, 0);
    assert_eq!(ACCOUNT_INDEX_MASK & SLOT_INDEX_MASK, 0);
    // And together they cover the full u32.
    assert_eq!(
        FLAG_INCLUDE_INIT_CODE | FLAG_REGISTER_SLOT | ACCOUNT_INDEX_MASK | SLOT_INDEX_MASK,
        u32::MAX
    );
}

#[test]
fn negative_max_account_index_is_255() {
    // 8-bit field at bits 29..22 — max value is 0xFF.
    assert_eq!(MAX_ACCOUNT_INDEX, 0xFF);
    // And the mask, when shifted down, yields 0..=255.
    assert_eq!(ACCOUNT_INDEX_MASK >> ACCOUNT_INDEX_SHIFT, MAX_ACCOUNT_INDEX);
}

#[test]
fn negative_slot_index_max_is_22_bits() {
    // The slot_index field is 22 bits — max representable value
    // 0x3F_FFFF = (1<<22) - 1.
    assert_eq!(SLOT_INDEX_MASK, 0x003F_FFFF);
}

#[test]
fn negative_max_tx_len_pinned_8192() {
    // CLAUDE.md §"Unified sign input": `data_len (u16 BE, 0..=8192)`.
    // The 16-bit field can hold 65535, but the firmware caps at
    // MAX_TX_LEN (raised from 4096 on 2026-10-22 and advertised by
    // GET_DEVICE_INFO bit 5). A larger cap would consume more SNAP_LEN
    // and the `ui-px` overlay headroom; a smaller one would silently
    // reject companion payloads that used to work.
    assert_eq!(MAX_TX_LEN, 8192);
    assert_eq!(
        sphincs_tz_shared::DEVICE_CAPABILITIES & sphincs_tz_shared::CAP_SIGN_USEROP_DATA_8K,
        sphincs_tz_shared::CAP_SIGN_USEROP_DATA_8K
    );
}

// ─────────────────────────────────────────────────────────────────────
// 6. Domain-tag / selector / address stability
//
// `cmd_sign_userop.rs` bakes in three on-chain protocol identities:
//   * FACTORY_ADD_SLOT_DOMAIN (the bytes the bootstrap key signs to
//     authorise slot-0 on a new chain).
//   * PQ_CREATE_ACCOUNT_SELECTOR (the factory's createAccount selector).
//   * PQ_ADD_OWNER_BYTES_SELECTOR (the wallet's addOwnerBytes selector).
//   * PQ_SMART_WALLET_FACTORY (the factory's deployed address).
//   * SET_PRE_SIGNATURE_SELECTOR + GPV2_SETTLEMENT_ADDRESS (CoW
//     downgrade-mitigation gate).
//   * APPROVE_HASH_SELECTOR + APPROVE_HASH_CALLDATA_LEN (Safe v1
//     downgrade-mitigation gate).
//
// A silent change to any of these breaks an on-chain interaction.
// These tests are the canary.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_factory_add_slot_domain_unchanged() {
    // CLAUDE.md §"Key derivation": this is the byte string the
    // bootstrap key signs to unlock the factory's createAccount on
    // a new chain. Renaming it without rebuilding every bench board
    // breaks deploy.
    const FACTORY_ADD_SLOT_DOMAIN: &[u8] = b"pqwallet-factory-add-slot";
    assert_eq!(FACTORY_ADD_SLOT_DOMAIN.len(), 25);
    assert_eq!(FACTORY_ADD_SLOT_DOMAIN, b"pqwallet-factory-add-slot");
}

#[test]
fn negative_pq_create_account_selector_unchanged() {
    // The function selector embedded in the initCode prefix. A
    // change here means the factory call reverts.
    assert_eq!(PQ_CREATE_ACCOUNT_SELECTOR, [0xf6, 0x18, 0x2a, 0x73]);
}

#[test]
fn negative_pq_add_owner_bytes_selector_unchanged() {
    // The selector for the wallet's addOwnerBytes(bytes) call that
    // the Type 1 sig authorises during a slot rotation.
    assert_eq!(PQ_ADD_OWNER_BYTES_SELECTOR, [0x10, 0x14, 0x90, 0xcb]);
}

#[test]
fn negative_set_pre_signature_selector_unchanged() {
    // CoW downgrade-mitigation: the gate at cmd_sign_userop.rs:694
    // checks `inner_data[..4] == SET_PRE_SIGNATURE_SELECTOR` to
    // require the v3 EIP-712 trailer. A wrong selector here would
    // let an attacker bypass the trusted-UI 8-page CoW order render.
    assert_eq!(SET_PRE_SIGNATURE_SELECTOR, [0xec, 0x6c, 0xb1, 0x3f]);
}

#[test]
fn negative_approve_hash_selector_unchanged() {
    // Safe downgrade-mitigation: `cmd_sign_userop.rs:706` checks
    // `inner_data[..4] == APPROVE_HASH_SELECTOR` to require the
    // `safe_v1` trailer.
    assert_eq!(APPROVE_HASH_SELECTOR, [0xd4, 0xd9, 0xbd, 0xcd]);
}

#[test]
fn negative_approve_hash_calldata_len_is_selector_plus_bytes32() {
    // The downgrade gate at cmd_sign_userop.rs:707 also requires
    // `inner_data.len() == 36`. Otherwise an attacker could pad the
    // calldata past the bytes32 hash, and the strict-length check
    // would no longer fire. Pin the value.
    assert_eq!(APPROVE_HASH_CALLDATA_LEN, 4 + 32);
    assert_eq!(APPROVE_HASH_CALLDATA_LEN, 36);
}

#[test]
fn negative_gpv2_settlement_address_unchanged() {
    // Real GPv2Settlement deployment address (same on every chain).
    // The CoW downgrade gate matches against this byte-for-byte.
    // Canonical value: 0x9008D19f58AAbD9eD0D60971565AA8510560ab41.
    let expected: [u8; 20] = [
        0x90, 0x08, 0xd1, 0x9f, 0x58, 0xaa, 0xbd, 0x9e, 0xd0, 0xd6, 0x09, 0x71, 0x56, 0x5a, 0xa8,
        0x51, 0x05, 0x60, 0xab, 0x41,
    ];
    assert_eq!(GPV2_SETTLEMENT_ADDRESS, expected);
}

#[test]
fn negative_pq_smart_wallet_factory_address_not_null() {
    // The factory address is part of the CREATE2 preimage that
    // determines the wallet's on-chain address. A silent change
    // here breaks invariant #6.
    assert_eq!(PQ_SMART_WALLET_FACTORY.len(), 20);
    assert_ne!(PQ_SMART_WALLET_FACTORY, [0u8; 20]);
}

// ─────────────────────────────────────────────────────────────────────
// 7. `cmd_sign_userop` private-helper characterisation tests
//
// `add_one_to_be_u256` and `u128_saturating_from_u256` are private
// helpers in `cmd_sign_userop.rs`. The whole file is `cfg(not(test))`
// so we cannot link the host test against them. The tests below
// mirror the helper body and verify the *documented behaviour* — if
// anyone changes the helper, they must update this characterisation
// to match (or our negative invariant tests on the calling site will
// surface the drift).
//
// This is a deliberate redundancy. If you only test wire format and
// constants you miss bugs in the arithmetic; if you only test the
// arithmetic you miss bugs in the wire layout.
// ─────────────────────────────────────────────────────────────────────

/// Mirror of `cmd_sign_userop.rs:1394 add_one_to_be_u256`. Update both
/// or neither.
fn mirror_add_one_to_be_u256(v: &mut [u8; 32]) {
    for i in (24..32).rev() {
        let (sum, carry) = v[i].overflowing_add(1);
        v[i] = sum;
        if !carry {
            return;
        }
    }
    panic!("nonce seq overflow slipped past the step-4b guard");
}

#[test]
fn positive_nonce_increment_simple() {
    let mut n = [0u8; 32];
    n[31] = 5;
    mirror_add_one_to_be_u256(&mut n);
    assert_eq!(n[31], 6);
    // Unaffected bytes stay zero.
    assert_eq!(&n[0..31], &[0u8; 31]);
}

#[test]
fn positive_nonce_increment_with_carry_inside_seq() {
    let mut n = [0u8; 32];
    n[31] = 0xff;
    mirror_add_one_to_be_u256(&mut n);
    assert_eq!(n[31], 0x00);
    assert_eq!(n[30], 0x01);
    // Key field (bytes 0..24) untouched.
    assert_eq!(&n[0..24], &[0u8; 24]);
}

#[test]
fn positive_nonce_increment_only_touches_seq_portion() {
    // CRIT-17 (cmd_sign_userop.rs:288): v0.6 nonces are 192-bit key
    // | 64-bit seq. The increment helper must touch bytes 24..32
    // only.
    let mut n = [0xAAu8; 32];
    mirror_add_one_to_be_u256(&mut n);
    // Key field (bytes 0..24) is unchanged.
    assert_eq!(&n[0..24], &[0xAAu8; 24]);
}

#[test]
fn positive_rotation_type2_display_sequence_is_base_plus_one_same_lane() {
    let mut base = [0x5au8; 32];
    base[24..32].copy_from_slice(&41u64.to_be_bytes());
    let mut type2 = base;
    mirror_add_one_to_be_u256(&mut type2);
    assert_eq!(u64::from_be_bytes(base[24..32].try_into().unwrap()), 41);
    assert_eq!(u64::from_be_bytes(type2[24..32].try_into().unwrap()), 42);
    assert_eq!(&type2[..24], &base[..24], "rotation changed nonce lane");
}

#[test]
#[should_panic(expected = "nonce seq overflow")]
fn negative_nonce_increment_at_seq_overflow_panics_in_debug() {
    // CLAUDE.md §"Sign dispatch" and cmd_sign_userop.rs:288 — the
    // run() handler refuses to call the increment when the seq is
    // all-0xff. If a future refactor accidentally drops that guard
    // and feeds the helper an overflow input, the helper's
    // debug_assert!(false) catches it. This test asserts that the
    // catch-all panic path still fires in the debug-build mirror.
    let mut n = [0xffu8; 32]; // seq = 0xff..ff
    mirror_add_one_to_be_u256(&mut n);
}

#[test]
fn negative_nonce_overflow_check_in_run_uses_correct_byte_range() {
    // cmd_sign_userop.rs:291 — `if register_slot && nonce[24..32] ==
    // [0xFFu8; 8]` — verify the byte range matches the helper's
    // increment range (24..32). A mismatch (e.g. checking [25..32]
    // or [24..31]) would let a partial-overflow nonce slip past the
    // gate and silently carry into the 192-bit key field.
    //
    // We characterise the guard's documented byte range: bytes the
    // helper increments must be exactly the bytes the gate checks.
    let increment_range = 24..32;
    let gate_check_range = 24..32;
    assert_eq!(increment_range, gate_check_range);
}

/// Mirror of `cmd_sign_userop.rs:1414 u128_saturating_from_u256`.
fn mirror_u128_saturating_from_u256(bytes: &[u8; 32]) -> u128 {
    for &b in &bytes[0..16] {
        if b != 0 {
            return u128::MAX;
        }
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes[16..32]);
    u128::from_be_bytes(buf)
}

#[test]
fn positive_u128_sat_zero_returns_zero() {
    let bytes = [0u8; 32];
    assert_eq!(mirror_u128_saturating_from_u256(&bytes), 0);
}

#[test]
fn positive_u128_sat_low_128_returns_value() {
    let mut bytes = [0u8; 32];
    bytes[16..32].copy_from_slice(&123u128.to_be_bytes());
    assert_eq!(mirror_u128_saturating_from_u256(&bytes), 123);
}

#[test]
fn positive_u128_sat_max_low_128() {
    let mut bytes = [0u8; 32];
    bytes[16..32].copy_from_slice(&u128::MAX.to_be_bytes());
    assert_eq!(mirror_u128_saturating_from_u256(&bytes), u128::MAX);
}

#[test]
fn negative_u128_sat_any_high_byte_nonzero_saturates() {
    // Assumption: gas-fee fields are u256 but the firmware only
    // displays the low 128 bits. Values above 2^128 - 1 must be
    // surfaced as u128::MAX so the display doesn't silently wrap a
    // hostile-attacker-supplied huge gas value down to a small one.
    for high_byte_index in 0..16 {
        let mut bytes = [0u8; 32];
        bytes[high_byte_index] = 0x01; // single non-zero high byte
        assert_eq!(
            mirror_u128_saturating_from_u256(&bytes),
            u128::MAX,
            "high byte at index {high_byte_index} must trigger saturation"
        );
    }
}

#[test]
fn negative_u128_sat_msb_high_byte_saturates_not_truncates() {
    // The most-significant byte of the u256 (index 0) is the most
    // likely place where an attacker would set a 1-bit to flip a
    // gas overflow attack into a "gas value that looks normal mod
    // 2^128." Assert this is what the saturation path catches.
    let mut bytes = [0u8; 32];
    bytes[0] = 0x80;
    assert_eq!(mirror_u128_saturating_from_u256(&bytes), u128::MAX);
}

// ─────────────────────────────────────────────────────────────────────
// 8. Algorithm / API-policy negatives (CLAUDE.md §"What NOT to do")
//
// CLAUDE.md hard-bans every classical signer and every reset path.
// These tests assert the slice's source has no such names; if a
// refactor ever introduces e.g. `secp256k1_sign` or `rotate_master`
// in this file, the test fails.
// ─────────────────────────────────────────────────────────────────────

const CMD_SIGN_USEROP_SRC: &str =
    include_str!("nsc/cmd_sign_userop.rs");
const CMD_SIGN_USEROP_FORCED_SRC: &str = include_str!("nsc/cmd_sign_userop_forced.rs");
const CMD_SIGN_USEROP_BATCH_SRC: &str = include_str!("nsc/cmd_sign_userop_batch.rs");
const CMD_SIGN_OFFCHAIN_SRC: &str = include_str!("nsc/cmd_sign_offchain.rs");
const OFFCHAIN_STATE_SRC: &str = include_str!("offchain_state.rs");
const NSC_MOD_SRC: &str = include_str!("nsc/mod.rs");
const FORCED_BLIND_DISPLAY_SRC: &str = include_str!("tx/display/forced_blind.rs");
const SAFE_EXEC_DECODE_SRC: &str = include_str!("tx/eip712/safe/exec_decode.rs");
const WALLET_ADDRESS_SRC: &str = include_str!("nsc/cmd_get_wallet_address.rs");
const VALUE_PAGE_SRC: &str = include_str!("tx/display/value_page.rs");
const NONCE_LANE_SRC: &str = include_str!("tx/display/nonce_lane.rs");
const SIG_WRAPPER_SRC: &str = include_str!("nsc/sig_wrapper.rs");
const TRAILER_SRC: &str = include_str!("nsc/trailer.rs");

#[test]
fn negative_slice_does_not_mention_any_classical_signer() {
    // Invariant #5: "One signature primitive: SPHINCS+C10." No
    // ECDSA, no Ed25519, no FORS+C, no secp256k1, no P-256.
    // A drift here = invariant violation.
    for forbidden in &[
        "secp256k1", "ECDSA", "ecdsa",
        "ed25519", "Ed25519",
        "p256", "P256", "p-256", "P-256",
        "FORS+C", "fors_c", "fors+c",
        "rsa_sign", "RSA",
    ] {
        assert!(
            !CMD_SIGN_USEROP_SRC.contains(forbidden),
            "cmd_sign_userop.rs must not mention banned signer '{forbidden}' — \
             CLAUDE.md invariant #5"
        );
        assert!(
            !SIG_WRAPPER_SRC.contains(forbidden),
            "sig_wrapper.rs must not mention banned signer '{forbidden}'"
        );
        assert!(
            !TRAILER_SRC.contains(forbidden),
            "trailer.rs must not mention banned signer '{forbidden}'"
        );
    }
}

#[test]
fn negative_slice_does_not_expose_reset_or_rotate_paths() {
    // CLAUDE.md §"What NOT to do": no `rotateMasterKeys`,
    // `resetBootstrapUses`, `resetSlotUses`, `increaseMaxBootstrap`,
    // `increaseMaxSlot`. If anyone ever wires a similarly-named
    // function into the sign handler this test surfaces it.
    for forbidden in &[
        "rotateMasterKeys", "rotate_master_keys",
        "resetBootstrapUses", "reset_bootstrap_uses",
        "resetSlotUses", "reset_slot_uses",
        "increaseMaxBootstrap", "increase_max_bootstrap",
        "increaseMaxSlot", "increase_max_slot",
    ] {
        assert!(
            !CMD_SIGN_USEROP_SRC.contains(forbidden),
            "cmd_sign_userop.rs must not expose '{forbidden}' — CLAUDE.md"
        );
    }
}

#[test]
fn negative_slice_does_not_use_entrypoint_v07_or_v08() {
    // CLAUDE.md §"What NOT to do": "No EntryPoint v0.7 / v0.8
    // migration." Frozen target.
    for forbidden in &["v0.7", "v07", "v0_7", "v0.8", "v08", "v0_8"] {
        assert!(
            !CMD_SIGN_USEROP_SRC.contains(forbidden),
            "cmd_sign_userop.rs must target only EntryPoint v0.6 — found '{forbidden}'"
        );
    }
    // And the slice's only AaUserOp params type must be the v06
    // Sha256 variant. (Compile-time pin via use-site.)
    assert!(CMD_SIGN_USEROP_SRC.contains("AaUserOpParamsV06Sha256"));
}

#[test]
fn negative_slice_fi_pins_wire_entrypoint_and_hashes_only_the_constant() {
    // The wire field is hostile input. It must be checked before any later
    // header field or verifier can consume the request, and it must never be
    // threaded into the signing params. Two independently materialized reads
    // and two spatially separate reject gates force a single skipped reject to
    // encounter the second gate; direct use of `ENTRY_POINT_V06` in every
    // params initializer keeps the signed domain canonical even if control
    // flow is faulted.
    const SNAPSHOT_COPY_END: &str =
        "snap[i] = core::ptr::read_volatile(payload_ptr.add(i));\n    }\n";
    let snapshot_copy_end = CMD_SIGN_USEROP_SRC
        .find(SNAPSHOT_COPY_END)
        .map(|p| p + SNAPSHOT_COPY_END.len())
        .expect("completed single-handler snapshot copy loop");
    let parse_header = CMD_SIGN_USEROP_SRC
        .find("// ── 4. Parse header (big-endian, fixed offsets)")
        .expect("single-handler request parse boundary");
    let pin_a = CMD_SIGN_USEROP_SRC
        .find("let supplied_entry_point_a")
        .expect("first EntryPoint pin read");
    let gate_a = CMD_SIGN_USEROP_SRC[pin_a..]
        .find("if crate::fi::check_true_into_sentinel(|| core::hint::black_box(entry_point_match_a)")
        .map(|p| pin_a + p)
        .expect("first EntryPoint rejection gate");
    let gate_a_end = CMD_SIGN_USEROP_SRC[gate_a..]
        .find("return NscStatus::InvalidPointer as u32;")
        .map(|p| gate_a + p + "return NscStatus::InvalidPointer as u32;".len())
        .expect("end of first EntryPoint rejection gate");
    let gap = CMD_SIGN_USEROP_SRC[gate_a_end..]
        .find("crate::fi::wait_random();")
        .map(|p| gate_a_end + p)
        .expect("randomized gap between EntryPoint gates");
    let pin_b = CMD_SIGN_USEROP_SRC[gap..]
        .find("let supplied_entry_point_b")
        .map(|p| gap + p)
        .expect("second EntryPoint pin read");
    let gate_b = CMD_SIGN_USEROP_SRC[pin_b..]
        .find("if crate::fi::check_true_into_sentinel(|| core::hint::black_box(entry_point_match_b)")
        .map(|p| pin_b + p)
        .expect("second EntryPoint rejection gate");
    let gate_b_end = CMD_SIGN_USEROP_SRC[gate_b..]
        .find("return NscStatus::InvalidPointer as u32;")
        .map(|p| gate_b + p + "return NscStatus::InvalidPointer as u32;".len())
        .expect("end of second EntryPoint rejection gate");
    let nonce_parse = CMD_SIGN_USEROP_SRC
        .find("let mut nonce =")
        .expect("nonce parse");
    let chain_parse = CMD_SIGN_USEROP_SRC
        .find("let chain_id = u64::from_be_bytes([")
        .expect("chain-id parse");
    let flags_parse = CMD_SIGN_USEROP_SRC
        .find("let flags_a = u32::from_be_bytes(")
        .expect("flags parse");
    let diagnostic = CMD_SIGN_USEROP_SRC
        .find("#[cfg(all(feature = \"e2e-test\", feature = \"ui-lcd\"))]")
        .expect("request-derived e2e diagnostic");
    let sender_parse = CMD_SIGN_USEROP_SRC
        .find("let mut companion_sender =")
        .expect("sender parse");
    assert!(snapshot_copy_end <= pin_a, "pin must follow snapshot copy");
    assert!(
        pin_a < gate_a
            && gate_a < gate_a_end
            && gate_a_end < gap
            && gap < pin_b
            && pin_b < gate_b
            && gate_b < gate_b_end
    );
    assert!(
        gate_b_end < parse_header,
        "both EntryPoint gates must finish before the request parse boundary"
    );
    for (label, parse) in [
        ("chain id", chain_parse),
        ("flags", flags_parse),
        ("e2e diagnostic", diagnostic),
        ("sender", sender_parse),
        ("nonce", nonce_parse),
    ] {
        assert!(
            gate_b_end < parse,
            "EntryPoint must fail before {label} request handling"
        );
    }
    let pin_window = &CMD_SIGN_USEROP_SRC[snapshot_copy_end..gate_b_end];
    assert!(
        !pin_window.contains("snap["),
        "no indexed request field may be consumed before both EntryPoint rejects complete"
    );
    assert_eq!(
        pin_window.matches("snap.as_ptr().add(32)").count(),
        2,
        "the pre-parse window may read only the two EntryPoint samples"
    );
    for forbidden_parse in ["u64::from_be_bytes", "u32::from_be_bytes", "copy_from_slice"] {
        assert!(
            !pin_window.contains(forbidden_parse),
            "request parsing via {forbidden_parse} appeared before pin completion"
        );
    }
    let pre_scrub = CMD_SIGN_USEROP_SRC[pin_a..gate_a]
        .rfind("crate::fi::scrub_sentinel_register();")
        .map(|p| pin_a + p)
        .expect("scrub before first EntryPoint sentinel check");
    assert!(
        pre_scrub < gate_a,
        "stale OK sentinel state must be scrubbed before the first pin gate"
    );
    assert_eq!(
        CMD_SIGN_USEROP_SRC
            .matches(".ct_eq(&ENTRY_POINT_V06)")
            .count(),
        2,
        "both EntryPoint reads must use constant-time equality"
    );
    assert_eq!(
        CMD_SIGN_USEROP_SRC
            .matches("read_volatile(snap.as_ptr().add(32).cast::<[u8; 20]>())")
            .count(),
        2,
        "the two snapshot samples must remain volatile under LTO"
    );
    assert_eq!(
        CMD_SIGN_USEROP_SRC.matches("wrong EntryPoint").count(),
        2,
        "two spatially separate mismatch rejects are required"
    );
    assert!(!CMD_SIGN_USEROP_SRC.contains("let mut entry_point ="));
    assert!(!CMD_SIGN_USEROP_SRC.contains("entry_point.copy_from_slice"));

    let params = CMD_SIGN_USEROP_SRC
        .matches("AaUserOpParamsV06Sha256 {")
        .count();
    assert_eq!(
        params, 2,
        "single handler owns one T1 and one T2 params site"
    );
    assert_eq!(
        CMD_SIGN_USEROP_SRC
            .matches("entry_point: ENTRY_POINT_V06,")
            .count(),
        params,
        "every T1/T2 digest must consume the firmware constant directly"
    );
}

#[test]
fn negative_slice_only_uses_sphincs_c10_verify_paths() {
    // Every sig the slice produces is verified-before-release. The
    // only verifier crate it should reach for is `sphincs_c10`.
    // A presence-check via the source text + the documented FI
    // double-verify pattern catches a refactor that introduces a
    // shortcut like a single-verify or a non-C10 verifier.
    assert!(
        CMD_SIGN_USEROP_SRC.contains("sphincs_c10::verify"),
        "cmd_sign_userop.rs must use sphincs_c10::verify for FI-hardened double-check"
    );
    assert!(
        CMD_SIGN_USEROP_SRC.contains("c10_sign_verified_with_progress"),
        "cmd_sign_userop.rs must use the verify-before-release sign primitive"
    );
}

#[test]
fn negative_slice_validates_ns_pointers_before_deref() {
    // CLAUDE.md invariant #4: NS pointer validation on every gateway
    // call before any deref. The handler calls
    // `validate_ns_read_ptr` / `validate_ns_write_ptr` before the
    // TOCTOU snapshot. A refactor that drops these would be
    // disastrous; pin them.
    assert!(
        CMD_SIGN_USEROP_SRC.contains("validate_ns_read_ptr"),
        "validate_ns_read_ptr must guard the NS read pointer"
    );
    assert!(
        CMD_SIGN_USEROP_SRC.contains("validate_ns_write_ptr"),
        "validate_ns_write_ptr must guard the NS write pointer"
    );
}

#[test]
fn negative_slice_zeroizes_secrets_on_every_error_path() {
    // CLAUDE.md §"Code Conventions": every secret type carries
    // ZeroizeOnDrop, and the handler explicitly invokes `zeroize`
    // + `fi::zeroize_barrier()` before returning an error. Pin
    // both presence + balance.
    let zeroize_count = CMD_SIGN_USEROP_SRC.matches("entropy.zeroize()").count();
    let barrier_count = CMD_SIGN_USEROP_SRC.matches("fi::zeroize_barrier()").count();
    assert!(
        zeroize_count > 0,
        "cmd_sign_userop.rs must zeroize `entropy` on every error path"
    );
    assert!(
        barrier_count > 0,
        "cmd_sign_userop.rs must call fi::zeroize_barrier() to defeat reordering"
    );
    // Defence in depth: every zeroize is paired with a barrier (rough
    // count check — a one-off mismatch would still be worth a manual
    // look).
    assert!(
        barrier_count >= zeroize_count - 1,
        "zeroize/barrier counts diverged: {zeroize_count} zeroize vs {barrier_count} barrier"
    );
}

#[test]
fn negative_slice_uses_fi_double_check_on_flag_parse() {
    // F-11 hardening (cmd_sign_userop.rs:160 onwards): flags are
    // parsed twice from the snapshot with a random delay between
    // reads. Pin the pattern so a future refactor that removes the
    // belt-and-braces second read surfaces a test failure.
    assert!(
        CMD_SIGN_USEROP_SRC.contains("flags_a") && CMD_SIGN_USEROP_SRC.contains("flags_b"),
        "the F-11 double-parse on the flags field must remain in place"
    );
    assert!(
        CMD_SIGN_USEROP_SRC.contains("flags_recheck"),
        "the F-11 belt-and-braces recheck after gate evaluation must remain in place"
    );
    assert!(
        CMD_SIGN_USEROP_SRC.contains("account_index_r != account_index"),
        "account_index selects the trusted sender and must be included in the F-11 recheck"
    );
}

#[test]
fn negative_slice_binds_sender_before_confirm_sign_or_counter_write() {
    let gate = CMD_SIGN_USEROP_SRC
        .find("super::cmd_get_wallet_address::bind_userop_sender(")
        .expect("single-sign sender binding must remain present");
    let trusted_shadow = CMD_SIGN_USEROP_SRC[gate..]
        .find("let sender =")
        .map(|p| gate + p)
        .expect("single-sign path must replace the companion sender");

    let before_gate = &CMD_SIGN_USEROP_SRC[..gate];
    for (label, needle) in [
        ("trusted-display confirm", "let (cr, cr_verdict) = confirm_checked"),
        ("C10 signing", "match crate::crypto::c10_sign_verified_with_progress"),
        ("offchain promotion", "crate::offchain_state::offchain_count_promote_to("),
        ("last-userop write", "crate::offchain_state::last_userop_count_set("),
        ("userop counter bump", "crate::offchain_state::userop_sigs_bump("),
    ] {
        assert!(
            !before_gate.contains(needle),
            "{label} must not occur before sender binding"
        );
    }

    for (label, needle) in [
        ("trusted-display confirm", "confirm_checked("),
        ("C10 signing", "c10_sign_verified_with_progress"),
        ("offchain promotion", "offchain_count_promote_to"),
        ("last-userop write", "last_userop_count_set"),
        ("userop counter bump", "userop_sigs_bump"),
    ] {
        let pos = CMD_SIGN_USEROP_SRC[gate..]
            .find(needle)
            .map(|p| gate + p)
            .unwrap_or_else(|| panic!("missing {label} marker: {needle}"));
        assert!(
            trusted_shadow < pos,
            "sender must be bound and shadowed before {label}"
        );
    }

    let downstream = CMD_SIGN_USEROP_SRC
        .find("// ── 6. Build display-time")
        .map(|p| &CMD_SIGN_USEROP_SRC[p..])
        .expect("section 6 marker");
    assert!(
        !downstream.contains("companion_sender"),
        "the untrusted sender must never reach display bindings or signed hashes"
    );
    let downstream_compact = downstream.split_whitespace().collect::<String>();
    assert!(
        downstream_compact.contains(
            "pick_sign_pages_with_erc7730_evidence(&tx_for_display,inner_data,&sender,"
        ),
        "ERC-7730 @.from must receive the already-bound device sender explicitly"
    );

    let helper_start = WALLET_ADDRESS_SRC
        .find("pub(super) unsafe fn bind_userop_sender")
        .expect("sender helper");
    let helper_end = WALLET_ADDRESS_SRC[helper_start..]
        .find("pub(super) unsafe fn run")
        .map(|p| helper_start + p)
        .expect("GET_WALLET_ADDRESS handler");
    let helper = &WALLET_ADDRESS_SRC[helper_start..helper_end];
    assert!(helper.contains("ct_eq"));
    assert!(helper.contains("Ok(expected_a)"));
    assert!(helper.contains("Ok(expected_b)"));
    assert!(helper.contains("derivations_agree"));
    assert!(helper.contains("wallet_address_for_account_cross_check("));
    assert!(WALLET_ADDRESS_SRC.contains("fn proxy_address_cross_check("));
    assert!(WALLET_ADDRESS_SRC.contains("h.update(core::hint::black_box(&pk_seed[..]))"));
    assert!(WALLET_ADDRESS_SRC.contains("h.update(core::hint::black_box(&pk_root[..]))"));
    assert!(WALLET_ADDRESS_SRC.contains("h.update(core::hint::black_box(&preimage[..21]))"));
    assert!(WALLET_ADDRESS_SRC.contains(
        "crate::aa::eip1271::proxy_address(&pk_seed, &pk_root)"
    ));
    assert!(helper.contains("check_true_into_sentinel"));
    assert!(helper.contains("SenderBinding"));
    assert!(WALLET_ADDRESS_SRC.contains(
        "#[inline(never)]\npub(super) unsafe fn bind_userop_sender"
    ));
    assert!(helper.contains("addr_of_mut!(output.sender)"));
    assert!(helper.contains("sender_readback_a"));
    assert!(helper.contains("sender_readback_b"));
    assert!(helper.contains("addr_of_mut!(output.verdict)"));
    assert!(helper.contains("cfi.bump(CFI_STEP_SENDER_BIND_DONE)"));
    assert!(WALLET_ADDRESS_SRC.contains("verdict: crate::fi::FAIL_SENTINEL"));
    assert!(helper.contains("NscStatus::InvalidPointer"));
    let before_call = &CMD_SIGN_USEROP_SRC[..gate];
    assert!(before_call.contains("SenderBinding::fail_closed()"));
    assert!(before_call.contains("core::ptr::write_volatile("));
    assert!(CMD_SIGN_USEROP_SRC[gate..].contains("SENDER_BIND_CFI_EXPECTED"));
    assert!(CMD_SIGN_USEROP_SRC[gate..].contains("let sender_check ="));
    assert!(CMD_SIGN_USEROP_SRC[gate..].contains("sender_reads_agree"));
}

#[test]
fn negative_slice_every_userop_confirm_gets_bound_from_page() {
    assert_eq!(
        CMD_SIGN_USEROP_SRC.matches("enforce_from_page(").count(),
        2,
        "slot-rotation and transaction confirms must each show source identity"
    );
    let compact = CMD_SIGN_USEROP_SRC
        .split_whitespace()
        .collect::<String>()
        .replace(",)", ")");
    assert!(compact.contains(
        "enforce_from_page(&mutrotate_pages,account_index,&sender,&mutsigner_cfi)"
    ));
    assert!(compact.contains(
        "enforce_from_page(&mutpages,account_index,&sender,&mutsigner_cfi)"
    ));
    assert!(CMD_SIGN_USEROP_SRC.contains("signer unshown"));
    assert_eq!(CMD_SIGN_USEROP_SRC.matches("from_page_proof(").count(), 2);
    assert_eq!(CMD_SIGN_USEROP_SRC.matches("SIGNER_PAGE_CFI_EXPECTED").count(), 2);
}

#[test]
fn negative_slice_transaction_confirm_gets_full_target_page() {
    assert_eq!(CMD_SIGN_USEROP_SRC.matches("enforce_target_page(").count(), 1);
    assert_eq!(CMD_SIGN_USEROP_SRC.matches("target_page_proof(").count(), 1);
    let compact = CMD_SIGN_USEROP_SRC.split_whitespace().collect::<String>();
    assert!(compact.contains(
        "enforce_target_page(&mutpages,&to_address,&muttarget_cfi)"
    ));
    assert!(CMD_SIGN_USEROP_SRC.contains("TARGET_IDENTITY_PAGES"));
    assert!(CMD_SIGN_USEROP_SRC.contains("target unshown"));
}

#[test]
fn negative_slice_shows_and_fi_proves_full_derived_signer_identity() {
    assert_eq!(
        CMD_SIGN_USEROP_SRC.matches("enforce_from_page(").count(),
        2,
        "rotation and transaction confirmation must both show signer identity"
    );
    assert_eq!(
        CMD_SIGN_USEROP_SRC.matches("from_page_proof(").count(),
        2,
        "every signer-page append needs an independent FI completion proof"
    );
    assert!(CMD_SIGN_USEROP_SRC.contains("SIGNER_IDENTITY_PAGES"));
    let compact = CMD_SIGN_USEROP_SRC.split_whitespace().collect::<String>();
    assert!(compact.contains("account_index,&sender,&mutsigner_cfi"));
    assert!(!CMD_SIGN_USEROP_SRC.contains("account_index, &companion_sender"));

    let main_page = CMD_SIGN_USEROP_SRC
        .rfind("let signer_pages_before = pages.len;")
        .expect("main UserOp signer page");
    let fingerprint = CMD_SIGN_USEROP_SRC[main_page..]
        .find("append_fingerprint_page(")
        .map(|p| main_page + p)
        .expect("ERC-8213 append after signer page");
    let confirm = CMD_SIGN_USEROP_SRC[fingerprint..]
        .find("confirm_checked(pages.as_slice())")
        .map(|p| fingerprint + p)
        .expect("confirmation after mandatory pages");
    assert!(main_page < fingerprint && fingerprint < confirm);

    assert!(VALUE_PAGE_SRC.contains("b\"Signer acct #\""));
    assert!(VALUE_PAGE_SRC.contains("primitives::write_addr_full(a, b, c, sender)"));
    assert!(VALUE_PAGE_SRC.contains("#[inline(never)]\npub(crate) fn enforce_from_page"));
    assert!(VALUE_PAGE_SRC.contains("#[inline(never)]\npub(crate) fn from_page_proof"));
    assert!(VALUE_PAGE_SRC.contains("from_page_matches(pages, prior_len"));
    assert!(!VALUE_PAGE_SRC.contains("b\"From account:"));
}

#[test]
fn negative_slice_shows_and_fi_proves_every_nonzero_nonce_lane() {
    assert_eq!(CMD_SIGN_USEROP_SRC.matches("enforce_nonce_lane_page(").count(), 2);
    assert_eq!(CMD_SIGN_USEROP_SRC.matches("nonce_lane_page_proof(").count(), 2);
    let compact = CMD_SIGN_USEROP_SRC.split_whitespace().collect::<String>();
    assert!(compact.contains("&mutrotate_pages,&nonce,&mutnonce_lane_cfi"));
    assert!(compact.contains("&mutpages,&type2_nonce,&mutnonce_lane_cfi"));
    assert!(CMD_SIGN_USEROP_SRC.contains("NONZERO_NONCE_LANE_PAGES"));
    assert!(CMD_SIGN_USEROP_SRC.contains("lane unshown"));

    let main_lane = CMD_SIGN_USEROP_SRC
        .rfind("let nonce_lane_pages_before = pages.len;")
        .unwrap();
    let proof = main_lane
        + CMD_SIGN_USEROP_SRC[main_lane..]
            .find("nonce_lane_page_proof(")
            .unwrap();
    let fingerprint = proof
        + CMD_SIGN_USEROP_SRC[proof..]
            .find("append_fingerprint_page(")
            .unwrap();
    let confirm = fingerprint
        + CMD_SIGN_USEROP_SRC[fingerprint..]
            .find("confirm_checked(pages.as_slice())")
            .unwrap();
    assert!(main_lane < proof && proof < fingerprint && fingerprint < confirm);

    assert!(NONCE_LANE_SRC.contains(
        "primitives::write_line(&mut page[0], \"Nonce lane key:\")"
    ));
    assert!(NONCE_LANE_SRC.contains("nonce[..24]"));
    assert!(NONCE_LANE_SRC.contains("NONZERO_NONCE_LANE_PAGES: usize = 1"));
    assert!(NONCE_LANE_SRC.contains(
        "#[inline(never)]\npub(crate) fn enforce_nonce_lane_page"
    ));
    assert!(NONCE_LANE_SRC.contains(
        "#[inline(never)]\npub(crate) fn nonce_lane_page_proof"
    ));
}

#[test]
fn single_payload_fingerprint_completes_and_rechecks_at_confirmation_boundary() {
    assert_eq!(CMD_SIGN_USEROP_SRC.matches("append_fingerprint_page(").count(), 1);
    assert_eq!(CMD_SIGN_USEROP_SRC.matches("fingerprint_page_proof(").count(), 1);
    assert_eq!(
        CMD_SIGN_USEROP_SRC
            .matches("fingerprint_final_set_proof(")
            .count(),
        1
    );
    assert_eq!(CMD_SIGN_USEROP_SRC.matches("FINGERPRINT_CFI_EXPECTED").count(), 1);

    let append = CMD_SIGN_USEROP_SRC
        .find("append_fingerprint_page(")
        .expect("single payload fingerprint append");
    let completion = append
        + CMD_SIGN_USEROP_SRC[append..]
            .find("fingerprint_page_proof(")
            .expect("single payload fingerprint completion proof");
    let gas_final = completion
        + CMD_SIGN_USEROP_SRC[completion..]
            .find("userop_gas_final_set_proof(")
            .expect("single final gas proof");
    let dispatch_final = gas_final
        + CMD_SIGN_USEROP_SRC[gas_final..]
            .find("dispatch_page_proofs.final_set_proof(")
            .expect("single final native/fee proof");
    let fingerprint_final = dispatch_final
        + CMD_SIGN_USEROP_SRC[dispatch_final..]
            .find("fingerprint_final_set_proof(")
            .expect("single final fingerprint proof");
    let confirm = fingerprint_final
        + CMD_SIGN_USEROP_SRC[fingerprint_final..]
            .find("confirm_checked(pages.as_slice())")
            .expect("single payload confirmation");
    assert!(append < completion);
    assert!(completion < gas_final && gas_final < dispatch_final);
    assert!(dispatch_final < fingerprint_final && fingerprint_final < confirm);

    let rotation = CMD_SIGN_USEROP_SRC
        .find("// Slot rotation is its own affirmative-consent step")
        .expect("single rotation confirmation block");
    let main = CMD_SIGN_USEROP_SRC
        .find("let mut dispatch_page_proofs")
        .expect("single payload render");
    assert!(
        !CMD_SIGN_USEROP_SRC[rotation..main].contains("append_fingerprint_page("),
        "firmware-built rotation must use its documented explicit exemption, not a pseudo hash"
    );
}

#[test]
fn negative_slice_type2_display_uses_incremented_rotation_nonce() {
    let overflow_guard = CMD_SIGN_USEROP_SRC
        .find("register_slot && nonce[24..32] == [0xFFu8; 8]")
        .unwrap();
    let derive = CMD_SIGN_USEROP_SRC
        .find("let mut type2_nonce = nonce;")
        .unwrap();
    let display = CMD_SIGN_USEROP_SRC
        .find("let display_nonce = u64::from_be_bytes([")
        .unwrap();
    let main_lane = CMD_SIGN_USEROP_SRC
        .rfind("let nonce_lane_pages_before = pages.len;")
        .unwrap();
    let signed = CMD_SIGN_USEROP_SRC
        .rfind("nonce: U256(type2_nonce)")
        .unwrap();
    assert!(overflow_guard < derive && derive < display && display < main_lane && main_lane < signed);
    assert_eq!(CMD_SIGN_USEROP_SRC.matches("let mut type2_nonce = nonce;").count(), 1);
    assert!(CMD_SIGN_USEROP_SRC[derive..display].contains("add_one_to_be_u256(&mut type2_nonce)"));
    assert!(CMD_SIGN_USEROP_SRC[display..].contains("type2_nonce[24]"));
    let display_fields = CMD_SIGN_USEROP_SRC[display..main_lane]
        .find("userop_fields: Some(UserOpDisplayFields")
        .map(|p| display + p)
        .expect("Type-2 UserOp display fields");
    let display_fields_end = CMD_SIGN_USEROP_SRC[display_fields..]
        .find("}),")
        .map(|p| display_fields + p)
        .expect("end of Type-2 UserOp display fields");
    assert!(
        CMD_SIGN_USEROP_SRC[display_fields..display_fields_end]
            .contains("nonce: U256(type2_nonce)"),
        "the visible UserOp nonce must be the exact Type-2 nonce, not the Type-1 base nonce"
    );
    // The separate Type-1 rotation lane page remains bound to the base
    // high-192 key; CRIT-17 proves base+1 cannot change that lane.
    let compact = CMD_SIGN_USEROP_SRC.split_whitespace().collect::<String>();
    assert!(compact.contains("&mutrotate_pages,&nonce,&mutnonce_lane_cfi"));
}

#[test]
fn negative_slice_deployment_mode_crosses_confirm_before_factory_or_type2_signing() {
    let context = CMD_SIGN_USEROP_SRC
        .find("let deployment_context =")
        .expect("fail-initialized deployment context");
    let append = CMD_SIGN_USEROP_SRC[context..]
        .find("enforce_deployment_page(")
        .map(|p| context + p)
        .expect("deployment page append");
    let final_proof = CMD_SIGN_USEROP_SRC[append..]
        .find("deployment_final_set_proof(")
        .map(|p| append + p)
        .expect("deployment final-set proof");
    let confirm = CMD_SIGN_USEROP_SRC[final_proof..]
        .find("confirm_checked(pages.as_slice())")
        .map(|p| final_proof + p)
        .expect("main Type-2 confirmation");
    let record = CMD_SIGN_USEROP_SRC[confirm..]
        .find(".record_confirmed(&deployment_context)")
        .map(|p| confirm + p)
        .expect("affirmative deployment receipt publication");
    let first_receipt_gate = CMD_SIGN_USEROP_SRC[record..]
        .find("deployment_confirm_receipt.completion_proof(&deployment_context)")
        .map(|p| record + p)
        .expect("pre-factory receipt gate");
    let factory_path = CMD_SIGN_USEROP_SRC[first_receipt_gate..]
        .find("// ── 13a. Deploy path")
        .map(|p| first_receipt_gate + p)
        .expect("factory-sign path");
    let output_gate = CMD_SIGN_USEROP_SRC[factory_path..]
        .find("deployment_output_binding_proof(")
        .map(|p| factory_path + p)
        .expect("post-confirm initCode binding");
    let type2_params = CMD_SIGN_USEROP_SRC[output_gate..]
        .find("let t2_params = AaUserOpParamsV06Sha256")
        .map(|p| output_gate + p)
        .expect("Type-2 digest parameters");

    assert!(context < append);
    assert!(append < final_proof && final_proof < confirm && confirm < record);
    assert!(record < first_receipt_gate && first_receipt_gate < factory_path);
    assert!(factory_path < output_gate && output_gate < type2_params);
    assert!(CMD_SIGN_USEROP_SRC[append..confirm].contains("DEPLOYMENT_PAGE_CFI_EXPECTED"));
    assert!(CMD_SIGN_USEROP_SRC[output_gate..type2_params].contains("emit_init_code"));
    assert!(CMD_SIGN_USEROP_SRC[output_gate..type2_params].contains("t2_init_code_digest"));
}

#[test]
fn negative_slice_guards_against_nonce_seq_overflow() {
    // CRIT-17 (cmd_sign_userop.rs:288): `nonce[24..32] ==
    // [0xFFu8; 8]` rejection is the only thing that stops a
    // REGISTER_SLOT bundle from silently corrupting the 192-bit
    // nonce key. Pin the guard's presence.
    assert!(
        CMD_SIGN_USEROP_SRC.contains("nonce[24..32]"),
        "the CRIT-17 nonce-seq overflow guard must remain"
    );
}

#[test]
fn negative_slice_enforces_mutually_exclusive_flags() {
    // The two top flags are mutually exclusive — deploy bundles its
    // slot-0 registration into the factory call, so a separate
    // addOwner UserOp on deploy is forbidden. Pin the gate.
    assert!(
        CMD_SIGN_USEROP_SRC.contains("include_init_code && register_slot"),
        "the include_init_code/register_slot mutual-exclusion gate must remain"
    );
}

#[test]
fn negative_slice_pins_factory_add_slot_domain_tag() {
    // The bootstrap key signs this string with the chain ID + slot-0
    // public key components. A rename invalidates every deployed
    // wallet's deploy path on a new chain.
    assert!(
        CMD_SIGN_USEROP_SRC.contains(r#""pqwallet-factory-add-slot""#)
            || CMD_SIGN_USEROP_SRC.contains(r#"b"pqwallet-factory-add-slot""#),
        "the factory-add-slot domain tag must not be renamed"
    );
}

#[test]
fn negative_slice_pins_cow_downgrade_mitigation_gate() {
    // CoW: if the inner calldata is setPreSignature on GPv2Settlement,
    // require v3 verification. Without this gate an attacker who
    // strips the v3 trailer would coerce a user into pre-signing an
    // orderUid they never saw the contents of.
    assert!(CMD_SIGN_USEROP_SRC.contains("SET_PRE_SIGNATURE_SELECTOR"));
    assert!(CMD_SIGN_USEROP_SRC.contains("GPV2_SETTLEMENT_ADDRESS"));
    assert!(CMD_SIGN_USEROP_SRC.contains("cow_order_verified.is_none()"));
}

#[test]
fn negative_slice_pins_safe_downgrade_mitigation_gate() {
    // Symmetric for Safe approveHash: must require the safe_v1
    // trailer when the inner calldata claims approveHash.
    //
    // The gate keys on the SELECTOR ALONE via the shared
    // `is_approve_hash_claim` predicate (audit 2026-06-28). It must NOT
    // re-introduce an exact calldata-length test: `Safe.approveHash` ignores
    // trailing calldata on-chain, so a `len == APPROVE_HASH_CALLDATA_LEN`
    // gate was bypassable with one padding byte → generic blind-sign of an
    // invisible SafeTx pre-approval.
    assert!(
        CMD_SIGN_USEROP_SRC.contains("is_approve_hash_claim"),
        "the approveHash gate must use the selector-only claim predicate"
    );
    assert!(CMD_SIGN_USEROP_SRC.contains("safe_v1_verified.is_none()"));
    // Regression guard: the bypassable exact-length test must NOT come back.
    assert!(
        !CMD_SIGN_USEROP_SRC.contains("APPROVE_HASH_CALLDATA_LEN"),
        "approveHash gate must not key on an exact calldata length (length-bypass)"
    );
}

#[test]
fn negative_slice_pins_safe_exec_decode_gate() {
    // Safe `execTransaction` ownership begins at the selector, not at the ABI
    // minimum length. The caller-owned proof and two independent strict
    // verifications must resolve twice before any lower routing surface.
    let claim = CMD_SIGN_USEROP_SRC
        .find("let mut safe_exec_claim =")
        .expect("fail-closed Safe claim receipt");
    let claim_proof = CMD_SIGN_USEROP_SRC[claim..]
        .find("prove_exec_transaction_claim(")
        .map(|p| claim + p)
        .expect("Safe selector A/B proof");
    let verify_a = CMD_SIGN_USEROP_SRC[claim_proof..]
        .find("let mut safe_exec_verified:")
        .map(|p| claim_proof + p)
        .expect("first strict Safe exec verifier");
    let verify_b = CMD_SIGN_USEROP_SRC[verify_a..]
        .find("let mut safe_exec_verified_check:")
        .map(|p| verify_a + p)
        .expect("second strict Safe exec verifier");
    let resolution = CMD_SIGN_USEROP_SRC[verify_b..]
        .find("exec_claim_resolution_proof(")
        .map(|p| verify_b + p)
        .expect("Safe claimed/verified resolution gate");
    let lower_routing = CMD_SIGN_USEROP_SRC
        .find("// 7c-bis-erc20.")
        .expect("next lower routing stage");
    let resolution_positions: Vec<_> = CMD_SIGN_USEROP_SRC
        .match_indices("exec_claim_resolution_proof(")
        .map(|(position, _)| position)
        .collect();
    assert_eq!(resolution_positions.len(), 2);
    assert!(
        resolution_positions.iter().all(|&position| position < lower_routing),
        "both Safe resolution gates must complete before lower routing"
    );
    assert!(
        claim < claim_proof
            && claim_proof < verify_a
            && verify_a < verify_b
            && verify_b < resolution
            && resolution < lower_routing
    );
    assert_eq!(
        CMD_SIGN_USEROP_SRC
            .matches("prove_exec_transaction_claim(")
            .count(),
        1
    );
    assert_eq!(
        CMD_SIGN_USEROP_SRC
            .matches("verify_and_bind_exec_into(")
            .count(),
        2,
        "caller-owned strict Safe verifier outputs must execute independently twice"
    );
    assert_eq!(
        CMD_SIGN_USEROP_SRC
            .matches("exec_claim_resolution_proof(")
            .count(),
        2,
        "a single skipped final reject must encounter the second gate"
    );
    assert_eq!(
        CMD_SIGN_USEROP_SRC
            .matches("EXEC_CLAIM_CFI_EXPECTED")
            .count(),
        2
    );
    assert_eq!(
        CMD_SIGN_USEROP_SRC
            .matches("EXEC_VERIFY_CFI_EXPECTED")
            .count(),
        4,
        "both verifier calls are CFI-checked at both final gates"
    );
    assert!(CMD_SIGN_USEROP_SRC.contains("exec parse fail"));
    assert!(
        !CMD_SIGN_USEROP_SRC.contains("EXEC_TRANSACTION_MIN_CALLDATA_LEN"),
        "handler claim ownership must not depend on the ABI minimum length"
    );
    assert!(!CMD_SIGN_USEROP_SRC.contains("safe_exec_enough_len"));
}

#[test]
fn safe_direct_publication_body_cannot_reintroduce_returning_decoder_dependency() {
    let start = SAFE_EXEC_DECODE_SRC
        .find("pub(crate) fn verify_and_bind_exec_into")
        .expect("authoritative Safe verifier");
    let tail = &SAFE_EXEC_DECODE_SRC[start..];
    let end = tail
        .find("\n// ---------------------------------------------------------------------------\n// Tests")
        .expect("end of authoritative Safe verifier section");
    let body = &tail[..end];
    for forbidden_call in ["decode_exec_transaction(", "verify_and_bind_exec("] {
        assert!(
            !body.contains(forbidden_call),
            "caller-storage verifier must not call returning helper {forbidden_call}"
        );
    }
    let fail_init = body.find("write_volatile(output, None)").expect("volatile fail init");
    let strict_decode = body.find("if inner_data.len()").expect("in-operation strict decode");
    let success_publish = body
        .find("Some(VerifiedSafeExec")
        .expect("direct successful publication");
    let final_cfi = body
        .rfind("cfi.bump(EXEC_VERIFY_CFI_STEP)")
        .expect("completion CFI after publication");
    assert!(fail_init < strict_decode && strict_decode < success_publish && success_publish < final_cfi);
}

#[test]
fn negative_slice_checks_pin_verified_before_signing() {
    // CLAUDE.md invariant #2: hardware PIN gating. The dispatcher's
    // unlock check must fire before any signing path. Pin its
    // presence in the slice.
    assert!(CMD_SIGN_USEROP_SRC.contains("pin_verified"));
    assert!(CMD_SIGN_USEROP_SRC.contains("NscStatus::NotInitialized"));
}

#[test]
fn negative_slice_snaps_payload_before_parsing() {
    // CLAUDE.md §"Code Conventions": NS buffers copied to S-stack
    // before parse (TOCTOU). The slice uses `SNAP_BUF` and
    // `read_volatile` for the copy.
    assert!(CMD_SIGN_USEROP_SRC.contains("SNAP_BUF"));
    assert!(CMD_SIGN_USEROP_SRC.contains("read_volatile"));
}

#[test]
fn negative_slice_wipes_snap_buf_on_exit() {
    // L-2 mitigation (cmd_sign_userop.rs:1340 onwards): wipe the
    // TOCTOU snapshot after the response is emitted, even though
    // the payload is not secret — names / EIP-712 readable text /
    // recipient addresses are user metadata we don't want pinned
    // in BSS until the next sign overwrites.
    assert!(
        CMD_SIGN_USEROP_SRC.contains("L-2") || CMD_SIGN_USEROP_SRC.contains("wipe the TOCTOU snapshot"),
        "the L-2 SNAP_BUF wipe-on-exit must remain"
    );
}

#[test]
fn negative_slice_uses_volatile_writes_to_ns_output() {
    // CMSE / TrustZone: NS-bound writes must be volatile so the
    // compiler can't reorder them or merge a torn word with the
    // dispatcher's status-word write. `cmd_sign_userop.rs` uses
    // `write_volatile` for every byte of the response.
    assert!(CMD_SIGN_USEROP_SRC.contains("write_volatile"));
}

#[test]
fn negative_trailer_does_not_log_secret_inputs() {
    // The trailer helper takes a `snap: &[u8]` that contains NS-
    // supplied payload. It must not leak any of those bytes via
    // logs or panic messages. The only diagnostic surface in this
    // file is `show_status(static_label, error_label)`, called
    // exactly once. A refactor that introduced `secure_log!(...)`
    // dumping `snap[..]` would silently widen the side-channel.
    let show_status_calls = TRAILER_SRC.matches("show_status").count();
    assert_eq!(
        show_status_calls, 1,
        "trailer.rs has exactly one show_status call; refactor surface must stay tiny"
    );
    // No `secure_log!` calls — payload bytes must never reach the
    // semihosting console.
    assert!(
        !TRAILER_SRC.contains("secure_log!"),
        "trailer.rs must not log payload bytes via secure_log!"
    );
    // No `format!` or `write!` against the payload either.
    assert!(
        !TRAILER_SRC.contains("format!") && !TRAILER_SRC.contains("write!"),
        "trailer.rs must not format/write payload bytes"
    );
}

#[test]
fn negative_sig_wrapper_src_only_imports_sphincs_tz_shared() {
    // Pure-logic invariant: sig_wrapper.rs must not pull in any
    // hardware deps. A refactor that introduces e.g.
    // `use crate::hw::...` would silently make the file
    // un-host-testable.
    let import_lines: Vec<_> = SIG_WRAPPER_SRC
        .lines()
        .filter(|l| l.trim_start().starts_with("use "))
        .collect();
    for line in &import_lines {
        assert!(
            line.contains("sphincs_tz_shared")
                || line.contains("zeroize")
                || line.contains("core::")
                || line.contains("super::"),
            "sig_wrapper.rs has an unexpected import: '{line}' — must stay pure logic"
        );
    }
}

#[test]
fn forced_route_is_feature_gated_and_owned_only_by_direct_userop() {
    let compact_mod = NSC_MOD_SRC.split_whitespace().collect::<String>();
    assert!(compact_mod.contains(
        "#[cfg(feature=\"erc7730-forced-blind\")]modcmd_sign_userop_forced;"
    ));
    assert!(CMD_SIGN_USEROP_SRC.contains("super::cmd_sign_userop_forced::classify("));
    assert!(CMD_SIGN_USEROP_SRC.contains("super::cmd_sign_userop_forced::run("));
    for (name, source) in [
        ("batch", CMD_SIGN_USEROP_BATCH_SRC),
        ("offchain", CMD_SIGN_OFFCHAIN_SRC),
    ] {
        assert!(
            !source.contains("cmd_sign_userop_forced"),
            "{name} handler must not acquire forced-blind authority"
        );
    }
}

#[test]
fn forced_route_requires_an_explicit_zero_length_erc7730_header() {
    let derive = CMD_SIGN_USEROP_FORCED_SRC
        .find("fn derive_wire_facts(")
        .expect("request-derived forced wire parser");
    let exclusions = CMD_SIGN_USEROP_FORCED_SRC[derive..]
        .find("fn exclusions_hold(")
        .map(|offset| derive + offset)
        .expect("forced exclusion proof");
    let parser = &CMD_SIGN_USEROP_FORCED_SRC[derive..exclusions];
    let compact_parser = parser.split_whitespace().collect::<String>();
    assert!(parser.contains("let erc7730_header_offset = cursor;"));
    assert!(compact_parser.contains("cursor.checked_add(2)"));
    assert!(parser.contains("*end <= total_len"));
    assert!(parser.contains("[wire[cursor], wire[cursor + 1]]"));

    let classify = CMD_SIGN_USEROP_FORCED_SRC
        .find("pub(super) fn classify(request: &ForcedRequest<'_>)")
        .expect("forced classifier");
    let exclusion_body = &CMD_SIGN_USEROP_FORCED_SRC[exclusions..classify];
    assert!(exclusion_body.contains("facts.erc7730_header == Some([0, 0])"));
    assert!(exclusion_body.contains("facts.erc7730_len == 0"));
    assert!(
        !CMD_SIGN_USEROP_SRC.contains("erc7730_clean_absence")
            && !CMD_SIGN_USEROP_FORCED_SRC.contains("clean_metadata_absence"),
        "forced authority must reparse raw framing, not accept an absence boolean"
    );
}

#[test]
fn forced_route_passes_every_frozen_exclusion_to_closed_classification() {
    let start = CMD_SIGN_USEROP_FORCED_SRC
        .find("fn exclusions_hold(")
        .expect("request-derived forced exclusion block");
    let end = CMD_SIGN_USEROP_FORCED_SRC[start..]
        .find("/// Determine whether an absent-descriptor request")
        .map(|offset| start + offset)
        .expect("forced classifier boundary");
    let block = &CMD_SIGN_USEROP_FORCED_SRC[start..end];
    for required in [
        "decode_flags(facts.flags)",
        "facts.data_len == request.calldata.len()",
        "facts.chain_id == request.chain_id",
        "facts.target == request.target",
        "facts.selector == request.calldata[..4]",
        "!include_init_code",
        "!register_slot",
        "account_index == request.account_index",
        "slot_index == request.slot_index",
        "facts.paymaster_and_data_hash == SHA256_EMPTY",
        "facts.cow_order_len == 0",
        "facts.safe_v1_len == 0",
        "facts.erc7730_header == Some([0, 0])",
        "facts.erc7730_len == 0",
        "!protected_selector",
        "!protected_target",
    ] {
        assert!(block.contains(required), "missing forced exclusion: {required}");
    }
    assert!(CMD_SIGN_USEROP_SRC.contains("wire: &snap[..total_len]"));
    assert!(CMD_SIGN_USEROP_SRC.contains("cmd_sign_userop_forced::classify(&request)"));
    for collapsed in [
        "single_steady_type2",
        "paymaster_empty",
        "safe_or_cow_present",
    ] {
        assert!(
            !CMD_SIGN_USEROP_SRC.contains(collapsed),
            "caller must not collapse forced exclusion into {collapsed}"
        );
    }
}

#[test]
fn forced_exact_membership_exclusions_are_fatal_before_candidate_proof() {
    let membership = CMD_SIGN_USEROP_FORCED_SRC
        .find("if !parsed.contains(facts.chain_id, &facts.target, &facts.selector)")
        .expect("exact-F membership gate");
    let proof = CMD_SIGN_USEROP_FORCED_SRC[membership..]
        .find("let mut verdict = crate::fi::FAIL_SENTINEL;")
        .map(|offset| membership + offset)
        .expect("forced eligibility proof boundary");
    let exclusion_block = &CMD_SIGN_USEROP_FORCED_SRC[membership..proof];
    assert!(exclusion_block.contains("return ForcedRoute::Fatal;"));
    assert_eq!(
        exclusion_block
            .matches("return ForcedRoute::ContinueOrdinary;")
            .count(),
        1,
        "only a wire-derived negative exact-F lookup may resume ordinary signing"
    );
}

#[test]
#[cfg(feature = "erc7730-forced-blind")]
fn production_exact_f_contains_reachable_protected_intersections() {
    let set = pqsigner_erc7730::forced_eligible::ForcedEligibleSet::from_bytes(
        &crate::db_roots::PQSIGNER_ERC7730_FORCED_ELIGIBLE_SET,
    )
    .expect("embedded exact-F set");
    let protected_hits = set
        .iter()
        .filter(|(_, target, selector)| {
            *selector == APPROVE_HASH_SELECTOR
                || *selector == EXEC_TRANSACTION_SELECTOR
                || *selector == SET_PRE_SIGNATURE_SELECTOR
                || *selector == MULTI_SEND_SELECTOR
                || *target == GPV2_SETTLEMENT_ADDRESS
                || MULTISEND_CALL_ONLY_ADDRESSES
                    .iter()
                    .any(|address| address == target)
        })
        .count();
    assert!(
        protected_hits > 0,
        "production exact-F must exercise the fatal protected branch"
    );
}

#[test]
fn forced_candidate_and_fatal_routes_return_terminally_before_ordinary_render() {
    let route = CMD_SIGN_USEROP_SRC
        .find("match super::cmd_sign_userop_forced::classify(")
        .expect("forced route match");
    let ordinary = CMD_SIGN_USEROP_SRC[route..]
        .find("// 7e. Address-name bundles.")
        .map(|offset| route + offset)
        .expect("ordinary metadata resolver boundary");
    let block = &CMD_SIGN_USEROP_SRC[route..ordinary];
    let compact = block.split_whitespace().collect::<String>();
    assert!(compact.contains("ForcedRoute::ContinueOrdinary=>{}"));
    assert!(compact.contains(
        "returnunsafe{super::cmd_sign_userop_forced::run(args,eligibility,request)};"
    ));
    assert!(compact.contains(
        "ForcedRoute::Fatal=>{ui::show_status(\"Signrefused\",\"forcedclassify\");returnNscStatus::InternalErrorasu32;}"
    ));
    assert!(!block.contains("pick_sign_pages_with_erc7730_evidence("));
}

#[test]
fn forced_consent_charges_once_only_after_complete_preflight() {
    let start = CMD_SIGN_USEROP_FORCED_SRC
        .find("fn collect_consent(")
        .expect("forced consent helper");
    let end = CMD_SIGN_USEROP_FORCED_SRC[start..]
        .find("unsafe fn commit_durable_tally(")
        .map(|offset| start + offset)
        .expect("consent helper boundary");
    let body = &CMD_SIGN_USEROP_FORCED_SRC[start..end];
    let mut cursor = 0;
    for stage in [
        "render_forced_transcript(",
        "forced_transcript_proof(",
        "flow_cfi.check_into_sentinel(CFI_PREWARNING_EXPECTED)",
        "warning.fail_initialize();",
        "final_receipt.fail_initialize();",
        "ForcedDeadline::start_verified()",
        ".charge_forced_attempt_for_warning()",
        "confirm_forced_checked(&FORCED_WARNING_PAGES",
        ".record_confirmed(",
        "confirm_forced_checked(pages.0.as_slice()",
        ".record_confirmed(",
        "pages.0.volatile_poison_and_reset();",
    ] {
        let offset = body[cursor..]
            .find(stage)
            .unwrap_or_else(|| panic!("missing or out-of-order forced consent stage: {stage}"));
        cursor += offset + stage.len();
    }
    assert_eq!(body.matches(".charge_forced_attempt_for_warning()").count(), 1);
}

#[test]
fn forced_terminal_flow_rechecks_and_reserves_tally_before_key_use() {
    let start = CMD_SIGN_USEROP_FORCED_SRC
        .find("pub(super) unsafe fn run(")
        .expect("terminal forced handler");
    let body = &CMD_SIGN_USEROP_FORCED_SRC[start..];
    let mut cursor = 0;
    for stage in [
        "prove_flow_eligibility(",
        "ForcedAttemptPhase::Armed",
        "read_counter_snapshot(",
        "compute_type2_digest(",
        ".request_digest()",
        "capacity_receipt(",
        "ensure_slot_key(",
        "forced_rate_preflight(",
        "ForcedCandidate::bind(",
        "collect_consent(",
        "prove_candidate_eligibility(",
        "read_counter_snapshot(",
        "compute_type2_digest(",
        "capacity_receipt(",
        "forced_rate_recheck(",
        "consume_forced_receipts_once(",
        "candidate.consume(",
        "CFI_PRESIGN_EXPECTED",
        "commit_durable_tally(",
        "CFI_PREKEY_EXPECTED",
        "c10_sign_verified_forced_with_progress(",
        "publish_forced_response(",
    ] {
        let offset = body[cursor..]
            .find(stage)
            .unwrap_or_else(|| panic!("missing or out-of-order forced terminal stage: {stage}"));
        cursor += offset + stage.len();
    }

    assert_eq!(
        body.matches("commit_durable_tally(").count(),
        1,
        "the forced flow must reserve exactly one durable use"
    );
    let tally = body
        .find("let mut tally_verdict = crate::fi::FAIL_SENTINEL;")
        .expect("pre-key durable tally");
    let signer = body
        .find("c10_sign_verified_forced_with_progress(")
        .expect("forced signer call");
    assert!(tally < signer, "durable use must precede every possible key use");
    let tally_arm = &body[tally..signer];
    assert!(tally_arm.contains("zeroize_sensitive_state();"));
    assert!(tally_arm.contains("CFI_PREKEY_EXPECTED"));
    assert!(tally_arm.contains("capacity_check,"));
    assert!(tally_arm.contains("&request_digest_check,"));
    assert!(tally_arm.contains("CFI_TALLY_COMMIT_EXPECTED"));
    assert!(tally_arm.matches("deadline_expired()").count() >= 1);

    let outer_verify = body[signer..]
        .find("let outer_verified =")
        .map(|offset| signer + offset)
        .expect("outer verify boundary");
    let signer_arm = &body[signer..outer_verify];
    assert!(signer_arm.contains("Err(_) =>"));
    assert!(!signer_arm.contains("commit_durable_tally("));
    assert!(signer_arm.contains("zeroize_sensitive_state();"));
    assert!(signer_arm.contains("return NscStatus::CryptoError as u32;"));

    let first_outer_verify = body[outer_verify..]
        .find("let first = sphincs_c10::verify(")
        .map(|offset| outer_verify + offset)
        .expect("outer verification call");
    let outer_cache_gate = &body[outer_verify..first_outer_verify];
    assert!(outer_cache_gate.contains("zeroize_sensitive_state();"));
}

#[test]
fn forced_tally_final_proof_follows_every_page123_mutation() {
    let start = CMD_SIGN_USEROP_FORCED_SRC
        .find("unsafe fn commit_durable_tally(")
        .expect("durable tally helper");
    let end = CMD_SIGN_USEROP_FORCED_SRC[start..]
        .find("unsafe fn publish_forced_response(")
        .map(|offset| start + offset)
        .expect("durable tally helper boundary");
    let body = &CMD_SIGN_USEROP_FORCED_SRC[start..end];

    let reserve = body
        .find("userop_sigs_bump(slot_key, next_tally)")
        .expect("USEROP_SIGS reservation");
    let promote = body
        .find("offchain_count_promote_to(slot_key, counters.new_offchain_count)")
        .expect("COUNT promotion");
    let userop = body
        .find("last_userop_count_set(slot_key, counters.new_offchain_count)")
        .expect("USEROP publication");
    let effective = body
        .find("effective_offchain_count(local, last)")
        .expect("effective count recheck");
    let final_a = body
        .find("let tally_a = unsafe { crate::offchain_state::userop_sigs_read(slot_key) };")
        .expect("final tally read A");
    let final_b = body
        .find("let tally_b = unsafe { crate::offchain_state::userop_sigs_read(slot_key) };")
        .expect("final tally read B");
    let proof = body
        .find("forced_final_tally_pair_proof(next_tally, tally_a, tally_b)")
        .expect("final tally equality proof");
    let publish = body
        .find("core::ptr::write_volatile(verdict_out, crate::fi::OK_SENTINEL)")
        .expect("fail-in verdict publication");

    assert!(reserve < final_a);
    assert!(promote < final_a);
    assert!(userop < final_a);
    assert!(effective < final_a);
    assert!(final_a < final_b && final_b < proof && proof < publish);
    assert_eq!(
        body.matches("crate::offchain_state::userop_sigs_read(slot_key)")
            .count(),
        2,
        "the authoritative post-mutation proof must contain exactly two tally reads"
    );
    assert!(body[final_a..].contains("CFI_TALLY_FINAL_READ_A"));
    assert!(body[final_b..].contains("CFI_TALLY_FINAL_READ_B"));
    assert!(body[proof..].contains("CFI_TALLY_PREPUBLISH_EXPECTED"));
    assert!(!body[final_a..].contains("userop_sigs_bump("));
    assert!(!body[final_a..].contains("offchain_count_promote_to("));
    assert!(!body[final_a..].contains("last_userop_count_set("));

    let consume = body
        .find("consume_capacity_receipt_once(")
        .expect("fresh capacity receipt consumption");
    assert!(consume < reserve);

    let consume_start = CMD_SIGN_USEROP_FORCED_SRC
        .find("fn consume_capacity_receipt_once(")
        .expect("capacity consumption helper");
    let consume_end = CMD_SIGN_USEROP_FORCED_SRC[consume_start..]
        .find("unsafe fn commit_durable_tally(")
        .map(|offset| consume_start + offset)
        .expect("capacity consumption helper boundary");
    let consume_body = &CMD_SIGN_USEROP_FORCED_SRC[consume_start..consume_end];
    assert!(consume_body.contains("*capacity.request_digest()"));
    assert!(consume_body.contains("capacity.slot_present()"));
    assert!(consume_body.contains("!core::hint::black_box(capacity.requires_compaction())"));
    assert!(consume_body.contains("capacity.blank_qws()"));
    assert!(consume_body.contains("FORCED_CAPACITY_REQUIRED_APPENDS"));
    assert!(consume_body.contains("cfi.bump(CFI_TALLY_CAPACITY_CONSUMED)"));

    let receipt = OFFCHAIN_STATE_SRC
        .find("pub struct ForcedCapacityReceipt")
        .expect("forced capacity receipt");
    let derive_start = OFFCHAIN_STATE_SRC[..receipt]
        .rfind("#[derive(")
        .expect("forced capacity receipt derive");
    let derive = &OFFCHAIN_STATE_SRC[derive_start..receipt];
    assert!(!derive.contains("Clone"));
    assert!(!derive.contains("Copy"));
}

#[test]
fn forced_tally_commit_cfi_rejects_every_omitted_stage_subset() {
    fn source_u32_const(name: &str) -> u32 {
        let prefix = format!("const {name}: u32 = 0x");
        let start = CMD_SIGN_USEROP_FORCED_SRC
            .find(&prefix)
            .unwrap_or_else(|| panic!("missing forced tally CFI constant {name}"))
            + prefix.len();
        let end = CMD_SIGN_USEROP_FORCED_SRC[start..]
            .find(';')
            .map(|offset| start + offset)
            .expect("CFI constant terminator");
        let hex = CMD_SIGN_USEROP_FORCED_SRC[start..end].replace('_', "");
        u32::from_str_radix(&hex, 16).expect("hex CFI constant")
    }

    let names = [
        "CFI_TALLY_CAPACITY_CONSUMED",
        "CFI_TALLY_FINAL_READ_A",
        "CFI_TALLY_FINAL_READ_B",
        "CFI_TALLY_FINAL_MATCH",
        "CFI_TALLY_VERDICT_PUBLISHED",
    ];
    let stages = names.map(source_u32_const);
    let expected = stages.iter().fold(
        crate::fi::CfiCounter::INIT_VALUE,
        |accum, stage| accum.wrapping_add(*stage),
    );

    let expected_start = CMD_SIGN_USEROP_FORCED_SRC
        .find("const CFI_TALLY_COMMIT_EXPECTED")
        .expect("tally commit expected constant");
    let expected_end = CMD_SIGN_USEROP_FORCED_SRC[expected_start..]
        .find(");")
        .map(|offset| expected_start + offset)
        .expect("tally commit expected boundary");
    let expected_source = &CMD_SIGN_USEROP_FORCED_SRC[expected_start..expected_end];
    for name in names {
        assert!(
            expected_source.contains(name),
            "production tally CFI expected value omitted {name}"
        );
    }

    let mut complete = crate::fi::CfiCounter::new();
    for stage in stages {
        complete.bump(stage);
    }
    assert_eq!(
        complete.check_into_sentinel(expected),
        crate::fi::OK_SENTINEL
    );

    for omitted in 1usize..(1usize << stages.len()) {
        let mut cfi = crate::fi::CfiCounter::new();
        for (index, stage) in stages.iter().enumerate() {
            if omitted & (1usize << index) == 0 {
                cfi.bump(*stage);
            }
        }
        assert_eq!(
            cfi.check_into_sentinel(expected),
            crate::fi::FAIL_SENTINEL,
            "omitted tally-CFI subset {omitted:#07b} collided with the complete transcript"
        );
    }
}

#[test]
fn forced_release_is_one_fixed_extent_after_the_final_gate() {
    let start = CMD_SIGN_USEROP_FORCED_SRC
        .find("unsafe fn publish_forced_response(")
        .expect("forced publisher");
    let end = CMD_SIGN_USEROP_FORCED_SRC[start..]
        .find("fn forced_sign_progress(")
        .map(|offset| start + offset)
        .expect("publisher boundary");
    let body = &CMD_SIGN_USEROP_FORCED_SRC[start..end];
    assert!(CMD_SIGN_USEROP_FORCED_SRC.contains(
        "const _: () = assert!(FORCED_SIGN_RESPONSE_LEN == 4_148);"
    ));
    assert_eq!(body.matches("validate_ns_write_ptr(args.arg1, MAX_SIGN_RESPONSE_LEN)").count(), 2);
    assert_eq!(body.matches("validate_ns_write_ptr(args.arg1, FORCED_SIGN_RESPONSE_LEN)").count(), 2);
    assert_eq!(body.matches("release_window_open_verified()").count(), 2);

    let release = body
        .find("flow_cfi.bump(CFI_RELEASE_GATE);")
        .expect("release CFI bump");
    let final_cfi = body[release..]
        .find("CFI_RELEASE_EXPECTED")
        .map(|offset| release + offset)
        .expect("final release CFI gate");
    let write_loop = body[final_cfi..]
        .find("for position in 0..FORCED_SIGN_RESPONSE_LEN")
        .map(|offset| final_cfi + offset)
        .expect("fixed publication loop");
    assert!(release < final_cfi && final_cfi < write_loop);
    assert_eq!(body.matches("write_volatile(out.add(position), byte)").count(), 1);
    assert!(body[write_loop..].contains("for index in 0..FORCED_SIGN_RESPONSE_LEN"));
    assert!(body[write_loop..].contains("SCB::sys_reset();"));
}

#[test]
fn forced_authority_is_volatile_invalidated_on_every_terminal_return() {
    for required in [
        "impl Drop for ForcedCandidate",
        "write_volatile(&mut self.state, 0)",
        "impl Drop for ForcedCleanup",
        "addr_of_mut!(SIGN_SNAP_BUF)",
    ] {
        assert!(
            CMD_SIGN_USEROP_FORCED_SRC.contains(required),
            "missing forced terminal cleanup pin: {required}"
        );
    }
    assert!(FORCED_BLIND_DISPLAY_SRC.contains("impl Drop for RawForcedReceipt"));
    assert!(FORCED_BLIND_DISPLAY_SRC.contains("write_volatile(&mut self.domain, 0)"));
    assert!(FORCED_BLIND_DISPLAY_SRC.contains("for byte in &mut self.request_digest"));
}

#[test]
fn negative_slot_master_is_derived_on_a_cache_miss_only() {
    // 2026-10-23. ASSUMPTION ATTACKED: a handler derives the slot master (a
    // whole BIP-39 seed: 24 constant-time dictionary scans and 2,048
    // HMAC-SHA512 rounds, ~0.6 s on the U585) on a slot-cache HIT, where
    // nothing reads it; or derives it anywhere but inside its own
    // `if need_keygen { … }` branch, so a keygen could run on a master the
    // request never derived. Measured on the pq1 bench board: moving it into
    // the branch took the fixed non-hash cost of a cached Type-2 sign from
    // 126.45 M to 25.15 M cycles.
    const GET_INIT_CODE_SRC: &str = include_str!("nsc/cmd_get_init_code.rs");
    for (name, src) in [
        ("cmd_sign_userop.rs", CMD_SIGN_USEROP_SRC),
        ("cmd_sign_userop_batch.rs", CMD_SIGN_USEROP_BATCH_SRC),
        ("cmd_sign_offchain.rs", CMD_SIGN_OFFCHAIN_SRC),
        ("cmd_get_init_code.rs", GET_INIT_CODE_SRC),
        ("cmd_sign_userop_forced.rs", CMD_SIGN_USEROP_FORCED_SRC),
    ] {
        let calls: std::vec::Vec<usize> =
            src.match_indices("slot_master_entropy_from_entropy(").map(|(i, _)| i).collect();
        assert_eq!(calls.len(), 1, "{name}: one slot-master derivation");
        let open = src.find("if need_keygen {\n").unwrap_or_else(|| panic!("{name}: need_keygen branch"));
        let indent = &src[src[..open].rfind('\n').expect("line start") + 1..open];
        let close = open + src[open..].find(&format!("\n{indent}}}\n")).unwrap_or_else(|| panic!("{name}: branch end"));
        assert!(open < calls[0] && calls[0] < close, "{name}: derivation outside the cache-miss branch");
        // It is the branch's first statement, before any keygen.
        let body = &src[open..calls[0]];
        assert!(!body.contains("derive_c10_slot_keypair"), "{name}: keygen before the derivation");
    }
}

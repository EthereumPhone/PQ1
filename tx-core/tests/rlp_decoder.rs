//! Positive + negative tests for `pqsigner_tx_core::rlp`.
//!
//! The RLP decoder is the trust root of the unsigned-tx parse path: any
//! malformed input the EVM would later reject must be rejected here so
//! the wallet never asks the user to confirm a tx that cannot land.
//! Every negative test names the assumption the decoder claims to
//! enforce and demonstrates that violating it returns the *specific*
//! `RlpError` variant the parser switches on — a downgraded "some error
//! happened" would still bypass downstream branches.

mod common;

use pqsigner_tx_core::rlp::{bytes_to_u256, bytes_to_u64, decode_item, Item, ListIter, RlpError};

// ---------------------------------------------------------------------------
// decode_item — positive
// ---------------------------------------------------------------------------

#[test]
fn positive_decode_single_byte_payload() {
    let (item, used) = decode_item(&[0x7f]).unwrap();
    assert_eq!(used, 1);
    match item {
        Item::Bytes(b) => assert_eq!(b, &[0x7f]),
        Item::List(_) => panic!("expected bytes"),
    }
}

#[test]
fn positive_decode_empty_string_is_zero_length_bytes() {
    // 0x80 is the canonical empty string (and encodes the integer 0).
    let (item, used) = decode_item(&[0x80]).unwrap();
    assert_eq!(used, 1);
    match item {
        Item::Bytes(b) => assert!(b.is_empty()),
        Item::List(_) => panic!("expected bytes"),
    }
}

#[test]
fn positive_decode_short_string_at_55_byte_boundary() {
    // 55 bytes is the max short-string length (header = 0x80 + 55 = 0xb7).
    let payload = [0xaau8; 55];
    let mut buf = vec![0xb7];
    buf.extend_from_slice(&payload);
    let (item, used) = decode_item(&buf).unwrap();
    assert_eq!(used, 56);
    match item {
        Item::Bytes(b) => assert_eq!(b, &payload[..]),
        Item::List(_) => panic!("expected bytes"),
    }
}

#[test]
fn positive_decode_long_string_56_bytes() {
    // 56 bytes is the smallest long-string size (length encoded explicitly).
    let payload = [0xbbu8; 56];
    let mut buf = vec![0xb8, 56];
    buf.extend_from_slice(&payload);
    let (item, used) = decode_item(&buf).unwrap();
    assert_eq!(used, 2 + 56);
    match item {
        Item::Bytes(b) => assert_eq!(b.len(), 56),
        Item::List(_) => panic!("expected bytes"),
    }
}

#[test]
fn positive_decode_short_list() {
    // 0xc2 = list of length 2, payload `0x01 0x02`.
    let (item, used) = decode_item(&[0xc2, 0x01, 0x02]).unwrap();
    assert_eq!(used, 3);
    match item {
        Item::List(l) => assert_eq!(l, &[0x01, 0x02]),
        Item::Bytes(_) => panic!("expected list"),
    }
}

#[test]
fn positive_decode_empty_list() {
    // 0xc0 = empty list — used by EIP-1559 access lists in the common case.
    let (item, used) = decode_item(&[0xc0]).unwrap();
    assert_eq!(used, 1);
    match item {
        Item::List(l) => assert!(l.is_empty()),
        Item::Bytes(_) => panic!("expected list"),
    }
}

#[test]
fn positive_decode_long_list_56_bytes() {
    let body = vec![0xccu8; 56];
    let mut buf = vec![0xf8, 56];
    buf.extend_from_slice(&body);
    let (item, used) = decode_item(&buf).unwrap();
    assert_eq!(used, 2 + 56);
    match item {
        Item::List(l) => assert_eq!(l.len(), 56),
        Item::Bytes(_) => panic!("expected list"),
    }
}

// ---------------------------------------------------------------------------
// decode_item — negative (parser-fuzz seeds)
// ---------------------------------------------------------------------------

#[test]
fn negative_empty_input_is_truncated() {
    // ASSUMPTION: decode_item must reject a zero-byte input rather than
    // returning a synthetic empty Item. A silent `Bytes(&[])` would let
    // the EIP-1559 parser fall through to `expect_list` and report a
    // spurious envelope-decoding success.
    assert_eq!(decode_item(&[]).unwrap_err(), RlpError::Truncated);
}

#[test]
fn negative_short_string_truncated_payload() {
    // Header says "3 bytes follow", buffer only has 2. Must reject.
    assert_eq!(
        decode_item(&[0x83, 0x11, 0x22]).unwrap_err(),
        RlpError::Truncated,
    );
}

#[test]
fn negative_single_byte_form_must_be_used_for_low_values() {
    // ASSUMPTION: a one-byte string with value <= 0x7f MUST be encoded
    // as itself, not as `0x81 <byte>`. Accepting non-canonical encodings
    // would split every wire format into two valid representations and
    // break replay/uniqueness guarantees downstream (userOpHash, etc.).
    assert_eq!(
        decode_item(&[0x81, 0x00]).unwrap_err(),
        RlpError::NonCanonical,
    );
    assert_eq!(
        decode_item(&[0x81, 0x7f]).unwrap_err(),
        RlpError::NonCanonical,
    );
}

#[test]
fn negative_single_byte_form_boundary_0x80_must_use_short_form() {
    // 0x80 is the lowest byte that legally appears inside an 0x81-prefixed
    // string, since the no-prefix form covers 0x00..=0x7f exactly. Confirm
    // the boundary is accepted (rejecting it would lose canonical inputs).
    let (item, used) = decode_item(&[0x81, 0x80]).unwrap();
    assert_eq!(used, 2);
    match item {
        Item::Bytes(b) => assert_eq!(b, &[0x80]),
        Item::List(_) => panic!("expected bytes"),
    }
}

#[test]
fn negative_long_string_55_byte_payload_is_non_canonical() {
    // 0..=55 byte payloads MUST use the short form. The long form for
    // any such length is non-canonical and must be rejected.
    let payload = [0u8; 55];
    let mut buf = vec![0xb8, 55];
    buf.extend_from_slice(&payload);
    assert_eq!(decode_item(&buf).unwrap_err(), RlpError::NonCanonical);
}

#[test]
fn negative_long_string_with_leading_zero_in_length() {
    // ASSUMPTION: the length field itself is RLP-canonical — no leading
    // zeros. `0xb9 0x00 0x38` encodes len=0x0038 with a leading zero
    // byte, equivalent to len=56 but with a redundant byte.
    let mut buf = vec![0xb9, 0x00, 0x38];
    buf.extend_from_slice(&[0u8; 56]);
    assert_eq!(decode_item(&buf).unwrap_err(), RlpError::LeadingZero);
}

#[test]
fn negative_long_string_truncated_length_bytes() {
    // Header advertises len_of_len=2 but only one length byte is present.
    assert_eq!(
        decode_item(&[0xb9, 0x10]).unwrap_err(),
        RlpError::Truncated,
    );
}

#[test]
fn negative_long_string_truncated_payload() {
    // Header says len=56, but only 10 payload bytes are present.
    let mut buf = vec![0xb8, 56];
    buf.extend_from_slice(&[0xaau8; 10]);
    assert_eq!(decode_item(&buf).unwrap_err(), RlpError::LengthOverflow);
}

#[test]
fn negative_long_list_55_byte_payload_is_non_canonical() {
    let body = [0u8; 55];
    let mut buf = vec![0xf8, 55];
    buf.extend_from_slice(&body);
    assert_eq!(decode_item(&buf).unwrap_err(), RlpError::NonCanonical);
}

#[test]
fn negative_short_list_truncated_payload() {
    // Header says list-len=4, only 2 bytes follow.
    assert_eq!(
        decode_item(&[0xc4, 0x01, 0x02]).unwrap_err(),
        RlpError::Truncated,
    );
}

#[test]
fn negative_long_list_truncated_length_bytes() {
    // 0xf9 = list with len_of_len=2; provide only one length byte.
    assert_eq!(
        decode_item(&[0xf9, 0x10]).unwrap_err(),
        RlpError::Truncated,
    );
}

#[test]
fn negative_long_list_truncated_payload() {
    // Header says len=56, but only 10 payload bytes are present.
    let mut buf = vec![0xf8, 56];
    buf.extend_from_slice(&[0xccu8; 10]);
    assert_eq!(decode_item(&buf).unwrap_err(), RlpError::LengthOverflow);
}

#[test]
fn negative_long_list_with_leading_zero_in_length() {
    let mut buf = vec![0xf9, 0x00, 0x38];
    buf.extend_from_slice(&[0u8; 56]);
    assert_eq!(decode_item(&buf).unwrap_err(), RlpError::LeadingZero);
}

// ---------------------------------------------------------------------------
// bytes_to_u64 / bytes_to_u256 — positive
// ---------------------------------------------------------------------------

#[test]
fn positive_bytes_to_u64_empty_is_zero() {
    // Canonical RLP integer 0 is the empty byte string. Decoders must
    // map this to numeric 0, not error.
    assert_eq!(bytes_to_u64(&[]).unwrap(), 0);
}

#[test]
fn positive_bytes_to_u64_max() {
    assert_eq!(bytes_to_u64(&[0xffu8; 8]).unwrap(), u64::MAX);
}

#[test]
fn positive_bytes_to_u64_one_byte() {
    assert_eq!(bytes_to_u64(&[0x42]).unwrap(), 0x42);
}

#[test]
fn positive_bytes_to_u256_empty_is_zero() {
    assert_eq!(bytes_to_u256(&[]).unwrap(), [0u8; 32]);
}

#[test]
fn positive_bytes_to_u256_full_32_bytes_left_padded() {
    let raw = [0xabu8; 32];
    assert_eq!(bytes_to_u256(&raw).unwrap(), raw);
}

#[test]
fn positive_bytes_to_u256_short_input_is_left_padded() {
    // Two-byte big-endian value 0x1234 must land in bytes [30..32].
    let v = bytes_to_u256(&[0x12, 0x34]).unwrap();
    let mut expected = [0u8; 32];
    expected[30] = 0x12;
    expected[31] = 0x34;
    assert_eq!(v, expected);
}

// ---------------------------------------------------------------------------
// bytes_to_u64 / bytes_to_u256 — negative
// ---------------------------------------------------------------------------

#[test]
fn negative_bytes_to_u64_oversize_rejected() {
    // ASSUMPTION: u64-typed RLP fields (chain_id, nonce, gas_limit) MUST
    // fit in 8 bytes. A 9-byte input would silently overflow if we
    // truncated, so we must error.
    assert_eq!(
        bytes_to_u64(&[0xffu8; 9]).unwrap_err(),
        RlpError::IntTooLarge,
    );
}

#[test]
fn negative_bytes_to_u64_leading_zero_rejected() {
    // ASSUMPTION: canonical RLP integer encoding has no leading zero
    // bytes (the empty string is the unique encoding of zero). A leading
    // zero opens a second wire representation that would break every
    // hash-based commitment the bytes feed into.
    assert_eq!(
        bytes_to_u64(&[0x00, 0x01]).unwrap_err(),
        RlpError::LeadingZero,
    );
}

#[test]
fn negative_bytes_to_u64_single_zero_byte_rejected() {
    // The integer zero is the empty string in canonical RLP; a single
    // 0x00 byte is the same value with one redundant leading zero.
    assert_eq!(bytes_to_u64(&[0x00]).unwrap_err(), RlpError::LeadingZero);
}

#[test]
fn negative_bytes_to_u256_oversize_rejected() {
    assert_eq!(
        bytes_to_u256(&[0xffu8; 33]).unwrap_err(),
        RlpError::IntTooLarge,
    );
}

#[test]
fn negative_bytes_to_u256_leading_zero_rejected() {
    assert_eq!(
        bytes_to_u256(&[0x00, 0x01]).unwrap_err(),
        RlpError::LeadingZero,
    );
}

// ---------------------------------------------------------------------------
// ListIter — positive + negative
// ---------------------------------------------------------------------------

#[test]
fn positive_listiter_walks_to_end() {
    // payload = bytes(0x42) ‖ empty list
    let payload = vec![0x42, 0xc0];
    let mut iter = ListIter::new(&payload);
    let first = iter.expect_bytes().unwrap();
    assert_eq!(first, &[0x42]);
    let inner = iter.expect_list().unwrap();
    assert!(inner.is_empty());
    assert!(iter.next_item().unwrap().is_none());
}

#[test]
fn negative_listiter_expect_bytes_when_list_present() {
    // ASSUMPTION: expect_bytes refuses lists. A flat unwrap on
    // expect_bytes() for the access-list slot must return UnexpectedType
    // — otherwise the parser would accept an access list where the
    // chain_id should be.
    let payload = vec![0xc0]; // empty list
    let mut iter = ListIter::new(&payload);
    assert_eq!(
        iter.expect_bytes().unwrap_err(),
        RlpError::UnexpectedType,
    );
}

#[test]
fn negative_listiter_expect_list_when_bytes_present() {
    let payload = vec![0x42];
    let mut iter = ListIter::new(&payload);
    assert_eq!(
        iter.expect_list().unwrap_err(),
        RlpError::UnexpectedType,
    );
}

#[test]
fn negative_listiter_expect_bytes_when_empty_is_truncated() {
    // ASSUMPTION: running out of fields mid-parse is Truncated, NOT
    // a silent success. EIP-1559 parse() relies on this to detect
    // envelopes missing the access-list / data / value fields.
    let payload: Vec<u8> = vec![];
    let mut iter = ListIter::new(&payload);
    assert_eq!(iter.expect_bytes().unwrap_err(), RlpError::Truncated);
}

#[test]
fn negative_listiter_expect_list_when_empty_is_truncated() {
    let payload: Vec<u8> = vec![];
    let mut iter = ListIter::new(&payload);
    assert_eq!(iter.expect_list().unwrap_err(), RlpError::Truncated);
}

#[test]
fn negative_listiter_propagates_inner_rlp_errors() {
    // Malformed inner item (0x81 0x00 — non-canonical single-byte form)
    // must bubble up through next_item; ListIter must not swallow
    // RlpError variants and pretend the list ended cleanly.
    let payload = vec![0x81, 0x00];
    let mut iter = ListIter::new(&payload);
    assert_eq!(
        iter.next_item().unwrap_err(),
        RlpError::NonCanonical,
    );
}

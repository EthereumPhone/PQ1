//! Positive + negative tests for `pqsigner_tx_core::eip1559::parse`.
//!
//! The strict envelope parser is the gate between a companion-supplied
//! RLP blob and the trusted-UI confirm flow. Every "the EVM would
//! revert" condition the parser claims to enforce is paired here with a
//! negative test, so a future refactor cannot silently relax one of
//! them and let the wallet ask the user to confirm a tx that can never
//! land.

mod common;

use common::*;
use pqsigner_tx_core::eip1559::{parse, TxError, MIN_INTRINSIC_GAS, U256};
use pqsigner_tx_core::hash::keccak256;
use pqsigner_tx_core::rlp::RlpError;

const TO: [u8; 20] = [0x11u8; 20];

// ---------------------------------------------------------------------------
// Positive parser coverage
// ---------------------------------------------------------------------------

#[test]
fn positive_parse_round_trip_recovers_all_fields() {
    let to = [0xabu8; 20];
    let env = build_envelope(7, 42, 3, 17, 30_000, Some(to), 1_000, b"hello");
    let parsed = parse(&env).unwrap();
    assert_eq!(parsed.tx.chain_id, 7);
    assert_eq!(parsed.tx.nonce, 42);
    assert_eq!(parsed.tx.max_priority_fee_per_gas.0[31], 3);
    assert_eq!(parsed.tx.max_fee_per_gas.0[31], 17);
    assert_eq!(parsed.tx.gas_limit, 30_000);
    assert_eq!(parsed.tx.to, Some(to));
    assert_eq!(parsed.tx.value.0[30..32], [0x03, 0xe8]); // 1000
    assert_eq!(parsed.tx.data_len, 5);
    assert_eq!(parsed.tx.access_list_count, 0);
    assert_eq!(parsed.data, b"hello");
    assert_eq!(parsed.envelope, env.as_slice());
}

#[test]
fn positive_parse_signing_hash_equals_keccak_of_full_envelope() {
    // INVARIANT: ParsedTx.tx.signing_hash MUST be keccak256(envelope).
    // Anything else would silently break replay protection downstream
    // (the EIP-1559 chain-id is folded into the hash via the envelope).
    let env = build_envelope(1, 0, 1, 2, 21_000, Some(TO), 0, &[]);
    let parsed = parse(&env).unwrap();
    assert_eq!(parsed.tx.signing_hash, keccak256(&env));
}

#[test]
fn positive_parse_contract_creation_to_is_none() {
    let env = build_envelope(1, 0, 1, 2, 100_000, None, 0, b"\x60\x80\x60\x40");
    let parsed = parse(&env).unwrap();
    assert!(parsed.tx.to.is_none());
}

#[test]
fn positive_contract_creation_below_intrinsic_floor_allowed() {
    // The 21_000 floor only applies to call-style txs (to.is_some()).
    // Contract-creation simulations frequently set gas_limit below that
    // and must NOT be rejected by the parser. See parse() comment.
    let env = build_envelope(1, 0, 1, 2, 1_000, None, 0, b"");
    let parsed = parse(&env).unwrap();
    assert_eq!(parsed.tx.gas_limit, 1_000);
    assert!(parsed.tx.to.is_none());
}

#[test]
fn positive_parse_with_populated_access_list() {
    // Access list = [(addr, [key1, key2]), (addr2, [])].
    let addr = [0x22u8; 20];
    let addr2 = [0x33u8; 20];
    let key1 = [0x44u8; 32];
    let key2 = [0x55u8; 32];

    let keys_a = rlp_encode_list(&[rlp_encode_bytes(&key1), rlp_encode_bytes(&key2)]);
    let entry_a = rlp_encode_list(&[rlp_encode_bytes(&addr), keys_a]);
    let entry_b = rlp_encode_list(&[rlp_encode_bytes(&addr2), rlp_encode_list(&[])]);
    let access_list = rlp_encode_list(&[entry_a, entry_b]);

    let env = build_envelope_with_access_list(
        1, 0, 1, 2, 21_000, Some(TO), 0, &[], &access_list,
    );
    let parsed = parse(&env).unwrap();
    assert_eq!(parsed.tx.access_list_count, 2);
}

#[test]
fn positive_parse_data_slice_borrows_from_envelope() {
    // The parsed `data` slice should be a borrow into the envelope, not
    // a copy. Pointer-arithmetic check: parsed.data.as_ptr() must lie
    // inside [envelope.as_ptr(), envelope.as_ptr() + envelope.len()).
    let env = build_envelope(1, 0, 1, 2, 21_000, Some(TO), 0, b"hello-world");
    let parsed = parse(&env).unwrap();
    let env_start = env.as_ptr() as usize;
    let env_end = env_start + env.len();
    let data_start = parsed.data.as_ptr() as usize;
    assert!(data_start >= env_start && data_start < env_end);
    assert!(data_start + parsed.data.len() <= env_end);
    assert_eq!(parsed.data, b"hello-world");
}

#[test]
fn positive_envelope_at_max_tx_len_is_accepted() {
    // Build a tx whose envelope is exactly MAX_TX_LEN bytes (4096). The
    // parser bound is `> MAX_TX_LEN` (strictly greater), so the exact
    // boundary must succeed.
    let max_len = pqsigner_proto::MAX_TX_LEN;
    // Empirically tune the data payload to hit exactly max_len.
    let mut data_len = max_len; // start above and shrink
    let mut env: Vec<u8> = Vec::new();
    while data_len > 0 {
        let data = vec![0xaau8; data_len];
        env = build_envelope(1, 0, 1, 2, 21_000, Some(TO), 0, &data);
        if env.len() == max_len {
            break;
        }
        if env.len() < max_len {
            data_len += max_len - env.len();
        } else {
            data_len -= env.len() - max_len;
        }
        if data_len == 0 {
            break;
        }
    }
    assert_eq!(env.len(), max_len, "could not tune envelope to MAX_TX_LEN");
    assert!(parse(&env).is_ok());
}

// ---------------------------------------------------------------------------
// Negative — envelope shell
// ---------------------------------------------------------------------------

#[test]
fn negative_empty_envelope_rejected() {
    // ASSUMPTION: parse() must never index into an empty envelope.
    // A panic here would be a DoS vector reachable by any companion
    // request; explicit EmptyEnvelope is the documented outcome.
    assert_eq!(parse(&[]).unwrap_err(), TxError::EmptyEnvelope);
}

#[test]
fn negative_legacy_tx_type_0x00_rejected() {
    let env = build_envelope(1, 0, 1, 2, 21_000, Some(TO), 0, &[]);
    let mut bad = env.clone();
    bad[0] = 0x00;
    assert_eq!(parse(&bad).unwrap_err(), TxError::NotEip1559);
}

#[test]
fn negative_eip2930_tx_type_0x01_rejected() {
    // ASSUMPTION: the wallet only signs EIP-1559 (0x02). EIP-2930
    // looks structurally similar and could trick a permissive parser.
    let env = build_envelope(1, 0, 1, 2, 21_000, Some(TO), 0, &[]);
    let mut bad = env.clone();
    bad[0] = 0x01;
    assert_eq!(parse(&bad).unwrap_err(), TxError::NotEip1559);
}

#[test]
fn negative_eip4844_tx_type_0x03_rejected() {
    let env = build_envelope(1, 0, 1, 2, 21_000, Some(TO), 0, &[]);
    let mut bad = env.clone();
    bad[0] = 0x03;
    assert_eq!(parse(&bad).unwrap_err(), TxError::NotEip1559);
}

#[test]
fn negative_envelope_just_type_byte_truncated() {
    // 0x02 alone has no RLP body — must surface as a Truncated RLP error.
    assert_eq!(parse(&[0x02]).unwrap_err(), TxError::Rlp(RlpError::Truncated));
}

#[test]
fn negative_envelope_over_max_tx_len_rejected() {
    // ASSUMPTION: the parser MUST enforce the MAX_TX_LEN bound (=4096
    // bytes) BEFORE doing any RLP work — that bound also sizes the
    // secure-world TOCTOU copy buffer. Letting a longer envelope through
    // could overflow that buffer in callers.
    let oversize = vec![0x02u8; pqsigner_proto::MAX_TX_LEN + 1];
    assert_eq!(parse(&oversize).unwrap_err(), TxError::EnvelopeTooLong);
}

#[test]
fn negative_trailing_bytes_after_rlp_list_rejected() {
    // The unsigned envelope is exactly 0x02 ‖ rlp(list). Any garbage
    // after the RLP list must be rejected so a malicious companion
    // can't smuggle a payload past the parser.
    let mut env = build_envelope(1, 0, 1, 2, 21_000, Some(TO), 0, &[]);
    env.extend_from_slice(&[0x00, 0xff, 0xaa]);
    assert_eq!(parse(&env).unwrap_err(), TxError::TrailingBytes);
}

#[test]
fn negative_rlp_body_is_bytes_not_list_rejected() {
    // Replace the list with a byte string at the top level — the
    // parser must reject the type mismatch rather than silently
    // discarding the inner fields.
    let mut env = vec![0x02];
    env.push(0x83);
    env.extend_from_slice(&[0x01, 0x02, 0x03]);
    assert_eq!(
        parse(&env).unwrap_err(),
        TxError::Rlp(RlpError::UnexpectedType),
    );
}

// ---------------------------------------------------------------------------
// Negative — field-level rejections
// ---------------------------------------------------------------------------

#[test]
fn negative_to_address_19_bytes_rejected() {
    // ASSUMPTION: `to` is either empty (contract creation) or exactly
    // 20 bytes. Any other length is a malformed Ethereum address.
    // Build directly so the malformed 19-byte `to` field is explicit.
    let items = vec![
        rlp_encode_bytes(&[0x01]),
        rlp_encode_bytes(&[]),
        rlp_encode_bytes(&[0x01]),
        rlp_encode_bytes(&[0x02]),
        rlp_encode_bytes(&be_trim(&21_000u64.to_be_bytes())),
        rlp_encode_bytes(&[0xaau8; 19]), // <-- 19 bytes, not 20
        rlp_encode_bytes(&[]),
        rlp_encode_bytes(&[]),
        rlp_encode_list(&[]),
    ];
    let list = rlp_encode_list(&items);
    let mut env = vec![0x02];
    env.extend_from_slice(&list);
    assert_eq!(parse(&env).unwrap_err(), TxError::BadToLength);
}

#[test]
fn negative_to_address_21_bytes_rejected() {
    let items = vec![
        rlp_encode_bytes(&[0x01]),
        rlp_encode_bytes(&[]),
        rlp_encode_bytes(&[0x01]),
        rlp_encode_bytes(&[0x02]),
        rlp_encode_bytes(&be_trim(&21_000u64.to_be_bytes())),
        rlp_encode_bytes(&[0xaau8; 21]),
        rlp_encode_bytes(&[]),
        rlp_encode_bytes(&[]),
        rlp_encode_list(&[]),
    ];
    let list = rlp_encode_list(&items);
    let mut env = vec![0x02];
    env.extend_from_slice(&list);
    assert_eq!(parse(&env).unwrap_err(), TxError::BadToLength);
}

#[test]
fn negative_chain_id_zero_rejected() {
    // ASSUMPTION: EIP-155 forbids chain_id = 0; signing one would allow
    // a replay on any other chain. The parser is the single point that
    // can refuse it.
    let env = build_envelope(0, 0, 1, 2, 21_000, Some(TO), 0, &[]);
    assert_eq!(parse(&env).unwrap_err(), TxError::BadChainId);
}

#[test]
fn negative_gas_limit_below_21000_rejected_for_call_tx() {
    for low in [0u64, 1, 20_999] {
        let env = build_envelope(1, 0, 1, 2, low, Some(TO), 0, &[]);
        assert_eq!(
            parse(&env).unwrap_err(),
            TxError::GasLimitTooLow,
            "gas_limit {low} for a call tx must be rejected",
        );
    }
}

#[test]
fn negative_gas_limit_exactly_at_floor_accepted() {
    // Boundary check on the "below intrinsic floor" rule.
    let env = build_envelope(1, 0, 1, 2, MIN_INTRINSIC_GAS, Some(TO), 0, &[]);
    assert!(parse(&env).is_ok());
}

#[test]
fn negative_max_priority_exceeds_max_fee_rejected() {
    let env = build_envelope(1, 0, 100, 50, 21_000, Some(TO), 0, &[]);
    assert_eq!(parse(&env).unwrap_err(), TxError::PriorityExceedsFee);
}

#[test]
fn negative_chain_id_with_leading_zero_rejected() {
    // ASSUMPTION: integer fields must use canonical RLP — a leading
    // zero byte is a NonCanonical encoding and a parallel wire
    // representation that the userOpHash commitment cannot tolerate.
    let items = vec![
        rlp_encode_bytes(&[0x00, 0x01]), // chain_id = 1 with bogus leading zero
        rlp_encode_bytes(&[]),
        rlp_encode_bytes(&[0x01]),
        rlp_encode_bytes(&[0x02]),
        rlp_encode_bytes(&be_trim(&21_000u64.to_be_bytes())),
        rlp_encode_bytes(&TO),
        rlp_encode_bytes(&[]),
        rlp_encode_bytes(&[]),
        rlp_encode_list(&[]),
    ];
    let list = rlp_encode_list(&items);
    let mut env = vec![0x02];
    env.extend_from_slice(&list);
    assert_eq!(
        parse(&env).unwrap_err(),
        TxError::Rlp(RlpError::LeadingZero),
    );
}

#[test]
fn negative_chain_id_9_bytes_int_too_large() {
    let items = vec![
        rlp_encode_bytes(&[0x01u8; 9]),
        rlp_encode_bytes(&[]),
        rlp_encode_bytes(&[0x01]),
        rlp_encode_bytes(&[0x02]),
        rlp_encode_bytes(&be_trim(&21_000u64.to_be_bytes())),
        rlp_encode_bytes(&TO),
        rlp_encode_bytes(&[]),
        rlp_encode_bytes(&[]),
        rlp_encode_list(&[]),
    ];
    let list = rlp_encode_list(&items);
    let mut env = vec![0x02];
    env.extend_from_slice(&list);
    assert_eq!(
        parse(&env).unwrap_err(),
        TxError::Rlp(RlpError::IntTooLarge),
    );
}

#[test]
fn negative_value_33_bytes_int_too_large() {
    // U256 field overflow — 33-byte big-endian is one byte too wide.
    let items = vec![
        rlp_encode_bytes(&[0x01]),
        rlp_encode_bytes(&[]),
        rlp_encode_bytes(&[0x01]),
        rlp_encode_bytes(&[0x02]),
        rlp_encode_bytes(&be_trim(&21_000u64.to_be_bytes())),
        rlp_encode_bytes(&TO),
        rlp_encode_bytes(&[0x01u8; 33]), // value: 33 bytes
        rlp_encode_bytes(&[]),
        rlp_encode_list(&[]),
    ];
    let list = rlp_encode_list(&items);
    let mut env = vec![0x02];
    env.extend_from_slice(&list);
    assert_eq!(
        parse(&env).unwrap_err(),
        TxError::Rlp(RlpError::IntTooLarge),
    );
}

#[test]
fn negative_missing_access_list_field_rejected() {
    // Only 8 fields — access list missing. The parser must surface this
    // as a Truncated RLP iterator error, NOT a successful parse.
    let items = vec![
        rlp_encode_bytes(&[0x01]),
        rlp_encode_bytes(&[]),
        rlp_encode_bytes(&[0x01]),
        rlp_encode_bytes(&[0x02]),
        rlp_encode_bytes(&be_trim(&21_000u64.to_be_bytes())),
        rlp_encode_bytes(&TO),
        rlp_encode_bytes(&[]),
        rlp_encode_bytes(&[]),
    ];
    let list = rlp_encode_list(&items);
    let mut env = vec![0x02];
    env.extend_from_slice(&list);
    // expect_list at the end of a too-short list returns Truncated.
    assert_eq!(
        parse(&env).unwrap_err(),
        TxError::Rlp(RlpError::Truncated),
    );
}

#[test]
fn negative_tenth_field_after_access_list_rejected() {
    // The unsigned form has exactly 9 fields. A 10th item (e.g. a
    // signature blob someone glued on) must be rejected by the
    // post-iterator drain.
    let items = vec![
        rlp_encode_bytes(&[0x01]),
        rlp_encode_bytes(&[]),
        rlp_encode_bytes(&[0x01]),
        rlp_encode_bytes(&[0x02]),
        rlp_encode_bytes(&be_trim(&21_000u64.to_be_bytes())),
        rlp_encode_bytes(&TO),
        rlp_encode_bytes(&[]),
        rlp_encode_bytes(&[]),
        rlp_encode_list(&[]),
        rlp_encode_bytes(&[0xde, 0xad]), // <-- 10th field
    ];
    let list = rlp_encode_list(&items);
    let mut env = vec![0x02];
    env.extend_from_slice(&list);
    assert_eq!(parse(&env).unwrap_err(), TxError::TrailingBytes);
}

// ---------------------------------------------------------------------------
// Negative — access-list structural rules
// ---------------------------------------------------------------------------

#[test]
fn negative_access_list_entry_is_bytes_not_list_rejected() {
    // Each access-list entry must be a 2-tuple, never a flat bytes
    // blob. A permissive parser would let the EVM revert at execution
    // time on a tx the user already confirmed.
    let bogus_entry = rlp_encode_bytes(&[0xaa, 0xbb]);
    let access_list = rlp_encode_list(&[bogus_entry]);
    let env = build_envelope_with_access_list(
        1, 0, 1, 2, 21_000, Some(TO), 0, &[], &access_list,
    );
    assert_eq!(parse(&env).unwrap_err(), TxError::BadAccessList);
}

#[test]
fn negative_access_list_address_wrong_length() {
    // Address must be 20 bytes. Try 19 and 21.
    for len in [19usize, 21] {
        let bad_addr = vec![0xccu8; len];
        let keys = rlp_encode_list(&[]);
        let entry = rlp_encode_list(&[rlp_encode_bytes(&bad_addr), keys]);
        let access_list = rlp_encode_list(&[entry]);
        let env = build_envelope_with_access_list(
            1, 0, 1, 2, 21_000, Some(TO), 0, &[], &access_list,
        );
        assert_eq!(
            parse(&env).unwrap_err(),
            TxError::BadAccessList,
            "address of length {len} must be rejected",
        );
    }
}

#[test]
fn negative_access_list_storage_key_wrong_length() {
    let addr = vec![0x22u8; 20];
    let bad_key = vec![0x33u8; 31];
    let keys = rlp_encode_list(&[rlp_encode_bytes(&bad_key)]);
    let entry = rlp_encode_list(&[rlp_encode_bytes(&addr), keys]);
    let access_list = rlp_encode_list(&[entry]);
    let env = build_envelope_with_access_list(
        1, 0, 1, 2, 21_000, Some(TO), 0, &[], &access_list,
    );
    assert_eq!(parse(&env).unwrap_err(), TxError::BadAccessList);
}

#[test]
fn negative_access_list_storage_key_is_list_not_bytes() {
    let addr = vec![0x22u8; 20];
    // A nested list where bytes were expected.
    let keys = rlp_encode_list(&[rlp_encode_list(&[])]);
    let entry = rlp_encode_list(&[rlp_encode_bytes(&addr), keys]);
    let access_list = rlp_encode_list(&[entry]);
    let env = build_envelope_with_access_list(
        1, 0, 1, 2, 21_000, Some(TO), 0, &[], &access_list,
    );
    assert_eq!(parse(&env).unwrap_err(), TxError::BadAccessList);
}

#[test]
fn negative_access_list_keys_is_bytes_not_list() {
    let addr = vec![0x22u8; 20];
    let keys_as_bytes = rlp_encode_bytes(&[0xaa, 0xbb]);
    let entry = rlp_encode_list(&[rlp_encode_bytes(&addr), keys_as_bytes]);
    let access_list = rlp_encode_list(&[entry]);
    let env = build_envelope_with_access_list(
        1, 0, 1, 2, 21_000, Some(TO), 0, &[], &access_list,
    );
    assert_eq!(parse(&env).unwrap_err(), TxError::BadAccessList);
}

#[test]
fn negative_access_list_entry_has_third_field() {
    let addr = vec![0x22u8; 20];
    let keys = rlp_encode_list(&[]);
    let extra = rlp_encode_bytes(&[0x99]);
    let entry = rlp_encode_list(&[rlp_encode_bytes(&addr), keys, extra]);
    let access_list = rlp_encode_list(&[entry]);
    let env = build_envelope_with_access_list(
        1, 0, 1, 2, 21_000, Some(TO), 0, &[], &access_list,
    );
    assert_eq!(parse(&env).unwrap_err(), TxError::BadAccessList);
}

#[test]
fn negative_access_list_entry_missing_keys_field() {
    // Tuple with only one element (just the address).
    let addr = vec![0x22u8; 20];
    let entry = rlp_encode_list(&[rlp_encode_bytes(&addr)]);
    let access_list = rlp_encode_list(&[entry]);
    let env = build_envelope_with_access_list(
        1, 0, 1, 2, 21_000, Some(TO), 0, &[], &access_list,
    );
    assert_eq!(parse(&env).unwrap_err(), TxError::BadAccessList);
}

// ---------------------------------------------------------------------------
// Stability — public surface
// ---------------------------------------------------------------------------

#[test]
fn positive_min_intrinsic_gas_is_21000() {
    // Anchor the public constant so a future refactor that "tightens"
    // the gas floor to e.g. 53_000 (CREATE intrinsic) breaks this test
    // before it breaks user txs.
    assert_eq!(MIN_INTRINSIC_GAS, 21_000);
}

#[test]
fn positive_u256_default_is_zero() {
    let v: U256 = Default::default();
    assert!(v.is_zero());
}

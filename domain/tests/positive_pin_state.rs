//! Positive functional coverage for the PIN-state serializer.  The
//! existing `pin_state_tests` module covers a basic roundtrip and three
//! rejection paths; here we cover boundary cases.

use pqsigner_domain::{
    deserialize_pin_state, serialize_pin_state, PER_SLOT_CT_LEN, PIN_STATE_MAX_LEN,
};
use pqsigner_proto::MAX_ATTEMPTS;

#[test]
fn positive_pin_state_max_len_matches_max_attempts() {
    // The blob layout is documented as `1 byte next_index + MAX_ATTEMPTS
    // slots of PER_SLOT_CT_LEN bytes each`.  Hardcoding the layout
    // means a future MAX_ATTEMPTS bump must consciously change both
    // here and on the SE side.
    assert_eq!(PIN_STATE_MAX_LEN, 1 + (MAX_ATTEMPTS as usize) * PER_SLOT_CT_LEN);
    assert_eq!(PER_SLOT_CT_LEN, 32 + 16);
}

#[test]
fn positive_pin_state_empty_slots_serialises_to_one_byte() {
    let slots: [[u8; PER_SLOT_CT_LEN]; 0] = [];
    let mut buf = [0u8; PIN_STATE_MAX_LEN];
    let len = serialize_pin_state(0, &slots, &mut buf);
    assert_eq!(len, 1, "empty slots → single next_index byte");

    let ps = deserialize_pin_state(&buf, len).expect("must accept 1-byte blob");
    assert_eq!(ps.num_slots, 0);
    assert_eq!(ps.next_index, 0);
}

#[test]
fn positive_pin_state_at_max_attempts_is_max_len() {
    let slots = [[0xEFu8; PER_SLOT_CT_LEN]; MAX_ATTEMPTS as usize];
    let mut buf = [0u8; PIN_STATE_MAX_LEN];
    let len = serialize_pin_state(MAX_ATTEMPTS - 1, &slots, &mut buf);
    assert_eq!(len, PIN_STATE_MAX_LEN);

    let ps = deserialize_pin_state(&buf, len).expect("must accept exactly MAX_LEN");
    assert_eq!(ps.num_slots, MAX_ATTEMPTS as usize);
    assert_eq!(ps.next_index, MAX_ATTEMPTS - 1);
    for slot in ps.encrypted_secrets.iter() {
        assert_eq!(slot, &[0xEFu8; PER_SLOT_CT_LEN]);
    }
}

#[test]
fn positive_pin_state_next_index_pass_through() {
    // The function does NOT validate `next_index`; it is the SE's
    // attempt counter and the parser must surface whatever byte the
    // SE returned so the caller can reconcile.
    for n in [0u8, 1, 9, 0x7F, 0xFE, 0xFF] {
        let slots: [[u8; PER_SLOT_CT_LEN]; 0] = [];
        let mut buf = [0u8; PIN_STATE_MAX_LEN];
        let len = serialize_pin_state(n, &slots, &mut buf);
        let ps = deserialize_pin_state(&buf, len).expect("deserialise");
        assert_eq!(ps.next_index, n);
    }
}

//! PIN-state parser negatives.  The serialised PIN-state blob lives in
//! the mock-SE backing store and is consumed on every unlock; the
//! parser must reject any malformed blob without panicking.

use pqsigner_domain::{deserialize_pin_state, PER_SLOT_CT_LEN, PIN_STATE_MAX_LEN};
use pqsigner_proto::MAX_ATTEMPTS;

#[test]
fn negative_pin_state_rejects_blob_one_byte_over_max() {
    let buf = [0u8; PIN_STATE_MAX_LEN + 1];
    assert!(
        deserialize_pin_state(&buf, buf.len()).is_err(),
        "blob_len > PIN_STATE_MAX_LEN must be rejected"
    );
}

#[test]
fn negative_pin_state_rejects_blob_with_partial_slot_at_tail() {
    // 1 byte next_index + 1 full slot + 1 trailing byte → not a
    // multiple of PER_SLOT_CT_LEN.
    let buf = [0u8; 1 + PER_SLOT_CT_LEN + 1];
    assert!(
        deserialize_pin_state(&buf, buf.len()).is_err(),
        "blob with non-multiple-of-PER_SLOT_CT_LEN body must be rejected"
    );
}

#[test]
fn negative_pin_state_rejects_blob_of_only_partial_slot() {
    // 1 byte next_index + half a slot.  The function must not silently
    // round down.
    let buf = [0u8; 1 + PER_SLOT_CT_LEN / 2];
    assert!(deserialize_pin_state(&buf, buf.len()).is_err());
}

#[test]
fn negative_pin_state_rejects_every_misalignment_below_max() {
    // Cover every off-by-one misalignment within the legal length
    // window.  Each one is a distinct attack: an attacker who could
    // mutate the SE backing store would happily settle for one byte
    // of length confusion that lets them inject an extra slot.
    for k in 0..(MAX_ATTEMPTS as usize) {
        for extra in 1..PER_SLOT_CT_LEN {
            let body_len = k * PER_SLOT_CT_LEN + extra;
            let total = 1 + body_len;
            if total > PIN_STATE_MAX_LEN {
                continue;
            }
            let mut buf = [0u8; PIN_STATE_MAX_LEN];
            assert!(
                deserialize_pin_state(&buf, total).is_err(),
                "blob_len={total} (body={body_len}, k={k}, extra={extra}) must be rejected"
            );
            let _ = &mut buf;
        }
    }
}

#[test]
fn negative_pin_state_rejects_zero_blob_len() {
    // Even with a non-empty backing buffer, blob_len == 0 means "no
    // next_index byte" and must be rejected.
    let buf = [0u8; PIN_STATE_MAX_LEN];
    assert!(deserialize_pin_state(&buf, 0).is_err());
}

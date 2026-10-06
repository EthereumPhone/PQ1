//! Keep the 18 KiB calldata buffer off the live C10 signing stack.
//!
//! The caller fail-initializes `completion` and checks it twice after this
//! call. Returning a digest alone never authorizes signing: the independently
//! parsed encoded tuple must match the tuple the user confirmed.

use crate::aa::userop::{
    execute_batch_tuple_commitment_from_calldata, reconstruct_execute_batch_calldata_into,
    sha256_bytes, BatchInnerTx, ExecuteBatchCallData, MAX_EXECUTE_BATCH_CALLDATA_LEN,
};
use subtle::ConstantTimeEq;

// This frame must end before key generation or either signing pass begins.
#[inline(never)]
pub(super) fn checked_digest(
    owner_index: u64,
    offchain_count: u64,
    members: &[BatchInnerTx<'_>],
    confirmed_tuple: &[u8; 32],
    completion: &mut u32,
) -> Result<[u8; 32], ()> {
    // SAFETY: exclusive caller-owned receipt. Also clear a reused receipt on
    // encoder failure; the caller's initialization protects a skipped call.
    unsafe { core::ptr::write_volatile(completion, crate::fi::FAIL_SENTINEL) };
    let mut calldata = ExecuteBatchCallData {
        buf: [0u8; MAX_EXECUTE_BATCH_CALLDATA_LEN],
        len: 0,
    };
    reconstruct_execute_batch_calldata_into(&mut calldata, owner_index, offchain_count, members)
        .map_err(|_| ())?;
    let mut verdict = crate::fi::FAIL_SENTINEL;
    if let Some(encoded_tuple) = execute_batch_tuple_commitment_from_calldata(
        calldata.as_slice(), owner_index, offchain_count, members.len(),
    ) {
        let exact = encoded_tuple.ct_eq(confirmed_tuple).unwrap_u8() == 1;
        crate::fi::scrub_sentinel_register();
        verdict = crate::fi::check_true_into_sentinel(|| core::hint::black_box(exact));
    }
    let digest = sha256_bytes(calldata.as_slice());
    // SAFETY: exclusive live receipt; publish only after hashing and the
    // independent tuple comparison. The caller reads it through volatile.
    unsafe { core::ptr::write_volatile(completion, verdict) };
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aa::userop::{batch_tuple_commitment, reconstruct_execute_batch_calldata};

    fn member(tag: u8, data: &[u8]) -> BatchInnerTx<'_> {
        let mut value = [0u8; 32];
        value[31] = tag;
        BatchInnerTx { to: [tag; 20], value, data }
    }

    #[test]
    fn digest_matches_existing_encoder_for_all_member_counts() {
        let data = [0x5a; 65];
        let members: Vec<_> = (1..=sphincs_tz_shared::MAX_BATCH_TXS)
            .map(|i| member(i as u8, &data[..i])).collect();
        for count in 1..=members.len() {
            let slice = &members[..count];
            let expected = batch_tuple_commitment(slice).unwrap();
            for (owner, offchain) in [(1, 0), (u64::MAX, u64::MAX)] {
                let mut receipt = crate::fi::FAIL_SENTINEL;
                let digest = checked_digest(owner, offchain, slice, &expected, &mut receipt).unwrap();
                let encoded = reconstruct_execute_batch_calldata(owner, offchain, slice).unwrap();
                assert_eq!(digest, sha256_bytes(encoded.as_slice()));
                assert_eq!(receipt, crate::fi::OK_SENTINEL);
            }
        }
    }

    #[test]
    fn changed_target_value_data_order_or_count_cannot_complete() {
        let original = [member(1, b"first"), member(2, b"second")];
        let confirmed = batch_tuple_commitment(&original).unwrap();
        for mutation in 0..5 {
            let mut members = [member(1, b"first"), member(2, b"second")];
            match mutation {
                0 => members[0].to[0] ^= 1,
                1 => members[0].value[31] ^= 1,
                2 => members[0].data = b"changed",
                3 => members.swap(0, 1),
                _ => (),
            }
            let count = if mutation == 4 { 1 } else { 2 };
            let mut receipt = crate::fi::OK_SENTINEL;
            let _ = checked_digest(1, 0, &members[..count], &confirmed, &mut receipt).unwrap();
            assert_ne!(receipt, crate::fi::OK_SENTINEL, "mutation {mutation}");
        }
    }

    #[test]
    fn encoder_error_clears_a_stale_completion_receipt() {
        let oversized = [0u8; MAX_EXECUTE_BATCH_CALLDATA_LEN];
        for members in [&[][..], &[member(1, &oversized)][..]] {
            let mut receipt = crate::fi::OK_SENTINEL;
            assert!(checked_digest(1, 0, members, &[0; 32], &mut receipt).is_err());
            assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
        }
    }
}

//! ERC-8213 wallet-signature & calldata-digest fingerprint primitives.
//!
//! Two pure functions that compute the public hashes the device renders
//! on the final "fingerprint" page, alongside `cast` / `viem` / `safe-
//! hash` output. Both stream into a single `Keccak256` — no intermediate
//! staging buffer, so a 4 KiB calldata blob does not balloon the stack.
//!
//! ```text
//!   calldata_digest(data)        = keccak256( u256_be(len) || data )
//!   eip712_final_hash(ds, sh)    = keccak256( 0x19 0x01 || ds || sh )
//! ```
//!
//! Cross-parity vs viem / cast lands in Phase 5
//! (`tools/cross_parity_erc8213.py`); Phase 4 ships self-consistency
//! tests against [`crate::hash::keccak256`].

use sha3::{Digest, Keccak256};

/// ERC-8213 §"Calldata Digest" — `keccak256( abi.encodePacked(uint256
/// len, bytes data) )`. Streams the length prefix and data into one
/// Keccak instance so callers do not pay for a staging buffer.
#[must_use]
pub fn calldata_digest(data: &[u8]) -> [u8; 32] {
    let mut len_be = [0u8; 32];
    // `data.len()` fits comfortably in a u64 on every platform we ship
    // (host u64, thumbv8m u32). Left-pad into a 256-bit BE word so the
    // hash preimage matches the EVM `abi.encodePacked(uint256, bytes)`
    // layout — high 24 bytes zero, low 8 bytes the length.
    len_be[24..].copy_from_slice(&(data.len() as u64).to_be_bytes());

    let mut h = Keccak256::new();
    h.update(len_be);
    h.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// ERC-8213 §"EIP-712 Final Hash" — `keccak256( 0x19 0x01 || domainSep
/// || structHash )`. The 2-byte prefix is required for cross-device
/// compatibility with every existing EIP-712 verifier.
#[must_use]
pub fn eip712_final_hash(domain_sep: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update([0x19, 0x01]);
    h.update(domain_sep);
    h.update(struct_hash);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::keccak256;

    #[test]
    fn calldata_digest_empty_matches_keccak_of_zero_word() {
        // Preimage is u256(0) — a single 32-byte zero word.
        let expected = keccak256(&[0u8; 32]);
        assert_eq!(calldata_digest(&[]), expected);
    }

    #[test]
    fn calldata_digest_three_bytes_matches_packed_preimage() {
        // u256(3) || 0xab 0xcd 0xef → 35-byte preimage.
        let mut preimage = [0u8; 35];
        preimage[31] = 3;
        preimage[32] = 0xab;
        preimage[33] = 0xcd;
        preimage[34] = 0xef;
        assert_eq!(
            calldata_digest(&[0xab, 0xcd, 0xef]),
            keccak256(&preimage),
        );
    }

    #[test]
    fn calldata_digest_distinguishes_lengths() {
        // Two preimages where one is a prefix of the other must hash
        // differently — that is the whole point of the length prefix.
        let a = calldata_digest(&[]);
        let b = calldata_digest(&[0x00]);
        assert_ne!(a, b);
    }

    #[test]
    fn calldata_digest_distinguishes_content() {
        let a = calldata_digest(&[0x00, 0x01]);
        let b = calldata_digest(&[0x01, 0x00]);
        assert_ne!(a, b);
    }

    #[test]
    fn eip712_final_hash_matches_packed_preimage() {
        let ds = [0x11u8; 32];
        let sh = [0x22u8; 32];
        let mut preimage = [0u8; 66];
        preimage[0] = 0x19;
        preimage[1] = 0x01;
        preimage[2..34].copy_from_slice(&ds);
        preimage[34..66].copy_from_slice(&sh);
        assert_eq!(eip712_final_hash(&ds, &sh), keccak256(&preimage));
    }

    #[test]
    fn eip712_final_hash_distinguishes_arguments() {
        let a = eip712_final_hash(&[0x11; 32], &[0x22; 32]);
        let b = eip712_final_hash(&[0x22; 32], &[0x11; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn calldata_and_eip712_digests_are_distinct_domains() {
        // 0x19-prefixed envelope vs unprefixed length-then-data — must
        // hash differently even when the payload bytes overlap.
        let a = calldata_digest(&[0u8; 64]);
        let b = eip712_final_hash(&[0u8; 32], &[0u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn calldata_digest_handles_4kib_buffer() {
        // Largest payload Phase 3 admits (MAX_TX_LEN). No allocation,
        // no panic — streaming Keccak handles this in O(1) stack.
        let data = [0xa5u8; 4096];
        let h = calldata_digest(&data);
        // Sanity: the digest depends on every byte, so flipping the
        // last byte must change the result.
        let mut data2 = data;
        data2[4095] ^= 1;
        assert_ne!(h, calldata_digest(&data2));
    }
}

//! Keccak-256 wrapper for the EIP-1559 envelope signing hash.

use sha3::{Digest, Keccak256};

pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

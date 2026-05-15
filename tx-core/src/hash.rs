//! Keccak-256 wrapper used wherever the EVM hashing rule applies —
//! EIP-1559 envelope signing hash, EIP-4337 `userOpHash`, EIP-712 typed
//! data, CREATE2 init-code digests. SHA-256 is used everywhere else in
//! the firmware (the SPHINCS+ stack); Keccak-256 is reserved for the
//! EVM-mandated digests.

use sha3::{Digest, Keccak256};

#[must_use]
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

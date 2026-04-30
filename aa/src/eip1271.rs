//! EIP-1271 / Solady nested-EIP-712 hash construction for the
//! `CMD_SIGN_OFFCHAIN` PersonalSign mode.
//!
//! Mirrors what `Solady.ERC1271._erc1271IsValidSignatureViaNestedEIP712`
//! computes on chain when no TypedDataSign appended-data is present in
//! the signature (which is always the case for sigs produced by this
//! firmware — our `SignatureWrapper` carries no appended data, so the
//! on-chain dispatcher always falls into the PersonalSign branch).
//!
//! ```text
//!   prefixed   = keccak256("\x19Ethereum Signed Message:\n" || itoa(len) || msg)
//!   structHash = keccak256(_PERSONAL_SIGN_TYPEHASH || prefixed)
//!   domainSep  = keccak256(EIP712_DOMAIN_TYPEHASH ||
//!                          keccak256("PQSmartWallet") ||
//!                          keccak256("1") ||
//!                          chainId ||
//!                          verifyingContract)
//!   final      = keccak256("\x19\x01" || domainSep || structHash)
//! ```
//!
//! `verifyingContract` is the proxy address derived from the bootstrap
//! C10 pubkey for `account_index` via the same CREATE2 formula
//! `cmd_get_wallet_address` uses; the bootstrap pubkey lives in
//! the secure-state cache across the unlock session.

use pqsigner_proto::{PQ_SMART_WALLET_FACTORY, PROXY_INIT_CODE_HASH};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

/// `keccak256("PersonalSign(bytes prefixed)")` — matches Solady's
/// `_PERSONAL_SIGN_TYPEHASH` in `lib/solady/src/accounts/ERC1271.sol`.
pub const PERSONAL_SIGN_TYPEHASH: [u8; 32] = [
    0x98, 0x3e, 0x65, 0xe5, 0x14, 0x8e, 0x57, 0x0c,
    0xd8, 0x28, 0xea, 0xd2, 0x31, 0xee, 0x75, 0x9a,
    0x8d, 0x79, 0x58, 0x72, 0x1a, 0x76, 0x8f, 0x93,
    0xbc, 0x44, 0x83, 0xba, 0x00, 0x5c, 0x32, 0xde,
];

/// `keccak256("EIP712Domain(string name,string version,uint256 chainId,
///                          address verifyingContract)")` — Solady's
/// `_DOMAIN_TYPEHASH` in `lib/solady/src/utils/EIP712.sol`.
pub const EIP712_DOMAIN_TYPEHASH: [u8; 32] = [
    0x8b, 0x73, 0xc3, 0xc6, 0x9b, 0xb8, 0xfe, 0x3d,
    0x51, 0x2e, 0xcc, 0x4c, 0xf7, 0x59, 0xcc, 0x79,
    0x23, 0x9f, 0x7b, 0x17, 0x9b, 0x0f, 0xfa, 0xca,
    0xa9, 0xa7, 0x5d, 0x52, 0x2b, 0x39, 0x40, 0x0f,
];

/// `keccak256("PQSmartWallet")` — the `name` field on
/// `PQSmartWallet._domainNameAndVersion`.
pub const NAME_HASH: [u8; 32] = [
    0x38, 0x5f, 0x8e, 0x06, 0xf7, 0x4d, 0x47, 0x93,
    0x2d, 0xe0, 0x6f, 0xb7, 0x65, 0x0c, 0x82, 0x75,
    0x1c, 0xef, 0x05, 0xac, 0xf6, 0xc1, 0xe7, 0xb5,
    0x0d, 0x9f, 0x82, 0x06, 0x84, 0x0d, 0xf7, 0x2f,
];

/// `keccak256("1")` — the `version` field on
/// `PQSmartWallet._domainNameAndVersion`.
pub const VERSION_HASH: [u8; 32] = [
    0xc8, 0x9e, 0xfd, 0xaa, 0x54, 0xc0, 0xf2, 0x0c,
    0x7a, 0xdf, 0x61, 0x28, 0x82, 0xdf, 0x09, 0x50,
    0xf5, 0xa9, 0x51, 0x63, 0x7e, 0x03, 0x07, 0xcd,
    0xcb, 0x4c, 0x67, 0x2f, 0x29, 0x8b, 0x8b, 0xc6,
];

/// Compute the CREATE2 proxy address from the bootstrap C10 pubkey
/// halves.
///
/// `pk_seed_32 || pk_root_32` are the same 64 bytes
/// `derive_c10_master_keypair_from_entropy` returns; the helper at
/// `cmd_get_wallet_address::run` uses the identical formula.
pub fn proxy_address(pk_seed_32: &[u8; 32], pk_root_32: &[u8; 32]) -> [u8; 20] {
    let mut salt_in = [0u8; 64];
    salt_in[..32].copy_from_slice(pk_seed_32);
    salt_in[32..].copy_from_slice(pk_root_32);
    let salt: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(salt_in);
        h.finalize().into()
    };
    let mut pre = [0u8; 1 + 20 + 32 + 32];
    pre[0] = 0xff;
    pre[1..21].copy_from_slice(&PQ_SMART_WALLET_FACTORY);
    pre[21..53].copy_from_slice(&salt);
    pre[53..85].copy_from_slice(&PROXY_INIT_CODE_HASH);
    let digest: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(pre);
        h.finalize().into()
    };
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&digest[12..]);
    addr
}

/// EIP-712 domain separator for the wallet at `verifying_contract` on
/// `chain_id`, using the firmware-baked `(name, version)` constants.
pub fn domain_separator(chain_id: u64, verifying_contract: &[u8; 20]) -> [u8; 32] {
    // abi.encode(typehash, nameHash, versionHash, chainId, verifyingContract)
    // — five 32-byte slots.
    let mut buf = [0u8; 5 * 32];
    buf[..32].copy_from_slice(&EIP712_DOMAIN_TYPEHASH);
    buf[32..64].copy_from_slice(&NAME_HASH);
    buf[64..96].copy_from_slice(&VERSION_HASH);
    // chainId left-padded to uint256.
    buf[96 + 24..128].copy_from_slice(&chain_id.to_be_bytes());
    // verifyingContract left-padded to address (20-byte right-aligned in 32).
    buf[128 + 12..160].copy_from_slice(verifying_contract);
    let mut h = Keccak256::new();
    h.update(buf);
    h.finalize().into()
}

/// `prefixed = keccak256("\x19Ethereum Signed Message:\n" || itoa(len) || msg)`.
pub fn personal_sign_prefixed_hash(msg: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(b"\x19Ethereum Signed Message:\n");
    let mut len_buf = [0u8; 20];
    let n = decimal_str(msg.len(), &mut len_buf);
    h.update(&len_buf[..n]);
    h.update(msg);
    h.finalize().into()
}

/// Final hash signed by the firmware on the PersonalSign workflow.
pub fn personal_sign_replay_safe_hash(
    chain_id: u64,
    verifying_contract: &[u8; 20],
    msg: &[u8],
) -> [u8; 32] {
    let prefixed = personal_sign_prefixed_hash(msg);

    // structHash = keccak256(PERSONAL_SIGN_TYPEHASH || prefixed)
    let struct_hash: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(PERSONAL_SIGN_TYPEHASH);
        h.update(prefixed);
        h.finalize().into()
    };

    // final = keccak256("\x19\x01" || domainSep || structHash)
    let domain_sep = domain_separator(chain_id, verifying_contract);
    let mut h = Keccak256::new();
    h.update(b"\x19\x01");
    h.update(domain_sep);
    h.update(struct_hash);
    h.finalize().into()
}

/// Format `n` into `out` as left-aligned ASCII decimal. Returns the
/// number of digits written. `out` must be ≥ 20 bytes (covers u64).
fn decimal_str(mut n: usize, out: &mut [u8]) -> usize {
    if n == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut i = 0usize;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    for j in 0..i {
        out[j] = tmp[i - 1 - j];
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: NAME_HASH = keccak256("PQSmartWallet")
    #[test]
    fn name_hash_is_keccak_of_pqsmartwallet() {
        let expected: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(b"PQSmartWallet");
            h.finalize().into()
        };
        assert_eq!(NAME_HASH, expected);
    }

    /// Sanity: VERSION_HASH = keccak256("1")
    #[test]
    fn version_hash_is_keccak_of_1() {
        let expected: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(b"1");
            h.finalize().into()
        };
        assert_eq!(VERSION_HASH, expected);
    }

    /// Sanity: PERSONAL_SIGN_TYPEHASH = keccak256("PersonalSign(bytes prefixed)")
    #[test]
    fn personal_sign_typehash_is_correct() {
        let expected: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(b"PersonalSign(bytes prefixed)");
            h.finalize().into()
        };
        assert_eq!(PERSONAL_SIGN_TYPEHASH, expected);
    }

    /// Sanity: EIP712_DOMAIN_TYPEHASH matches the standard string.
    #[test]
    fn eip712_domain_typehash_is_correct() {
        let expected: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(
                b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
            );
            h.finalize().into()
        };
        assert_eq!(EIP712_DOMAIN_TYPEHASH, expected);
    }
}

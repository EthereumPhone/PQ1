//! Uniswap Permit2 — EIP-712 permit clear-signing (`SIGN_OFFCHAIN` kind 6).
//!
//! The wallet signs a Permit2 permit as its owner: Permit2 calls the
//! wallet's ERC-1271 `isValidSignature(digest, sig)` when it verifies one.
//! The companion sends the permit packed (`pqsigner_tx::permit2`); the
//! device rebuilds the digest here from pinned constants only:
//!
//!   * domain `EIP712Domain(string name,uint256 chainId,address
//!     verifyingContract)` with `name = "Permit2"` (no version), the request
//!     chain and [`PERMIT2_ADDRESS`] — the companion's domain is never used;
//!   * the type hash chosen by the variant byte, never read from the wire;
//!   * nested `PermitDetails` / `TokenPermissions` members as `hashStruct`,
//!     arrays as `keccak(hashStruct(e0) ‖ … ‖ hashStruct(en))` — exactly
//!     `PermitHash.sol` at the deployment tag.
//!
//! Semantics the display must respect (from the pinned source, see
//! `tests/erc7730-semantic-evidence/uniswap-permit2/README.md`):
//!
//!   * `PermitSingle` / `PermitBatch` set reusable allowances. Only the exact
//!     `uint160` maximum is non-decrementing ("unlimited"). An `expiration`
//!     of 0 is stored as the current block timestamp (usable in that block
//!     only), not the Unix epoch. The allowance `nonce` must equal the stored
//!     one and is then incremented.
//!   * `PermitTransferFrom` / `PermitBatchTransferFrom` authorize ONE pull
//!     per token: the spender picks the recipient and any amount up to the
//!     signed maximum; the unordered `nonce` is burnt on use.
//!   * Permit2 takes the ERC-1271 branch only for an owner that already has
//!     code and has no ERC-6492 unwrap — kind 6 therefore requires a deployed
//!     wallet (enforced by the handler).

use pqsigner_erc7730::display::render::nested::{hash_struct, hash_struct_array};
use pqsigner_tx::permit2::{Permit2Core, Permit2Entry};
use sphincs_tz_shared::{
    PERMIT2_MAX_TOKENS, PERMIT2_VARIANT_BATCH, PERMIT2_VARIANT_BATCH_TRANSFER,
    PERMIT2_VARIANT_SINGLE, PERMIT2_VARIANT_TRANSFER,
};

use super::{final_digest, keccak, Eip712Error};

pub use sphincs_tz_shared::PERMIT2_ADDRESS;

pub mod verify;
pub use verify::{verify_offchain_permit2, VerifiedPermit2};

#[cfg(test)]
pub(crate) mod test_vectors;

/// `keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)")`
/// preimage — Permit2's domain has no `version`.
pub const DOMAIN_NAME_ONLY_PREIMAGE: &[u8] =
    b"EIP712Domain(string name,uint256 chainId,address verifyingContract)";
/// The domain `name`.
pub const PERMIT2_DOMAIN_NAME: &[u8] = b"Permit2";

/// Type preimages, exactly as `PermitHash.sol` declares them.
pub const PERMIT_DETAILS_PREIMAGE: &[u8] =
    b"PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
pub const PERMIT_SINGLE_PREIMAGE: &[u8] = b"PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
pub const PERMIT_BATCH_PREIMAGE: &[u8] = b"PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
pub const TOKEN_PERMISSIONS_PREIMAGE: &[u8] = b"TokenPermissions(address token,uint256 amount)";
pub const PERMIT_TRANSFER_FROM_PREIMAGE: &[u8] = b"PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)";
pub const PERMIT_BATCH_TRANSFER_FROM_PREIMAGE: &[u8] = b"PermitBatchTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)";

// The hashes of the preimages above, pinned (host test
// `typehashes_are_keccak_of_preimages`) so signing never depends on a
// preimage edit going unnoticed.
pub const PERMIT_DETAILS_TYPEHASH: [u8; 32] = [
    0x65, 0x62, 0x6c, 0xad, 0x6c, 0xb9, 0x64, 0x93, 0xbf, 0x6f, 0x5e, 0xbe, 0xa2, 0x87, 0x56, 0xc9,
    0x66, 0xf0, 0x23, 0xab, 0x9e, 0x8a, 0x83, 0xa7, 0x10, 0x18, 0x49, 0xd5, 0x57, 0x3b, 0x36, 0x78,
];
pub const PERMIT_SINGLE_TYPEHASH: [u8; 32] = [
    0xf3, 0x84, 0x1c, 0xd1, 0xff, 0x00, 0x85, 0x02, 0x6a, 0x63, 0x27, 0xb6, 0x20, 0xb6, 0x79, 0x97,
    0xce, 0x40, 0xf2, 0x82, 0xc8, 0x8a, 0x8e, 0x90, 0x5a, 0x7a, 0x56, 0x26, 0xe3, 0x10, 0xf3, 0xd0,
];
pub const PERMIT_BATCH_TYPEHASH: [u8; 32] = [
    0xaf, 0x1b, 0x0d, 0x30, 0xd2, 0xca, 0xb0, 0x38, 0x0e, 0x68, 0xf0, 0x68, 0x90, 0x07, 0xe3, 0x25,
    0x49, 0x93, 0xc5, 0x96, 0xf2, 0xfd, 0xd0, 0xaa, 0xa7, 0xf4, 0xd0, 0x4f, 0x79, 0x44, 0x08, 0x63,
];
pub const TOKEN_PERMISSIONS_TYPEHASH: [u8; 32] = [
    0x61, 0x83, 0x58, 0xac, 0x3d, 0xb8, 0xdc, 0x27, 0x4f, 0x0c, 0xd8, 0x82, 0x9d, 0xa7, 0xe2, 0x34,
    0xbd, 0x48, 0xcd, 0x73, 0xc4, 0xa7, 0x40, 0xae, 0xde, 0x1a, 0xde, 0xc9, 0x84, 0x6d, 0x06, 0xa1,
];
pub const PERMIT_TRANSFER_FROM_TYPEHASH: [u8; 32] = [
    0x93, 0x9c, 0x21, 0xa4, 0x8a, 0x8d, 0xbe, 0x3a, 0x9a, 0x24, 0x04, 0xa1, 0xd4, 0x66, 0x91, 0xe4,
    0xd3, 0x9f, 0x65, 0x83, 0xd6, 0xec, 0x6b, 0x35, 0x71, 0x46, 0x04, 0xc9, 0x86, 0xd8, 0x01, 0x06,
];
pub const PERMIT_BATCH_TRANSFER_FROM_TYPEHASH: [u8; 32] = [
    0xfc, 0xf3, 0x5f, 0x5a, 0xc6, 0xa2, 0xc2, 0x88, 0x68, 0xdc, 0x44, 0xc3, 0x02, 0x16, 0x64, 0x70,
    0x26, 0x62, 0x39, 0x19, 0x5f, 0x02, 0xb0, 0xee, 0x40, 0x83, 0x34, 0x82, 0x93, 0x33, 0xb7, 0x66,
];

/// The exact `uint160` maximum: AllowanceTransfer leaves such an allowance
/// untouched on every transfer — the only "unlimited" a permit can set.
pub const UINT160_MAX_WORD: [u8; 32] = {
    let mut w = [0xffu8; 32];
    let mut i = 0;
    while i < 12 {
        w[i] = 0;
        i += 1;
    }
    w
};

/// Permit2's domain separator on `chain_id`.
pub fn domain_separator(chain_id: u64) -> [u8; 32] {
    let mut buf = [0u8; 32 * 4];
    buf[0..32].copy_from_slice(&keccak(DOMAIN_NAME_ONLY_PREIMAGE));
    buf[32..64].copy_from_slice(&keccak(PERMIT2_DOMAIN_NAME));
    buf[64 + 24..96].copy_from_slice(&chain_id.to_be_bytes());
    buf[96 + 12..128].copy_from_slice(&PERMIT2_ADDRESS);
    keccak(&buf)
}

fn address_word(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

fn u64_word(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

/// `encodeData(PermitDetails)`: token, amount, expiration, nonce.
fn details_ed(e: &Permit2Entry) -> [u8; 128] {
    let mut ed = [0u8; 128];
    ed[0..32].copy_from_slice(&address_word(&e.token));
    ed[32..64].copy_from_slice(&e.amount);
    ed[64..96].copy_from_slice(&u64_word(e.expiration));
    ed[96..128].copy_from_slice(&u64_word(e.nonce));
    ed
}

/// `encodeData(TokenPermissions)`: token, amount.
fn permissions_ed(e: &Permit2Entry) -> [u8; 64] {
    let mut ed = [0u8; 64];
    ed[0..32].copy_from_slice(&address_word(&e.token));
    ed[32..64].copy_from_slice(&e.amount);
    ed
}

/// The member word of the nested struct (single) or struct array (batch).
fn entries_word(core: &Permit2Core) -> [u8; 32] {
    let live = core.live();
    if core.is_allowance() {
        let mut eds = [[0u8; 128]; PERMIT2_MAX_TOKENS];
        for (ed, e) in eds.iter_mut().zip(live) {
            *ed = details_ed(e);
        }
        if core.variant == PERMIT2_VARIANT_SINGLE {
            return hash_struct(&PERMIT_DETAILS_TYPEHASH, &eds[0]);
        }
        let mut refs: [&[u8]; PERMIT2_MAX_TOKENS] = [&[]; PERMIT2_MAX_TOKENS];
        for (r, ed) in refs.iter_mut().zip(eds.iter()) {
            *r = ed;
        }
        hash_struct_array(&PERMIT_DETAILS_TYPEHASH, &refs[..live.len()])
    } else {
        let mut eds = [[0u8; 64]; PERMIT2_MAX_TOKENS];
        for (ed, e) in eds.iter_mut().zip(live) {
            *ed = permissions_ed(e);
        }
        if core.variant == PERMIT2_VARIANT_TRANSFER {
            return hash_struct(&TOKEN_PERMISSIONS_TYPEHASH, &eds[0]);
        }
        let mut refs: [&[u8]; PERMIT2_MAX_TOKENS] = [&[]; PERMIT2_MAX_TOKENS];
        for (r, ed) in refs.iter_mut().zip(eds.iter()) {
            *r = ed;
        }
        hash_struct_array(&TOKEN_PERMISSIONS_TYPEHASH, &refs[..live.len()])
    }
}

/// `hashStruct` of the permit.
pub fn struct_hash(core: &Permit2Core) -> [u8; 32] {
    let typehash = match core.variant {
        PERMIT2_VARIANT_SINGLE => &PERMIT_SINGLE_TYPEHASH,
        PERMIT2_VARIANT_BATCH => &PERMIT_BATCH_TYPEHASH,
        PERMIT2_VARIANT_TRANSFER => &PERMIT_TRANSFER_FROM_TYPEHASH,
        // `decode_core` admits nothing else.
        _ => &PERMIT_BATCH_TRANSFER_FROM_TYPEHASH,
    };
    debug_assert!(core.variant <= PERMIT2_VARIANT_BATCH_TRANSFER);
    let mut buf = [0u8; 32 * 5];
    buf[0..32].copy_from_slice(typehash);
    buf[32..64].copy_from_slice(&entries_word(core));
    buf[64..96].copy_from_slice(&address_word(&core.spender));
    let n = if core.is_allowance() {
        // PermitSingle / PermitBatch: (details, spender, sigDeadline)
        buf[96..128].copy_from_slice(&core.deadline);
        128
    } else {
        // PermitTransferFrom / PermitBatchTransferFrom: (permitted, spender, nonce, deadline)
        buf[96..128].copy_from_slice(&core.nonce);
        buf[128..160].copy_from_slice(&core.deadline);
        160
    };
    keccak(&buf[..n])
}

/// The EIP-712 digest Permit2 hands to `isValidSignature`. Refuses a permit
/// whose packed `chain_id` is not the request chain (the chain of both the
/// Permit2 domain and the wallet's replay-safe nesting).
pub fn compute_digest(core: &Permit2Core, chain_id: u64) -> Result<[u8; 32], Eip712Error> {
    if core.chain_id != chain_id {
        return Err(Eip712Error::ChainIdMismatch);
    }
    Ok(final_digest(&domain_separator(chain_id), &struct_hash(core)))
}

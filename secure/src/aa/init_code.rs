//! initCode construction for first-deployment ERC-4337 UserOps.
//!
//! When a wallet has not yet been deployed on a given chain, the UserOp
//! must carry an `initCode` field that tells the EntryPoint how to
//! deploy the smart account. For PQSigner, the initCode is:
//!
//! ```text
//!   factory_address(20) || abi.encodeCall(
//!       createAccount,
//!       (bootstrapPkSeed, bootstrapPkRoot, mainPkSeed, mainPkRoot, bootstrapSig)
//!   )
//! ```
//!
//! where `bootstrapSig` is a SPHINCS+C7 signature over
//! `keccak256("PQWALLET_INIT_V1" || mainPkSeed || mainPkRoot)` — a
//! chain-agnostic authorization that proves the bootstrap key holder
//! approved this initial main signer.
//!
//! The factory address is currently a placeholder (null address).
//! **It MUST be replaced with the actual deployed
//! `PQCoinbaseSmartWalletFactory` address before production.**
//!
//! All functions in this module are pure (no SE access, no UI) and
//! operate on stack-only buffers.

use sha3::{Digest, Keccak256};
use sphincs_tz_shared::{
    CREATE_ACCOUNT_SELECTOR, FACTORY_ADDRESS, INIT_CODE_LEN, SIGNATURE_LEN,
};

/// Domain tag signed by the bootstrap key to authorize factory deployment.
/// Must match `PQCoinbaseSmartWalletFactory.createAccount()` exactly:
///   `keccak256(abi.encodePacked("PQWALLET_INIT_V1", mainPkSeed, mainPkRoot))`
const PQWALLET_INIT_TAG: &[u8] = b"PQWALLET_INIT_V1";

/// Compute the authorization message hash that the bootstrap key signs
/// to authorize factory deployment with a given initial main signer:
///
///   `keccak256("PQWALLET_INIT_V1" || mainPkSeed || mainPkRoot)`
///
/// The pk_seed and pk_root are bytes32 (16 real bytes right-padded to
/// 32), matching the Solidity `abi.encodePacked` encoding.
pub fn compute_auth_message(
    main_pk_seed: &[u8; 32],
    main_pk_root: &[u8; 32],
) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(PQWALLET_INIT_TAG);
    h.update(main_pk_seed);
    h.update(main_pk_root);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Compute `keccak256(initCode)` by streaming the initCode components
/// through a Keccak256 hasher. No large buffer needed — each piece is
/// fed incrementally.
///
/// The ABI encoding of `createAccount(bytes32,bytes32,bytes32,bytes32,bytes)`:
/// ```text
///   factory(20) + selector(4) + bootstrapPkSeed(32) + bootstrapPkRoot(32)
///   + mainPkSeed(32) + mainPkRoot(32) + offset(32) + sigLen(32)
///   + sig(3704) + padding(24) = 3928
/// ```
pub fn compute_init_code_hash(
    bootstrap_pk_seed: &[u8; 32],
    bootstrap_pk_root: &[u8; 32],
    main_pk_seed: &[u8; 32],
    main_pk_root: &[u8; 32],
    bootstrap_sig: &[u8],
) -> [u8; 32] {
    debug_assert_eq!(bootstrap_sig.len(), SIGNATURE_LEN);

    let mut h = Keccak256::new();

    // Factory address (20 bytes)
    h.update(&FACTORY_ADDRESS);

    // Selector (4 bytes)
    h.update(&CREATE_ACCOUNT_SELECTOR);

    // ABI-encoded static args (4 × bytes32)
    h.update(bootstrap_pk_seed);
    h.update(bootstrap_pk_root);
    h.update(main_pk_seed);
    h.update(main_pk_root);

    // Offset to dynamic `bytes` arg = 0xA0 (160), left-padded to 32 bytes
    let mut offset_word = [0u8; 32];
    offset_word[31] = 0xA0;
    h.update(&offset_word);

    // Length of bootstrapSig as uint256
    let mut len_word = [0u8; 32];
    len_word[24..32].copy_from_slice(&(SIGNATURE_LEN as u64).to_be_bytes());
    h.update(&len_word);

    // Bootstrap signature data (3,704 bytes)
    h.update(bootstrap_sig);

    // ABI zero-padding to 32-byte boundary (3704 % 32 = 8, need 24 zeros)
    let padding = ((SIGNATURE_LEN + 31) / 32) * 32 - SIGNATURE_LEN;
    let zeros = [0u8; 32];
    h.update(&zeros[..padding]);

    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Write the full initCode to an NS output buffer using volatile writes.
///
/// Returns the number of bytes written (always `INIT_CODE_LEN`).
///
/// # Safety
///
/// `out_ptr` must point to a validated NS-writable region of at least
/// `INIT_CODE_LEN` bytes.
pub unsafe fn write_init_code_to_ns(
    out_ptr: *mut u8,
    bootstrap_pk_seed: &[u8; 32],
    bootstrap_pk_root: &[u8; 32],
    main_pk_seed: &[u8; 32],
    main_pk_root: &[u8; 32],
    bootstrap_sig: &[u8],
) -> usize {
    debug_assert_eq!(bootstrap_sig.len(), SIGNATURE_LEN);

    let mut pos: usize = 0;

    // Factory address (20 bytes)
    for b in &FACTORY_ADDRESS {
        core::ptr::write_volatile(out_ptr.add(pos), *b);
        pos += 1;
    }

    // Selector (4 bytes)
    for b in &CREATE_ACCOUNT_SELECTOR {
        core::ptr::write_volatile(out_ptr.add(pos), *b);
        pos += 1;
    }

    // bootstrapPkSeed (bytes32)
    write_word_volatile(out_ptr, &mut pos, bootstrap_pk_seed);

    // bootstrapPkRoot (bytes32)
    write_word_volatile(out_ptr, &mut pos, bootstrap_pk_root);

    // mainPkSeed (bytes32)
    write_word_volatile(out_ptr, &mut pos, main_pk_seed);

    // mainPkRoot (bytes32)
    write_word_volatile(out_ptr, &mut pos, main_pk_root);

    // Offset to dynamic `bytes` arg = 0xA0 (160)
    let mut offset_word = [0u8; 32];
    offset_word[31] = 0xA0;
    write_word_volatile(out_ptr, &mut pos, &offset_word);

    // Length of bootstrapSig
    let mut len_word = [0u8; 32];
    len_word[24..32].copy_from_slice(&(SIGNATURE_LEN as u64).to_be_bytes());
    write_word_volatile(out_ptr, &mut pos, &len_word);

    // Bootstrap signature data (3,704 bytes)
    for i in 0..SIGNATURE_LEN {
        core::ptr::write_volatile(out_ptr.add(pos), bootstrap_sig[i]);
        pos += 1;
    }

    // ABI zero-padding to 32-byte boundary (3704 % 32 = 8, need 24 zeros)
    let padding = ((SIGNATURE_LEN + 31) / 32) * 32 - SIGNATURE_LEN;
    for _ in 0..padding {
        core::ptr::write_volatile(out_ptr.add(pos), 0u8);
        pos += 1;
    }

    debug_assert_eq!(pos, INIT_CODE_LEN);
    pos
}

/// Extract pk_seed and pk_root from a 32-byte SPHINCS+C7 verifying key,
/// each right-padded to bytes32 for Solidity ABI compatibility.
///
/// VK layout: `pk_seed[16] || pk_root[16]`
/// Output: two `[u8; 32]` with real bytes in `[0..16)` and zeros in `[16..32)`.
pub fn vk_to_pk_components(vk: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut pk_seed = [0u8; 32];
    let mut pk_root = [0u8; 32];
    pk_seed[..16].copy_from_slice(&vk[..16]);
    pk_root[..16].copy_from_slice(&vk[16..32]);
    (pk_seed, pk_root)
}

/// Write a 32-byte word via volatile writes, advancing `pos`.
#[inline]
unsafe fn write_word_volatile(out_ptr: *mut u8, pos: &mut usize, word: &[u8; 32]) {
    for b in word {
        core::ptr::write_volatile(out_ptr.add(*pos), *b);
        *pos += 1;
    }
}

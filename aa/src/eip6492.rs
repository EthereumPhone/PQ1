//! ERC-6492 — Signature Validation for Predeploy Contracts.
//!
//! When a smart-wallet contract has not yet been deployed at its
//! CREATE2 address, a dapp can't ask it for an EIP-1271 verdict on a
//! signature: there's no code there to call. [ERC-6492][eip6492] solves
//! this by letting the signer wrap the inner EIP-1271 signature with
//! the factory address + factory calldata that **will** deploy the
//! exact wallet, suffixed with a 32-byte magic constant so universal
//! verifiers (Solady `SignatureCheckerLib`,
//! Ambire `UniversalSigValidator`, viem `verifyMessage`, …) can detect
//! the wrapping, deploy the wallet via `eth_call`, and verify the
//! inner sig against the freshly-deployed account — all in one
//! `eth_call`, no on-chain state change.
//!
//! Wire format (Solidity ABI):
//!
//! ```text
//!   abi.encode(
//!     address create2Factory,
//!     bytes   factoryCalldata,
//!     bytes   signatureWrapper      // what isValidSignature(hash, _) sees
//!   ) || MAGIC                       // 0x6492…6492 (32 bytes)
//! ```
//!
//! This module is pure logic, `no_std`, and **only** handles the outer
//! wrapping. The caller supplies the inner `signatureWrapper` (already
//! ABI-encoded as `(uint256 ownerIndex, bytes c10Sig)` in our case) and
//! the factory + factoryCalldata bytes. Nothing in this module touches
//! the SPHINCS+ key material — the inner sig is opaque to it.
//!
//! [eip6492]: https://eips.ethereum.org/EIPS/eip-6492

use pqsigner_proto::{
    EIP6492_BLOB_LEN, EIP6492_FACTORY_CALLDATA_LEN, EIP6492_FACTORY_CALLDATA_PADDED,
    EIP6492_INNER_WRAPPER_LEN, EIP6492_MAGIC,
};

/// ABI-encode `(address, bytes, bytes) || MAGIC` into `out`.
///
/// The output buffer is exactly [`EIP6492_BLOB_LEN`] (8640 bytes) for
/// our fixed-size factoryCalldata (4260 bytes) + inner wrapper (4128
/// bytes). All slots are filled — there is no need to pre-zero `out`.
///
/// Universal-verifier compatibility: the resulting blob validates
/// against Ambire's `UniversalSigValidator`, Solady's
/// `SignatureCheckerLib.isValidERC6492SignatureNow`, and viem's
/// `verifyMessage` / `serializeErc6492Signature` round-trip.
///
/// Layout written into `out` (Solidity ABI for
/// `encode(address, bytes, bytes)` followed by the 32-byte magic
/// suffix):
///
/// ```text
///   [   0..  32)  factory (right-aligned, static)
///   [  32..  64)  offset to fc                  = 0x60
///   [  64..  96)  offset to innerSig            = 0x60 + 32 + fc_padded
///   [  96.. 128)  fc length                     = EIP6492_FACTORY_CALLDATA_LEN
///   [ 128.. 128+padded)        fc bytes + zero pad
///   [ 128+padded.. +32)        innerSig length  = EIP6492_INNER_WRAPPER_LEN
///   [ +32 .. +32+inner)        innerSig bytes (already 32-aligned)
///   [ EIP6492_BLOB_LEN-32 ..)  EIP6492_MAGIC
/// ```
pub fn wrap_signature(
    out: &mut [u8; EIP6492_BLOB_LEN],
    factory: &[u8; 20],
    factory_calldata: &[u8],
    inner_sig_wrapper: &[u8; EIP6492_INNER_WRAPPER_LEN],
) {
    assert_eq!(
        factory_calldata.len(),
        EIP6492_FACTORY_CALLDATA_LEN,
        "ERC-6492 factoryCalldata must equal EIP6492_FACTORY_CALLDATA_LEN"
    );

    // ── 1. Zero the buffer so unused padding bytes are clean.
    out.fill(0);

    // ── 2. ABI-encode `(address, bytes, bytes)`.
    //
    // Solidity flattens the tuple into head + tail. `address` is static
    // and is written inline; the two `bytes` are dynamic and the head
    // stores offsets from the start of the tuple to where their data
    // begins in the tail.
    //
    //   head:
    //     [ 0..32)   address (right-aligned, static)
    //     [32..64)   offset to fc                = 0x60
    //     [64..96)   offset to innerSig          = 0x60 + 32 + fc_padded
    //
    //   tail:
    //     [ 96..128)            fc length
    //     [128..128+fc_padded)  fc data + zero pad
    //     [next..+32)           innerSig length
    //     [next..+innerSig_len) innerSig data
    //     [last 32 bytes)       EIP-6492 magic
    //
    // Confirmed against viem `encodeAbiParameters` and `cast abi-encode`.

    // Head [0..96):
    //   [0..32)   factory address (right-aligned, static)
    //   [32..64)  offset to fc            = 0x60
    //   [64..96)  offset to innerSig      = 0x60 + 32 + fc_padded
    out[12..32].copy_from_slice(factory);
    write_be_u256_small(&mut out[32..64], 0x60);
    let inner_sig_offset: u64 = (0x60 + 32 + EIP6492_FACTORY_CALLDATA_PADDED) as u64;
    write_be_u256_small(&mut out[64..96], inner_sig_offset);

    // Tail — fc length + data + zero pad.
    write_be_u256_small(&mut out[96..128], EIP6492_FACTORY_CALLDATA_LEN as u64);
    out[128..128 + EIP6492_FACTORY_CALLDATA_LEN].copy_from_slice(factory_calldata);
    // Pad bytes already zero from out.fill(0).

    // Tail — innerSig length + data (already 32-aligned, no pad).
    let sig_len_off = 128 + EIP6492_FACTORY_CALLDATA_PADDED;
    write_be_u256_small(&mut out[sig_len_off..sig_len_off + 32], EIP6492_INNER_WRAPPER_LEN as u64);
    let sig_data_off = sig_len_off + 32;
    out[sig_data_off..sig_data_off + EIP6492_INNER_WRAPPER_LEN]
        .copy_from_slice(inner_sig_wrapper);

    // Magic suffix.
    let magic_off = EIP6492_BLOB_LEN - 32;
    out[magic_off..].copy_from_slice(&EIP6492_MAGIC);

    debug_assert_eq!(sig_data_off + EIP6492_INNER_WRAPPER_LEN, magic_off);
}

/// Write a small u64 value into a 32-byte big-endian slot, zeroing the
/// top 24 bytes.
fn write_be_u256_small(slot: &mut [u8], v: u64) {
    debug_assert_eq!(slot.len(), 32);
    for b in &mut slot[..24] {
        *b = 0;
    }
    slot[24..32].copy_from_slice(&v.to_be_bytes());
}

/// Detection helper: returns `true` iff `sig` ends with [`EIP6492_MAGIC`].
/// Mirrors the unwrap check in every reference verifier.
pub fn has_magic_suffix(sig: &[u8]) -> bool {
    sig.len() >= 32 && sig[sig.len() - 32..] == EIP6492_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqsigner_proto::{
        PQ_CREATE_ACCOUNT_SELECTOR, PQ_SMART_WALLET_FACTORY, SIG_WRAPPER_LEN,
    };

    fn make_calldata() -> [u8; EIP6492_FACTORY_CALLDATA_LEN] {
        // A non-trivial fake: selector + a recognisable byte pattern so
        // we can spot it when slicing the encoded tuple back out.
        let mut fc = [0u8; EIP6492_FACTORY_CALLDATA_LEN];
        fc[..4].copy_from_slice(&PQ_CREATE_ACCOUNT_SELECTOR);
        for (i, b) in fc[4..].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        fc
    }

    fn make_inner_wrapper() -> [u8; SIG_WRAPPER_LEN] {
        // A non-trivial fake SignatureWrapper. Pattern is recognisable
        // and 32-aligned.
        let mut sig = [0u8; SIG_WRAPPER_LEN];
        sig[31] = 0x01; // ownerIndex = 1
        sig[63] = 0x40; // bytes offset = 0x40
        sig[64..68].copy_from_slice(&[0x00, 0x00, 0x0f, 0xa8]); // length = 4008 (sloppy little)
        // Inner C10 sig bytes
        for (i, b) in sig[96..].iter_mut().enumerate() {
            *b = ((i + 17) % 251) as u8;
        }
        sig
    }

    #[test]
    fn blob_length_matches_constant() {
        let fc = make_calldata();
        let inner = make_inner_wrapper();
        let mut blob = [0u8; EIP6492_BLOB_LEN];
        wrap_signature(&mut blob, &PQ_SMART_WALLET_FACTORY, &fc, &inner);
        assert_eq!(blob.len(), EIP6492_BLOB_LEN);
        assert_eq!(blob.len(), 8608);
    }

    #[test]
    fn magic_suffix_present_and_detected() {
        let fc = make_calldata();
        let inner = make_inner_wrapper();
        let mut blob = [0u8; EIP6492_BLOB_LEN];
        wrap_signature(&mut blob, &PQ_SMART_WALLET_FACTORY, &fc, &inner);

        assert_eq!(&blob[blob.len() - 32..], &EIP6492_MAGIC);
        assert!(has_magic_suffix(&blob));
    }

    #[test]
    fn address_right_aligned_in_first_slot() {
        let fc = make_calldata();
        let inner = make_inner_wrapper();
        let mut blob = [0u8; EIP6492_BLOB_LEN];
        wrap_signature(&mut blob, &PQ_SMART_WALLET_FACTORY, &fc, &inner);

        // Top 12 bytes of the address slot must be zero.
        assert_eq!(&blob[0..12], &[0u8; 12]);
        // Bottom 20 bytes match the factory address.
        assert_eq!(&blob[12..32], &PQ_SMART_WALLET_FACTORY);
    }

    #[test]
    fn offsets_match_abi_layout() {
        let fc = make_calldata();
        let inner = make_inner_wrapper();
        let mut blob = [0u8; EIP6492_BLOB_LEN];
        wrap_signature(&mut blob, &PQ_SMART_WALLET_FACTORY, &fc, &inner);

        // Offset to fc = 0x60
        let mut expected = [0u8; 32];
        expected[31] = 0x60;
        assert_eq!(&blob[32..64], &expected);

        // Offset to innerSig = 0x60 + 32 + fc_padded
        let inner_off = 0x60u64 + 32 + EIP6492_FACTORY_CALLDATA_PADDED as u64;
        let mut want = [0u8; 32];
        want[24..32].copy_from_slice(&inner_off.to_be_bytes());
        assert_eq!(&blob[64..96], &want);
    }

    #[test]
    fn factory_calldata_length_and_data_match() {
        let fc = make_calldata();
        let inner = make_inner_wrapper();
        let mut blob = [0u8; EIP6492_BLOB_LEN];
        wrap_signature(&mut blob, &PQ_SMART_WALLET_FACTORY, &fc, &inner);

        // Length at [96..128)
        let mut expected = [0u8; 32];
        let len_be = (EIP6492_FACTORY_CALLDATA_LEN as u64).to_be_bytes();
        expected[24..32].copy_from_slice(&len_be);
        assert_eq!(&blob[96..128], &expected);

        // Data at [128..128+fc_len)
        assert_eq!(&blob[128..128 + EIP6492_FACTORY_CALLDATA_LEN], &fc[..]);

        // Padding from 128+fc_len..128+fc_padded must be zero (4260 → 4288 = 28 zeros).
        let pad_start = 128 + EIP6492_FACTORY_CALLDATA_LEN;
        let pad_end = 128 + EIP6492_FACTORY_CALLDATA_PADDED;
        assert!(blob[pad_start..pad_end].iter().all(|&b| b == 0));
    }

    #[test]
    fn inner_signature_length_and_data_match() {
        let fc = make_calldata();
        let inner = make_inner_wrapper();
        let mut blob = [0u8; EIP6492_BLOB_LEN];
        wrap_signature(&mut blob, &PQ_SMART_WALLET_FACTORY, &fc, &inner);

        let sig_len_off = 128 + EIP6492_FACTORY_CALLDATA_PADDED;
        let mut expected = [0u8; 32];
        let len_be = (EIP6492_INNER_WRAPPER_LEN as u64).to_be_bytes();
        expected[24..32].copy_from_slice(&len_be);
        assert_eq!(&blob[sig_len_off..sig_len_off + 32], &expected);

        let sig_data_off = sig_len_off + 32;
        assert_eq!(
            &blob[sig_data_off..sig_data_off + EIP6492_INNER_WRAPPER_LEN],
            &inner[..]
        );
        // The inner wrapper is 32-aligned so no padding follows — magic
        // begins immediately after.
        assert_eq!(sig_data_off + EIP6492_INNER_WRAPPER_LEN, EIP6492_BLOB_LEN - 32);
    }

    #[test]
    fn has_magic_suffix_rejects_short_or_bare() {
        assert!(!has_magic_suffix(&[]));
        assert!(!has_magic_suffix(&[0u8; 31]));
        assert!(!has_magic_suffix(&[0u8; 32]));

        let mut buf = [0u8; 64];
        buf[32..].copy_from_slice(&EIP6492_MAGIC);
        assert!(has_magic_suffix(&buf));
    }
}

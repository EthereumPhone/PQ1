//! Permit2 digest vectors. The references are independent: viem 2.56.3
//! `hashTypedData` over the equivalent typed data (script below), and the
//! Ethereum domain separator observed on-chain at the deployment
//! (`tests/erc7730-semantic-evidence/uniswap-permit2`).
//!
//! ```text
//! // node, viem 2.56.3 — P2 = 0x000000000022d473030f116ddee9f6b43ac78ba3
//! hashTypedData({ domain: { name: 'Permit2', chainId, verifyingContract: P2 },
//!                 types, primaryType, message })
//! ```
//! with the messages built by `single()`, `batch()`, `transfer()` and
//! `batch_transfer()` below (USDC 0x8335…2913 / WETH 0x4200…0006 on Base,
//! USDC 0xa0b8…eb48 on Ethereum, spenders 0x6ff5…9b43 / 0x3fc9…7fad).

extern crate std;

use super::*;
use pqsigner_tx::permit2::decode_core;
use std::vec::Vec;

fn h32(s: &str) -> [u8; 32] {
    let v: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap()).collect();
    v.try_into().unwrap()
}

fn a20(s: &str) -> [u8; 20] {
    let v: Vec<u8> = (0..20).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap()).collect();
    v.try_into().unwrap()
}

pub(crate) const USDC_BASE: &str = "833589fcd6edb6e08f4c7c32d4f71b54bda02913";
pub(crate) const WETH_BASE: &str = "4200000000000000000000000000000000000006";
pub(crate) const USDC_ETH: &str = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
pub(crate) const UR_BASE: &str = "6ff5693b99212da76ad316178a184ab56d299b43";
pub(crate) const UR_ETH: &str = "3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad";

fn u256_be(lo: u128, hi: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[..16].copy_from_slice(&hi.to_be_bytes());
    w[16..].copy_from_slice(&lo.to_be_bytes());
    w
}

fn allowance_head(variant: u8, chain: u64, spender: &str, sig_deadline: [u8; 32], n: u8) -> Vec<u8> {
    let mut v = std::vec![variant];
    v.extend_from_slice(&chain.to_be_bytes());
    v.extend_from_slice(&a20(spender));
    v.extend_from_slice(&sig_deadline);
    v.push(n);
    v
}

fn details(v: &mut Vec<u8>, token: &str, amount160: [u8; 20], expiration: u64, nonce: u64) {
    v.extend_from_slice(&a20(token));
    v.extend_from_slice(&amount160);
    v.extend_from_slice(&expiration.to_be_bytes()[2..]);
    v.extend_from_slice(&nonce.to_be_bytes()[2..]);
}

fn amount160(x: u128) -> [u8; 20] {
    let mut a = [0u8; 20];
    a[4..].copy_from_slice(&x.to_be_bytes());
    a
}

fn transfer_head(variant: u8, chain: u64, spender: &str, nonce: [u8; 32], deadline: [u8; 32], n: u8) -> Vec<u8> {
    let mut v = std::vec![variant];
    v.extend_from_slice(&chain.to_be_bytes());
    v.extend_from_slice(&a20(spender));
    v.extend_from_slice(&nonce);
    v.extend_from_slice(&deadline);
    v.push(n);
    v
}

pub(crate) fn single() -> Vec<u8> {
    let mut v = allowance_head(PERMIT2_VARIANT_SINGLE, 8453, UR_BASE, u256_be(1_767_225_600, 0), 1);
    details(&mut v, USDC_BASE, amount160(1_000_000_000), 1_798_761_600, 3);
    v
}

pub(crate) fn batch() -> Vec<u8> {
    let mut v = allowance_head(PERMIT2_VARIANT_BATCH, 8453, UR_BASE, u256_be(1_767_225_600, 0), 2);
    details(&mut v, USDC_BASE, amount160(1_000_000_000), 1_798_761_600, 3);
    details(&mut v, WETH_BASE, [0xff; 20], 0, 0);
    v
}

pub(crate) fn transfer() -> Vec<u8> {
    let mut v = transfer_head(PERMIT2_VARIANT_TRANSFER, 1, UR_ETH, u256_be(42, 0), u256_be(1_767_225_600, 0), 1);
    v.extend_from_slice(&a20(USDC_ETH));
    v.extend_from_slice(&u256_be(500_000_000, 0));
    v
}

pub(crate) fn batch_transfer() -> Vec<u8> {
    // nonce = 2^200 + 7, deadline = 2^256 - 1
    let mut nonce = [0u8; 32];
    nonce[6] = 1;
    nonce[31] = 7;
    let mut v = transfer_head(PERMIT2_VARIANT_BATCH_TRANSFER, 8453, UR_BASE, nonce, [0xff; 32], 2);
    v.extend_from_slice(&a20(USDC_BASE));
    v.extend_from_slice(&[0xff; 32]);
    v.extend_from_slice(&a20(WETH_BASE));
    v.extend_from_slice(&u256_be(123_456_789_012_345_678, 0));
    v
}

pub(crate) const SINGLE_DIGEST: &str = "497c41366bda0e8bb4d9744d263a0979a0eeb5df293ced92d4aba868ac946888";
pub(crate) const BATCH_DIGEST: &str = "83e5dfb254dc96d7dfda2ea103d5063b019939ec087e15862bee88d416c7a4ba";
pub(crate) const TRANSFER_DIGEST: &str = "17146f9e0b8c3404e9e667f3655b031304f4ef59e2052b36f674e27c1515e8fe";
pub(crate) const BATCH_TRANSFER_DIGEST: &str = "a13082a184d56e9a727c02b337098b02c57c3fe4e8f78f01a554b2f7f11ebede";

#[test]
fn typehashes_are_keccak_of_preimages() {
    assert_eq!(keccak(PERMIT_DETAILS_PREIMAGE), PERMIT_DETAILS_TYPEHASH);
    assert_eq!(keccak(PERMIT_SINGLE_PREIMAGE), PERMIT_SINGLE_TYPEHASH);
    assert_eq!(keccak(PERMIT_BATCH_PREIMAGE), PERMIT_BATCH_TYPEHASH);
    assert_eq!(keccak(TOKEN_PERMISSIONS_PREIMAGE), TOKEN_PERMISSIONS_TYPEHASH);
    assert_eq!(keccak(PERMIT_TRANSFER_FROM_PREIMAGE), PERMIT_TRANSFER_FROM_TYPEHASH);
    assert_eq!(keccak(PERMIT_BATCH_TRANSFER_FROM_PREIMAGE), PERMIT_BATCH_TRANSFER_FROM_TYPEHASH);
    // The four primary types reference their member type after their own
    // definition, exactly as EIP-712 `encodeType` orders them.
    assert!(PERMIT_SINGLE_PREIMAGE.ends_with(PERMIT_DETAILS_PREIMAGE));
    assert!(PERMIT_BATCH_PREIMAGE.ends_with(PERMIT_DETAILS_PREIMAGE));
    assert!(PERMIT_TRANSFER_FROM_PREIMAGE.ends_with(TOKEN_PERMISSIONS_PREIMAGE));
    assert!(PERMIT_BATCH_TRANSFER_FROM_PREIMAGE.ends_with(TOKEN_PERMISSIONS_PREIMAGE));
}

#[test]
fn domain_separator_matches_the_deployment() {
    // Observed on-chain: DOMAIN_SEPARATOR() at Ethereum block 25,581,839.
    assert_eq!(domain_separator(1), h32("866a5aba21966af95d6c7ab78eb2b2fc913915c28be3b9aa07cc04ff903e3f28"));
    assert_eq!(domain_separator(8453), h32("3b6f35e4fce979ef8eac3bcdc8c3fc38fe7911bb0c69c8fe72bf1fd1a17e6f07"));
}

#[test]
fn digests_match_viem() {
    for (packed, chain, want) in [
        (single(), 8453, SINGLE_DIGEST),
        (batch(), 8453, BATCH_DIGEST),
        (transfer(), 1, TRANSFER_DIGEST),
        (batch_transfer(), 8453, BATCH_TRANSFER_DIGEST),
    ] {
        let core = decode_core(&packed).unwrap();
        assert_eq!(compute_digest(&core, chain).unwrap(), h32(want));
    }
}

#[test]
fn chain_mismatch_is_refused() {
    let core = decode_core(&single()).unwrap();
    assert_eq!(compute_digest(&core, 1), Err(Eip712Error::ChainIdMismatch));
}

#[test]
fn every_signed_field_moves_the_digest() {
    // Flip each byte of each packed vector (except variant/count, which
    // change the framing): the digest must change or the core must refuse.
    for (packed, chain) in [(single(), 8453), (batch(), 8453), (transfer(), 1), (batch_transfer(), 8453)] {
        let base = compute_digest(&decode_core(&packed).unwrap(), chain).unwrap();
        let head = pqsigner_tx::permit2::head_len(packed[0]).unwrap();
        for i in 1..packed.len() {
            if i == head - 1 || (1..9).contains(&i) {
                continue; // count byte; chain id (refused by compute_digest)
            }
            let mut m = packed.clone();
            m[i] ^= 0x01;
            if let Ok(c) = decode_core(&m) {
                assert_ne!(compute_digest(&c, chain).unwrap(), base, "byte {i} not bound");
            }
        }
    }
}

#[test]
fn verifier_degrades_unproven_tokens_and_refuses_bad_cores() {
    let empty: [&[u8]; PERMIT2_MAX_TOKENS] = [&[]; PERMIT2_MAX_TOKENS];
    let (v, d) = verify_offchain_permit2(&batch(), &empty, 8453).unwrap();
    assert_eq!(d, h32(BATCH_DIGEST));
    assert_eq!(v.packed(), &batch()[..]);
    assert!(v.legs.iter().all(|l| !l.is_decoded()));
    // A garbage bundle degrades too.
    let junk: [&[u8]; PERMIT2_MAX_TOKENS] = [&[1, 2, 3]; PERMIT2_MAX_TOKENS];
    assert!(!verify_offchain_permit2(&batch(), &junk, 8453).unwrap().0.legs[0].is_decoded());
    assert_eq!(verify_offchain_permit2(&batch(), &empty, 1).unwrap_err(), "permit2 chain");
    let mut dup = batch();
    let first_token = dup[62..82].to_vec();
    dup[114..134].copy_from_slice(&first_token);
    assert_eq!(verify_offchain_permit2(&dup, &empty, 8453).unwrap_err(), "permit2 dup tok");
}

/// The firmware's type strings and domain are the deployed contract's: each
/// appears verbatim in the hash-pinned official source of the deployment tag
/// (`tests/erc7730-semantic-evidence/uniswap-permit2`, see its manifest).
#[test]
fn preimages_are_the_pinned_permit2_source() {
    const PERMIT_HASH_SOL: &str =
        include_str!("../../../../../tests/erc7730-semantic-evidence/uniswap-permit2/src/libraries/PermitHash.sol");
    const EIP712_SOL: &str =
        include_str!("../../../../../tests/erc7730-semantic-evidence/uniswap-permit2/src/EIP712.sol");
    for pre in [
        PERMIT_DETAILS_PREIMAGE,
        PERMIT_SINGLE_PREIMAGE,
        PERMIT_BATCH_PREIMAGE,
        TOKEN_PERMISSIONS_PREIMAGE,
        PERMIT_TRANSFER_FROM_PREIMAGE,
        PERMIT_BATCH_TRANSFER_FROM_PREIMAGE,
    ] {
        let quoted = std::format!("\"{}\"", core::str::from_utf8(pre).unwrap());
        assert!(PERMIT_HASH_SOL.contains(&quoted), "{quoted} is not in PermitHash.sol");
    }
    assert!(EIP712_SOL.contains("keccak256(\"Permit2\")"));
    assert!(EIP712_SOL.contains("\"EIP712Domain(string name,uint256 chainId,address verifyingContract)\""));
}

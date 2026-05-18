//! Positive: `tx::erc20::calldata` strict ABI decoder happy paths.
//!
//! Covers the three canonical selectors (`transfer`, `transferFrom`,
//! `approve`), the `decode_*_word` primitives, and the `unlimited` heuristic.

mod common;

use common::{pad_address, u256_word};
use pqsigner_tx::erc20::calldata::{
    decode_address_word, decode_u256_word, is_unlimited_amount, parse_erc20_calldata, Erc20Call,
    SELECTOR_APPROVE, SELECTOR_TRANSFER, SELECTOR_TRANSFER_FROM,
};

fn build_transfer(to: &[u8; 20], amount_word: [u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 64);
    v.extend_from_slice(&SELECTOR_TRANSFER);
    v.extend_from_slice(&pad_address(to));
    v.extend_from_slice(&amount_word);
    v
}

#[test]
fn positive_transfer_decodes_address_and_amount() {
    let to = [0x11u8; 20];
    let data = build_transfer(&to, u256_word(1_000_000));
    let parsed = parse_erc20_calldata(&data).expect("transfer must decode");
    match parsed {
        Erc20Call::Transfer { to: t, amount } => {
            assert_eq!(t, to);
            // value 1_000_000 BE in low bytes
            assert_eq!(&amount.0[24..32], &1_000_000u64.to_be_bytes());
            assert!(amount.0[..24].iter().all(|&b| b == 0));
        }
        _ => panic!("expected Transfer variant"),
    }
}

#[test]
fn positive_transfer_from_decodes_three_args() {
    let from = [0x22u8; 20];
    let to = [0x33u8; 20];
    let mut data = Vec::with_capacity(4 + 96);
    data.extend_from_slice(&SELECTOR_TRANSFER_FROM);
    data.extend_from_slice(&pad_address(&from));
    data.extend_from_slice(&pad_address(&to));
    data.extend_from_slice(&u256_word(42));
    let parsed = parse_erc20_calldata(&data).expect("transferFrom must decode");
    match parsed {
        Erc20Call::TransferFrom { from: f, to: t, amount } => {
            assert_eq!(f, from);
            assert_eq!(t, to);
            assert_eq!(amount.0[31], 42);
        }
        _ => panic!("expected TransferFrom variant"),
    }
}

#[test]
fn positive_approve_decodes_spender_and_amount() {
    let spender = [0x44u8; 20];
    let mut data = Vec::with_capacity(4 + 64);
    data.extend_from_slice(&SELECTOR_APPROVE);
    data.extend_from_slice(&pad_address(&spender));
    data.extend_from_slice(&u256_word(1));
    let parsed = parse_erc20_calldata(&data).expect("approve must decode");
    match parsed {
        Erc20Call::Approve { spender: s, amount } => {
            assert_eq!(s, spender);
            assert_eq!(amount.0[31], 1);
        }
        _ => panic!("expected Approve variant"),
    }
}

#[test]
fn positive_zero_address_decodes() {
    // 0x000…000 is a legal address word — the burn / null address. Most
    // contracts reject it, but the *decoder* must surface it cleanly so
    // the trusted UI can show it and let the user confirm.
    let word = [0u8; 32];
    let addr = decode_address_word(&word).expect("all-zero word must decode");
    assert_eq!(addr, [0u8; 20]);
}

#[test]
fn positive_max_address_decodes() {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&[0xffu8; 20]);
    let addr = decode_address_word(&word).expect("0x000..00ffff…ff must decode");
    assert_eq!(addr, [0xff; 20]);
}

#[test]
fn positive_decode_u256_max() {
    let max = decode_u256_word(&[0xffu8; 32]);
    assert_eq!(max.0, [0xff; 32]);
}

#[test]
fn positive_decode_u256_zero() {
    let zero = decode_u256_word(&[0u8; 32]);
    assert!(zero.0.iter().all(|&b| b == 0));
}

#[test]
fn positive_unlimited_threshold_exactly_at_2_to_200() {
    // 2^200 has a `1` at bit 200, which is the LSB of byte 6 from MSB.
    let mut word = [0u8; 32];
    word[6] = 0x01;
    let v = decode_u256_word(&word);
    assert!(
        is_unlimited_amount(&v),
        "2^200 must classify as unlimited"
    );
}

#[test]
fn positive_unlimited_just_below_threshold_is_bounded() {
    // 2^200 - 1 has bytes 6..7 == 0x00 and bytes 7..32 all 0xff. So
    // byte[0..7] is all zero → not unlimited.
    let mut word = [0u8; 32];
    for b in word.iter_mut().skip(7) {
        *b = 0xff;
    }
    let v = decode_u256_word(&word);
    assert!(
        !is_unlimited_amount(&v),
        "values < 2^200 must NOT classify as unlimited"
    );
}

#[test]
fn positive_unlimited_classification_for_uint256_max() {
    let v = decode_u256_word(&[0xffu8; 32]);
    assert!(is_unlimited_amount(&v),
        "type(uint256).max must classify as unlimited");
}

#[test]
fn positive_selectors_match_published_constants() {
    // Pins the bytewise selector constants — every NS-side / dapp-side
    // implementation hard-codes these. A silent rename here would let
    // the secure world dispatch a different ABI shape.
    assert_eq!(SELECTOR_TRANSFER, [0xa9, 0x05, 0x9c, 0xbb]);
    assert_eq!(SELECTOR_TRANSFER_FROM, [0x23, 0xb8, 0x72, 0xdd]);
    assert_eq!(SELECTOR_APPROVE, [0x09, 0x5e, 0xa7, 0xb3]);
}

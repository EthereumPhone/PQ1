//! Negative: `tx::erc20::calldata` strict ABI decoder adversarial inputs.
//!
//! The decoder is the *only* thing standing between non-secure-supplied
//! bytes and the "trusted-display" trust level. If it accepts a sloppy
//! encoding, the OLED renders attacker-shaped values: a dirty address
//! word can mean the displayed `to` and the value the EVM dispatches
//! diverge silently. Each negative here pins a single rejection lever.

mod common;

use common::{pad_address, u256_word};
use pqsigner_tx::erc20::calldata::{
    decode_address_word, parse_erc20_calldata, SELECTOR_APPROVE, SELECTOR_TRANSFER,
    SELECTOR_TRANSFER_FROM,
};

#[test]
fn negative_calldata_shorter_than_selector_rejected() {
    for n in 0..4 {
        let data = vec![0u8; n];
        assert!(
            parse_erc20_calldata(&data).is_none(),
            "{n}-byte calldata (< 4-byte selector) MUST be rejected"
        );
    }
}

#[test]
fn negative_unknown_selector_rejected() {
    // Picks a selector that is NOT one of the three. Returning `None`
    // here is what forces dispatch_tx onto the BLIND-SIGN path; an
    // accidental "looks like ERC20" decode would let an attacker reuse
    // the token-aware display copy for an unrelated method.
    let mut data = vec![0xde, 0xad, 0xbe, 0xef];
    data.extend_from_slice(&pad_address(&[0x11; 20]));
    data.extend_from_slice(&u256_word(1));
    assert!(parse_erc20_calldata(&data).is_none(),
        "unknown selectors must NOT decode as ERC20");
}

#[test]
fn negative_transfer_wrong_body_length_rejected() {
    // transfer requires exactly 64 body bytes. Anything else is either a
    // truncation attack or a token with a non-standard method (e.g. USDT
    // approve-with-meta) that we deliberately do NOT trust to display.
    for body_len in [0, 1, 32, 63, 65, 96, 128, 1024] {
        let mut data = Vec::with_capacity(4 + body_len);
        data.extend_from_slice(&SELECTOR_TRANSFER);
        data.resize(4 + body_len, 0u8);
        assert!(
            parse_erc20_calldata(&data).is_none(),
            "transfer with {body_len}-byte body MUST be rejected"
        );
    }
}

#[test]
fn negative_transfer_from_wrong_body_length_rejected() {
    for body_len in [0, 32, 64, 95, 97, 128] {
        let mut data = Vec::with_capacity(4 + body_len);
        data.extend_from_slice(&SELECTOR_TRANSFER_FROM);
        data.resize(4 + body_len, 0u8);
        assert!(
            parse_erc20_calldata(&data).is_none(),
            "transferFrom with {body_len}-byte body MUST be rejected"
        );
    }
}

#[test]
fn negative_approve_wrong_body_length_rejected() {
    for body_len in [0, 32, 63, 65, 96] {
        let mut data = Vec::with_capacity(4 + body_len);
        data.extend_from_slice(&SELECTOR_APPROVE);
        data.resize(4 + body_len, 0u8);
        assert!(
            parse_erc20_calldata(&data).is_none(),
            "approve with {body_len}-byte body MUST be rejected"
        );
    }
}

#[test]
fn negative_dirty_top_bytes_of_address_word_rejected() {
    // Assumption attacked: a hostile sender could try to smuggle bits in
    // the top 12 bytes of an address word — the EVM still routes the
    // call to the low 20 bytes, but a naive UI showing "the address
    // word" could be confused. The decoder MUST reject any non-zero
    // byte in word[0..12].
    let to = [0x11u8; 20];
    let mut bad_addr = pad_address(&to);
    for dirty_idx in 0..12 {
        let mut tampered = bad_addr;
        tampered[dirty_idx] = 0x01;
        // standalone decode_address_word
        assert!(
            decode_address_word(&tampered).is_none(),
            "decode_address_word MUST reject non-zero top byte at idx {dirty_idx}"
        );
        // and inside a transfer:
        let mut data = Vec::with_capacity(4 + 64);
        data.extend_from_slice(&SELECTOR_TRANSFER);
        data.extend_from_slice(&tampered);
        data.extend_from_slice(&u256_word(1));
        assert!(
            parse_erc20_calldata(&data).is_none(),
            "parse_erc20_calldata MUST reject dirty top byte at idx {dirty_idx}"
        );
        // sanity: restoring zeros makes it pass
        bad_addr[dirty_idx] = 0;
    }
}

#[test]
fn negative_decode_address_word_wrong_length_rejected() {
    // word.len() != 32 must reject without panicking even on weirder
    // lengths the caller might pass in if a parser drifts.
    for n in [0usize, 1, 16, 31, 33, 64] {
        let w = vec![0u8; n];
        assert!(
            decode_address_word(&w).is_none(),
            "{n}-byte word MUST NOT decode as a 20-byte address"
        );
    }
}

#[test]
fn negative_transfer_from_dirty_second_address_rejected() {
    // The dirty-bytes check must hold for *every* address word in a
    // multi-arg call, not just the first.
    let from = pad_address(&[0x22; 20]);
    let mut to_dirty = pad_address(&[0x33; 20]);
    to_dirty[5] = 0x99;
    let mut data = Vec::with_capacity(4 + 96);
    data.extend_from_slice(&SELECTOR_TRANSFER_FROM);
    data.extend_from_slice(&from);
    data.extend_from_slice(&to_dirty);
    data.extend_from_slice(&u256_word(1));
    assert!(
        parse_erc20_calldata(&data).is_none(),
        "dirty top byte in second address word of transferFrom MUST be rejected"
    );
}

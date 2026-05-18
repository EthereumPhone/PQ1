//! Negative: `tx::erc20::dispatch::dispatch_tx` policy invariants.
//!
//! Trust-level routing is the policy boundary between trusted-display
//! (Level 2), structurally-decoded (Erc20Unknown), and BLIND-SIGNING.
//! Each negative pins a piece of that policy so a refactor that
//! "simplifies" the dispatcher can't silently upgrade an attacker's
//! input from CommonCall to Erc20Known.

mod common;

use common::{pad_address, u256_word};
use pqsigner_tx::erc20::bundle::Erc20Metadata;
use pqsigner_tx::erc20::calldata::SELECTOR_TRANSFER;
use pqsigner_tx::erc20::{dispatch_tx, TxKind};
use pqsigner_tx_core::eip1559::{Eip1559Tx, ParsedTx, U256};

fn parsed_with(to: Option<[u8; 20]>, data: &[u8]) -> ParsedTx<'_> {
    ParsedTx {
        tx: Eip1559Tx {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: U256([0u8; 32]),
            max_fee_per_gas: U256([0u8; 32]),
            gas_limit: 21_000,
            to,
            value: U256([0u8; 32]),
            data_len: data.len(),
            access_list_count: 0,
            signing_hash: [0u8; 32],
        },
        data,
        envelope: &[],
    }
}

#[test]
fn negative_contract_creation_with_bundle_still_routes_to_creation() {
    // Assumption attacked: a hostile NS supplies an ERC-20 metadata
    // bundle for a CREATE transaction, hoping the dispatcher will
    // hand back Erc20Known and render the new-contract calldata under
    // the "trusted token transfer" banner. `to.is_none()` MUST win.
    let mut data = Vec::new();
    data.extend_from_slice(&SELECTOR_TRANSFER);
    data.extend_from_slice(&pad_address(&[0x33; 20]));
    data.extend_from_slice(&u256_word(1));
    let parsed = parsed_with(None, &data);
    let meta = Erc20Metadata {
        chain_id: 1,
        contract: [0x22; 20],
        decimals: 6,
        name: b"USD Coin",
        symbol: b"USDC",
    };
    let kind = dispatch_tx(&parsed, Some(meta));
    assert!(matches!(kind, TxKind::ContractCreation),
        "ContractCreation MUST take priority over any supplied bundle");
}

#[test]
fn negative_unknown_selector_with_bundle_routes_to_contract_call() {
    // Even when a bundle is supplied, calldata that isn't one of the
    // three ERC20 selectors MUST fall through to BLIND-SIGNING. If the
    // dispatcher accidentally peeked at the bundle's bytes instead of
    // calldata, an attacker could borrow the trusted-display banner
    // for an arbitrary contract call.
    let data = vec![0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0];
    let parsed = parsed_with(Some([0x22; 20]), &data);
    let meta = Erc20Metadata {
        chain_id: 1,
        contract: [0x22; 20],
        decimals: 6,
        name: b"USD Coin",
        symbol: b"USDC",
    };
    let kind = dispatch_tx(&parsed, Some(meta));
    assert!(matches!(kind, TxKind::ContractCall),
        "non-ERC20 selector MUST route to ContractCall even with bundle present");
}

#[test]
fn negative_value_transfer_with_bundle_still_routes_to_value_transfer() {
    // Empty calldata + supplied bundle: still a plain ETH transfer.
    // An attacker who can pass an arbitrary bundle alongside a plain
    // value transfer should NOT see the "trusted token" copy.
    let parsed = parsed_with(Some([0x22; 20]), &[]);
    let meta = Erc20Metadata {
        chain_id: 1,
        contract: [0x22; 20],
        decimals: 6,
        name: b"USD Coin",
        symbol: b"USDC",
    };
    let kind = dispatch_tx(&parsed, Some(meta));
    assert!(matches!(kind, TxKind::ValueTransfer),
        "empty calldata MUST short-circuit to ValueTransfer regardless of bundle");
}

#[test]
fn negative_too_short_for_selector_routes_to_contract_call() {
    // 3-byte data — too short to even hold a selector. The decoder
    // returns None and dispatch must route to BLIND-SIGN.
    let data = vec![0xa9, 0x05, 0x9c]; // first 3 bytes of transfer selector
    let parsed = parsed_with(Some([0x22; 20]), &data);
    assert!(matches!(dispatch_tx(&parsed, None), TxKind::ContractCall),
        "calldata shorter than a selector MUST NOT be classified as ERC20");
}

#[test]
fn negative_malformed_transfer_body_falls_through_to_contract_call() {
    // Correct selector, wrong body length → strict decoder returns None
    // → dispatch falls to ContractCall (BLIND-SIGN). If the dispatcher
    // were ever loosened to accept "first 64 bytes look-ish like
    // transfer", an attacker could embed extra junk past byte 68 and
    // hide intent in the un-displayed tail.
    let mut data = Vec::new();
    data.extend_from_slice(&SELECTOR_TRANSFER);
    data.extend_from_slice(&pad_address(&[0x33; 20]));
    data.extend_from_slice(&u256_word(1));
    data.push(0xff); // ← trailing byte makes body 65, not 64
    let parsed = parsed_with(Some([0x22; 20]), &data);
    assert!(matches!(dispatch_tx(&parsed, None), TxKind::ContractCall),
        "transfer body != 64 bytes MUST route to ContractCall, not Erc20Unknown");
}

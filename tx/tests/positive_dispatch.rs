//! Positive: `tx::erc20::dispatch::dispatch_tx` correct trust-level routing.

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
fn positive_no_to_routes_to_contract_creation() {
    let parsed = parsed_with(None, &[]);
    assert!(matches!(dispatch_tx(&parsed, None), TxKind::ContractCreation));
}

#[test]
fn positive_to_present_empty_data_routes_to_value_transfer() {
    let parsed = parsed_with(Some([0x11; 20]), &[]);
    assert!(matches!(dispatch_tx(&parsed, None), TxKind::ValueTransfer));
}

#[test]
fn positive_transfer_with_bundle_routes_to_erc20_known() {
    let mut data = Vec::new();
    data.extend_from_slice(&SELECTOR_TRANSFER);
    data.extend_from_slice(&pad_address(&[0x33; 20]));
    data.extend_from_slice(&u256_word(1));
    let parsed = parsed_with(Some([0x22; 20]), &data);
    let meta = Erc20Metadata {
        chain_id: 1,
        contract: [0x22; 20],
        decimals: 6,
        name: b"USD Coin",
        symbol: b"USDC",
    };
    let kind = dispatch_tx(&parsed, Some(meta));
    match kind {
        TxKind::Erc20Known(_, m) => {
            assert_eq!(m.decimals, 6);
            assert_eq!(m.symbol, b"USDC");
        }
        _ => panic!("expected Erc20Known"),
    }
}

#[test]
fn positive_transfer_without_bundle_routes_to_erc20_unknown() {
    let mut data = Vec::new();
    data.extend_from_slice(&SELECTOR_TRANSFER);
    data.extend_from_slice(&pad_address(&[0x33; 20]));
    data.extend_from_slice(&u256_word(1));
    let parsed = parsed_with(Some([0x22; 20]), &data);
    assert!(matches!(
        dispatch_tx(&parsed, None),
        TxKind::Erc20Unknown(_)
    ));
}

#[test]
fn positive_unknown_calldata_routes_to_contract_call() {
    // 4-byte selector that doesn't match any of the three ERC20 ones.
    let data = vec![0xde, 0xad, 0xbe, 0xef, 0u8, 0, 0, 1];
    let parsed = parsed_with(Some([0x22; 20]), &data);
    assert!(matches!(dispatch_tx(&parsed, None), TxKind::ContractCall));
}

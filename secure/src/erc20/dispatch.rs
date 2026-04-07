//! Trust-level dispatcher for sign requests.
//!
//! Given a parsed EIP-1559 envelope and an optional already-verified
//! ERC20 metadata bundle, decide which trusted-display flow to use:
//!
//! - **Plain value transfer** (calldata empty): no warning
//! - **Decoded ERC20** (`transfer`/`transferFrom`/`approve`)
//!   + bundle present and verified → token-aware display (Level 2)
//!   + no bundle                   → structurally decoded with warning
//! - **Arbitrary contract call**: Ledger-style "BLIND SIGNING" warning
//! - **Contract creation**: separate "CONTRACT CREATION" warning
//!
//! The bundle that flows in here MUST already have been Merkle-verified
//! AND cross-checked against `parsed.tx.chain_id`/`parsed.tx.to`. The
//! cross-check is the caller's job (cmd_sign), not this module's, so
//! the bundle stays a pure verifier and `dispatch_tx` stays branchless
//! on trust state.

use super::bundle::Erc20Metadata;
use super::calldata::{parse_erc20_calldata, Erc20Call};
use crate::tx::eip1559::ParsedTx;

#[derive(Debug)]
pub enum TxKind<'a> {
    /// Plain ETH-only value transfer to an EOA or to a contract that
    /// expects no calldata. No warnings.
    ValueTransfer,
    /// Standard ERC20 method targeting a contract whose bundle the
    /// non-secure world supplied AND the secure world verified. Both
    /// the structure and the token identity are trusted.
    Erc20Known(Erc20Call, Erc20Metadata<'a>),
    /// Standard ERC20 method, but no verified bundle was supplied.
    /// Either NS doesn't have this contract in its DB, or it
    /// deliberately omitted the bundle. Structure is decoded but the
    /// token identity is unknown — display the amount as raw uint256.
    Erc20Unknown(Erc20Call),
    /// Non-empty calldata that doesn't match any known ERC20 selector.
    /// Ledger-style BLIND SIGNING warning.
    ContractCall,
    /// `tx.to` is `None` — this is a CREATE transaction.
    ContractCreation,
}

pub fn dispatch_tx<'a>(
    parsed: &ParsedTx<'_>,
    verified_meta: Option<Erc20Metadata<'a>>,
) -> TxKind<'a> {
    if parsed.tx.to.is_none() {
        return TxKind::ContractCreation;
    }

    if parsed.data.is_empty() {
        return TxKind::ValueTransfer;
    }

    match parse_erc20_calldata(parsed.data) {
        Some(call) => match verified_meta {
            Some(meta) => TxKind::Erc20Known(call, meta),
            None => TxKind::Erc20Unknown(call),
        },
        None => TxKind::ContractCall,
    }
}

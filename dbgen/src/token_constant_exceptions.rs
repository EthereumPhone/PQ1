//! Reviewed exceptions to the ERC-7730 constant-token gate
//! ([`crate::erc7730::check_token_amount_constants`]).
//!
//! Every effective `tokenAmount` literal `(chain_id, token)` in an emitted
//! production catalogue leaf must be a row of `secure/data/erc20.json`, a
//! native sentinel, or listed here with a reason. An entry here means the
//! device shows that amount raw / UNVERIFIED (no exact decimals), and that
//! this is the intended outcome. The gate fails on a stale entry (no emitted
//! leaf pins it any more, or the DB now has the token), so this list cannot
//! outlive its reason.
//!
//! Do NOT add an entry to make a real token pass: verify `name()`, `symbol()`
//! and `decimals()` on-chain and add the row to `secure/data/erc20.json`.
//!
//! Known descriptor bug that needs an entry here if it ever starts emitting
//! leaves: the OKX DEX router descriptors
//! (`registry/okx/calldata-OkxDexRouterV1.0.7-multi-commission.json`,
//! `calldata-OkxDexRouterV1.0.8-suffix-compat.json`) pin the Ethereum-mainnet
//! WETH address `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` on ~24 non-mainnet
//! chains. On those chains it is not WETH: the entries must use
//! [`OKX_MAINNET_WETH_REASON`] and the address must never be added to the
//! ERC-20 DB for them. As of 2026-11-14 neither descriptor compiles (no leaf),
//! so no entry is needed and a pre-emptive one would be stale.

use crate::erc7730::TokenConstantException;

/// Reason text for the OKX entries described in the module documentation.
pub const OKX_MAINNET_WETH_REASON: &str =
    "descriptor pins mainnet WETH address on a chain where it is not WETH";

/// Production catalogue exceptions.
pub const PRODUCTION: &[TokenConstantException] = &[
    // Angle Protocol USDA (verified on-chain 2026-11-14 over two public RPCs:
    // name "USDA", symbol "USDA", decimals 18). Used as the vault asset by
    // registry/morpho/calldata-gauntlet-gtUSDAcore.json and
    // calldata-re7_labs-Re7USDA.json. Not added to the DB because
    // tools/erc20_impersonator_denylist.txt deliberately excludes this
    // (chain 1, address) pair (ticker collision with Avalon "USDa" at
    // 0x8A60E489004Ca22d775C5F2c657598278d17D9c2, the CoinGecko-listed
    // "USDA"); lifting that denylist entry is an owner decision.
    TokenConstantException {
        chain_id: 1,
        token: "0x0000206329b97db379d5e1bf586bbdb969c63274",
        reason: "denylisted in tools/erc20_impersonator_denylist.txt (ticker \
                 collision with Avalon USDa); the Morpho USDA vault amounts render \
                 raw until that entry is reviewed",
    },
];

/// E2E fixture catalogue exceptions (checked against `erc20-e2e.json`).
pub const E2E: &[TokenConstantException] = &[];

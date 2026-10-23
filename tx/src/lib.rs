//! `pqsigner-tx` — pure-logic Solidity-ABI trust gates.
//!
//! Hosts:
//!
//! - [`cowswap_order`] — pure field-decode of the 204-byte canonical
//!   CowSwap `GPv2Order` packed encoding (Kani decode-soundness verified).
//! - [`erc20`] — ERC-20 metadata Merkle DB + strict `transfer` /
//!   `transferFrom` / `approve` calldata decoder + dispatch.
//! - [`multisend`] — strict Safe `MultiSendCallOnly` outer-framing
//!   decoder + inner packed-record walk + per-record display
//!   classification / page-budget accounting (Kani: outer canonical-
//!   acceptance; inner-walk exact-tiling/partition + field-fidelity;
//!   page-budget per-record page bound + the no-hidden-value WYSIWYS
//!   soundness + CoW-first precedence — `records_pages_total`'s own
//!   panic-freedom is compositional from these parts).
//! - [`permit2`] — pure field-decode of the packed Uniswap Permit2 permit
//!   carried by the off-chain kind 6 (Kani decode-soundness + duplicate-token
//!   refusal verified).
//! - [`names`] — address-name DB + stack-resident [`names::NameResolver`].
//! - [`safe_mgmt`] — strict selector + fixed-arg decoder for Safe
//!   owner/module/guard/fallback management ops
//!   ([`safe_mgmt::classify_safe_mgmt`], Kani decode-soundness: accept ⟹
//!   length-exact + selector-match + canonical address words + faithful
//!   threshold, reconstructed from the original bytes; plus
//!   selector-gating reject).
//! - [`safe_tx`] — pure byte-layout decoders for the Safe SafeTx
//!   clear-sign path: the 281-byte canonical typed-data
//!   ([`safe_tx::decode_canonical`], Kani exhaustive biconditional) and
//!   the `execTransaction(...)` calldata with dynamic `data`/`signatures`
//!   ([`safe_tx::decode_exec_transaction`], Kani no-read-past-end +
//!   fixed-field soundness).
//! - [`selectors`] — function-selector → text-sig DB.
//!
//! The `verify_*_bundle` Merkle verifiers all take a `root: &[u8; 32]`
//! parameter so the embedded `secure/src/db_roots.rs` constants can be
//! injected from the call site instead of hard-coded into the crate.
//! That keeps `pqsigner-tx` reusable by any future host-side
//! reference-signer that exercises the same trust gates.
//!
//! Phase 5 PR 5.4 of the modularity refactor extracted these out of
//! `secure/src/{erc20,names,selectors}/`. Existing call sites continue
//! to work because the secure-side `mod.rs` files now re-export from
//! here and bake the embedded root into thin wrapper functions.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

mod wire;

pub mod cowswap_order;
pub mod erc20;
pub mod multisend;
pub mod names;
pub mod permit2;
pub mod safe_mgmt;
pub mod safe_tx;
pub mod selectors;
pub mod typed_call;

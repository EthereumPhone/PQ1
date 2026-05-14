//! `pqsigner-erc7730` — on-device ERC-7730 clear-signing interpreter.
//!
//! The Ethereum Foundation launched the Clear Signing standard
//! (<https://clearsigning.org>) on 2026-05-12. ERC-7730 specifies a
//! JSON descriptor format that turns opaque calldata / EIP-712 messages
//! into human-readable intent ("Swap 1,000 USDC for at least 0.42 WETH
//! on Uniswap V3"). PQSigner ingests descriptors from the official
//! registry at <https://github.com/ethereum/clear-signing-erc7730-registry>.
//!
//! ## On-device model
//!
//! JSON parsing on a 1 MiB Cortex-M33 with no heap is impractical. The
//! host compiler in `dbgen` walks each descriptor JSON, validates it
//! against the v2 schema (and, separately, against the ERC-8176
//! attestation policy in `secure/data/erc7730/policy.toml`), and emits
//! a compact binary IR. The IR is what the device walks at sign time.
//!
//! ## Trust model
//!
//! The non-secure world is NOT trusted to supply correct descriptor
//! bytes. It IS trusted to look up the appropriate descriptor for the
//! `(chain_id, contract_addr)` pair (or `(domain_separator,
//! primary_type_hash)` for EIP-712) and to forward the corresponding
//! pre-compiled IR plus a Merkle proof. The secure world
//!
//! 1. Verifies the IR's leaf hash against the firmware-pinned
//!    `ERC7730_DESCRIPTORS_ROOT` (compile-time, sibling to the existing
//!    `ERC20_DB_ROOT` / `SELECTOR_DB_ROOT` / `NAMES_DB_ROOT`).
//! 2. Cross-checks the IR's binding context (`chain_id` + `contract`
//!    or `domain_separator` + `primary_type_hash`) against the actual
//!    payload being signed.
//! 3. Walks the IR with the ABI-decoded payload to produce the
//!    page-by-page display.
//!
//! Step 1 reuses `pqsigner-tx::erc20::merkle::verify_proof` byte-for-byte
//! — same scheme as every other trust DB (SHA-256, 0x00/0x01 domain
//! separation, leaf-index bit selection, 32-level depth cap).
//!
//! ## What is NOT on-device
//!
//! - **ERC-8176 attestation signature verification.** 8176 uses
//!   secp256k1 (EIP-191) or ERC-1271 contract sigs. Adding a classical
//!   verifier to the firmware would break the PQSigner invariant "no
//!   classical signer anywhere — firmware, contract, FW-update path."
//!   8176 enforcement happens in the host build pipeline: only
//!   descriptors meeting `min_attesters` / `trusted_attesters` policy
//!   in `secure/data/erc7730/policy.toml` enter the Merkle tree. The
//!   firmware pins the *root* of that filtered tree.
//! - **Live registry resolution.** All shipped descriptors are pinned
//!   at firmware build time. Updates rotate via signed FW updates
//!   (already SPHINCS+C10, `PQFW_V1`).
//! - **External data resolution (ENS, token decimals, NFT collection
//!   names).** Companion supplies via existing trailers
//!   (`Erc20Metadata`, `NameMeta`).
//!
//! See `docs/erc7730-integration.md` for the full spec, IR layout, and
//! formatter coverage.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

pub mod abi;
pub mod binding;
pub mod bundle;
pub mod ir;
pub mod walker;

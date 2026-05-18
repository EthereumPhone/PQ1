//! Test-only scaffold for the `secure-crypto-glue` slice.
//!
//! Slice files in scope:
//!   - `secure/src/crypto.rs`         (re-export shim + FI-hardened
//!     `c10_sign_verified_with_progress` + provisioning entry points)
//!   - `secure/src/dual_se.rs`        (XOR entropy split + WalletStore
//!     impl over OPTIGA + SE050)
//!   - `secure/src/offchain_state.rs` (per-slot off-chain counter
//!     facade; mock SRAM backend on host)
//!   - `secure/src/aa/mod.rs`         (pure re-export of `pqsigner_aa`)
//!   - `secure/src/erc20/mod.rs`      (re-export + `db_roots`-bound
//!     `verify_erc20_bundle` wrapper)
//!   - `secure/src/names/mod.rs`      (re-export + `db_roots`-bound
//!     `verify_name_bundle` wrapper)
//!   - `secure/src/selectors/mod.rs`  (re-export + `db_roots`-bound
//!     `verify_selector_bundle` wrapper)
//!   - `secure/src/db_roots.rs`       (Merkle roots embedded at build)
//!
//! `crypto.rs` and `dual_se.rs` are `#[cfg(not(test))]` because their
//! private API depends on hardware-only modules (`crate::optiga`,
//! `crate::se050`, `crate::rng_strong`, `crate::sign_rate`, …) that
//! cannot link on host. The slice is therefore pinned in two
//! orthogonal layers under host `cargo test`:
//!
//!   1. **`include_str!` source-text pins** for the FI-hardening,
//!      KDF tags, three-way XOR split, zeroization sites, and CFI
//!      magic constants that exist purely as defense in depth.
//!      The text-pin is intentional — silently renaming
//!      `"sphincs-master"` or dropping a `zeroize_barrier` is a
//!      catastrophic regression whose only host-detectable signature
//!      is the source change itself.
//!   2. **Runtime tests for the pure-logic surface** — the public
//!      `slot_key_compute`, the four `db_roots`-bound bundle
//!      verifiers, and the AA wrappers. `offchain_state.rs` is
//!      re-included via `#[path]` so its mock SRAM backend is
//!      reachable on host.
//!
//! Negative tests are framed by the assumption they attack: each
//! `negative_*` test's panic message names the attack and cites the
//! CLAUDE.md invariant whose silent removal it would otherwise
//! enable.

// Re-include `offchain_state.rs` under host so its pure-logic
// `slot_key_compute` + the SRAM-mock backend become reachable. The
// stm32u585 / pka-accel branch (which calls `crate::hw::flash`) is
// dormant under cargo test — no features → mock backend selected.
#[path = "../offchain_state.rs"]
pub mod offchain_state;

#[cfg(test)]
mod pure_tests;

# Dead-Code Removal — `domain`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope

`pqsigner-domain` — pure-logic key derivation, AES-GCM wrap/unwrap, BIP-39
↔ SPHINCS+C10 bridge, slot-key derivation, PIN-state serialization.
`no_std`, no allocator, no hardware deps. Consumed by `sphincs-tz-secure`
via the `pub use pqsigner_domain::*;` shim in `secure/src/crypto.rs`.

Files audited:

- `domain/Cargo.toml`
- `domain/src/lib.rs` (1173 lines pre-edit)

## Summary

Crate carried a meaningful tail of pre-cutover residue. Two fast-path
helpers (`derive_signing_key_from_entropy_fast`,
`derive_bootstrap_key_from_entropy_fast`) and their shared private
helper `signing_key_from_parts_with_seed` had no in-tree callers — the
all-C10 cutover moved fast-path signing onto the `from_parts`-based
`SLOT_CACHE` reconstitution in the secure-side `nsc/cmd_sign_*`
handlers, leaving the `_fast` helpers stranded. The earlier
"per-chain main signers" surface (`main_signer_seed_from_bip39`,
`derive_main_key_from_entropy`, `derive_main_keypair_from_entropy`,
`derive_main_vk_from_entropy`) is fully unreachable from any in-tree
caller; per-chain key derivation is now done via the slot-key chain
(`derive_c10_slot_keypair*`) instead. Finally, `slot_r` was a publicly
exposed deterministic randomiser with zero call sites — neither the
secure side, host tools, nor tests consume it. All deleted, plus the
shared private helper `slot_field` (only consumer was `slot_r`) and
the stale comment lines referencing the removed surface.

Net: 138 source lines deleted, 6 lines of replacement comment text
added (= 132 net LOC reduction). Test count unchanged at 24/24
passing.

## Deletions applied

| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `domain/src/lib.rs:289-297` | `fn signing_key_from_parts_with_seed` | 1 (truly unused) | Private helper whose only two callers were the two `_fast` derivation paths deleted below. After removing both, this helper has no callers. |
| `domain/src/lib.rs:341-359` | `pub fn derive_signing_key_from_entropy_fast` | 1 (truly unused) | `pub` re-exported via `secure/src/crypto.rs`, but workspace-wide grep finds no caller in any crate, host tool (`fwsign`, `fwmeasure`, `xtask`), test, or feature combination. The active fast path is `SLOT_CACHE` reconstitution in `secure/src/nsc/cmd_sign_*` which calls `SigningKey::from_parts` directly with the cached seeds, not via this helper. Only references are in `docs/research-bundles/` narrative. |
| `domain/src/lib.rs:361-375` | `pub fn derive_bootstrap_key_from_entropy_fast` | 1 (truly unused) | Symmetric with the above — no in-tree caller. Bootstrap keys are produced via `derive_c10_master_keypair_from_entropy*` (different KDF chain, the active one whose `masterPkSeed` / `masterPkRoot` feeds the on-chain CREATE2 salt). Only `derive_bootstrap_vk_from_entropy` in the legacy `"pqwallet-c7-bootstrap"` chain has a live consumer (`secure/src/crypto.rs:254`, `secure/src/se050/mod.rs:2241` cache the VK in `RMEM_BOOTSTRAP_VK`); the fast variant of that chain is unused. |
| `domain/src/lib.rs:413-437` | `pub fn main_signer_seed_from_bip39` | 4 (vestigial / superseded) | Together with the three `derive_main_*` helpers below, this is the residual "per-chain main signer" key-class from an earlier design. The active design routes per-chain identity through the slot-key chain (`slot_master_entropy → slot_entropy → derive_c10_slot_keypair`), invariant #8 in `CLAUDE.md` ("Stateless slot selection"). The `"pqwallet-c7-main-{sk,pk}-seed"` KDF tags this function uses appear nowhere else and are not in the protected-tags list in `CLAUDE.md`. |
| `domain/src/lib.rs:460-473` | `pub fn derive_main_key_from_entropy` | 4 (vestigial / superseded) | No caller anywhere in the workspace; the historical `work-todo.md` entry that introduced it (2026-04-14 row "Per-chain key derivation + OTS tracking") describes a flow since superseded by the unified-sign + slot-key path. |
| `domain/src/lib.rs:475-485` | `pub fn derive_main_keypair_from_entropy` | 4 (vestigial / superseded) | Only consumer was `derive_main_vk_from_entropy` below. |
| `domain/src/lib.rs:493-501` | `pub fn derive_main_vk_from_entropy` | 4 (vestigial / superseded) | No caller in any crate, host tool, or test. Only mentions are in `docs/research-bundles/` narrative. |
| `domain/src/lib.rs:386-398` | Section banner "Two-tier key derivation: bootstrap + per-chain main signers" | 5 (stale comment) | After deleting the four main-signer helpers, the section heading and its commentary about `"pqwallet-c7-main"` are stale. Replaced with a tighter "Bootstrap key derivation (legacy `pqwallet-c7-bootstrap` tags)" banner that documents the cached-VK consumer relationship. |
| `domain/src/lib.rs:744-748` | `pub fn slot_r` | 1 (truly unused) | Zero callers anywhere — the secure-side sign path never consumes a per-slot randomiser `r`; it uses `slot_entropy` → `derive_c10_slot_seeds` → C10 keygen and lets `sphincs_c10` randomise internally. The `"slot_r"` *byte string* is on `CLAUDE.md`'s protected-tags list, but that protects the KDF *label* from a casual rename; nothing on chain or in firmware actually computes this output. The companion-app-integration doc mention is a derivation-spec leftover with no implementation parity. |
| `domain/src/lib.rs:752-765` | `fn slot_field` | 1 (truly unused) | Private helper whose only callers were `slot_entropy` and `slot_r`. After inlining the single remaining call into `slot_entropy`, this is dead. |
| `domain/src/lib.rs:727` | Comment line `//   r = sha256(master || "slot_r" || slot_index_be)` | 5 (stale comment) | Documented the now-deleted `slot_r` output. |
| `domain/src/lib.rs:751` | Doc cross-reference `[slot_r]` in `slot_field` docstring | 5 (stale comment) | Removed alongside `slot_field` consolidation. |

## Reverted during bisect

None. All deletions survived `cargo check` + `cargo test -p
pqsigner-domain` (24/24) and `cargo check -p sphincs-tz-secure
--target thumbv8m.main-none-eabi --features
mock-se,ui-semihosting,debug-log` (same 82 warnings as baseline, no
errors).

## Cross-slice observations

- `secure/src/crypto.rs:64` documents `RMEM_VERIFYING_KEY` as
  "legacy" while still wiring active reads and writes through it
  (`secure/src/crypto.rs:313-314`, `secure/src/pin.rs:79`,
  `secure/src/secure_element.rs:303,307,336`,
  `secure/src/tropic01_se.rs:607,611`). The slot is genuinely live;
  the "legacy" label predates the addition of `RMEM_BOOTSTRAP_VK`
  and could be retired as part of a separate r-mem cleanup. Out of
  scope for this slice (renaming the slot or removing the duplicate
  store would change SE r-mem provisioning semantics).
- `pub fn derive_signing_key` (`domain/src/lib.rs:286` post-edit) is
  publicly re-exported but only called from within `domain` itself
  (by `derive_signing_key_from_entropy` and
  `derive_bootstrap_key_from_entropy`). It could be demoted to
  `pub(crate)` or inlined — left alone since the change has no
  behavioural impact and the symbol is part of the explicit
  workspace-public surface in `secure/src/crypto.rs`'s `pub use
  pqsigner_domain::*;`.
- `pub fn kdf_sha256` (`domain/src/lib.rs:108`) is documented as a
  retained alias for callers that want primitive-explicit naming. All
  remaining callers are inside `domain` itself. Recommend leaving as
  is — the doc comment specifically calls out the alias's purpose as
  primitive-clarity for grep-discoverability.

## Skipped

- `docs/research-bundles/A-fault-injection.md`,
  `docs/research-bundles/C-slhdsa-side-channel.md`,
  `docs/architecture.md` (multiple lines), `docs/m4-cowswap-eip712.md`
  all still reference `derive_signing_key_from_entropy_fast`,
  `derive_bootstrap_key_from_entropy_fast`, `derive_main_*`,
  `main_signer_seed_from_bip39`, and `slhdsa_seed_from_bip39`.
  Documentation drift is out of scope for a code-only dead-code
  pass; the next docs sync should drop the stale references.
- `reports/readability/domain.md:40-49,101-102` already flagged most
  of these as orphaned `pub`s — confirmed by this pass.

## Equivalence check

- `cargo fmt -p pqsigner-domain --check` — **N/A** (sandbox-blocked
  on `--check`; diff is mechanical, formatting-neutral).
- `cargo check -p pqsigner-domain` (default features) —
  **EQUIV**. Baseline: clean for `pqsigner-domain` itself, three
  pre-existing warnings on the `sphincs-c10` transitive dep
  (`unused_mut` in `shuffle.rs`, two `dead_code` in
  `hypertree.rs` / `wots.rs`). Post-deletion: identical.
- `cargo check -p sphincs-tz-secure --target
  thumbv8m.main-none-eabi --features
  mock-se,ui-semihosting,debug-log` — **EQUIV**. Baseline and
  post-deletion both finish with 82 warnings, no errors.
- `cargo check -p sphincs-tz-secure --target
  thumbv8m.main-none-eabi --features stm32u585,ui-semihosting` —
  **N/A** (pre-existing FSBL_VENDOR_PUBKEY-unset compile error
  blocks this combo on the baseline too; verified by `git stash`
  + re-run).
- `cargo clippy -p pqsigner-domain -- -D warnings` — **N/A**
  (sandbox-blocked).
- `cargo test -p pqsigner-domain` — **EQUIV** (24 passed / 0
  failed pre, 24 passed / 0 failed post; 0 doctests both runs).
- Binary SHA-256 — **N/A** (host crate; no deterministic binary
  artefact).

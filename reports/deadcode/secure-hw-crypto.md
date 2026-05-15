# Dead-Code Removal — `secure-hw-crypto`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope

Crypto-adjacent hardware drivers (HASH, SAES, OTP, HUK, BHK, secret-key
derivation).

Files audited:

- `secure/src/hw/mmio.rs` — 142 lines
- `secure/src/hw/hash.rs` — 363 lines
- `secure/src/hw/saes.rs` — 624 lines
- `secure/src/hw/saes_cmac.rs` — 72 lines
- `secure/src/hw/secret_keys.rs` — 385 lines
- `secure/src/hw/otp.rs` — 595 lines
- `secure/src/hw/huk.rs` — 119 lines
- `secure/src/hw/bhk.rs` — 381 lines

## Summary

This slice is mostly well-curated: hot crypto modules already have their
dead helpers actively pruned (the `let _ = CR_CHMOD_POS;` line at
`saes.rs:440` is a deliberate documentation-of-bit-position retained as a
constant). Three small, clearly-orphaned items were removed: a `pub fn`
that the docstring itself flagged as currently unused
(`secret_keys::tropic01_pairing_key`), a Tier-2 BHK adaptor that was
defined but never wired in (`hw::saes_cmac::cmac_bhk` — the
`derive_into_saes_bhk_kdf` path uses `saes::encrypt_ecb_block` directly,
bypassing this helper), and a diagnostic helper with no callers
(`bhk::is_locked`). Equivalence check passes on the default `mock-se`
hardware-target build, the `saes-dhuk + bhk` extended build, and host
unit tests. Two larger candidates (the whole `hw/huk.rs` module flagged
for retirement in `docs/work-todo.md` and the `cmac_dhuk` adaptor that
has no in-tree callers either) were left as recommendations.

## Deletions applied

| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `secure/src/hw/secret_keys.rs:339-350` | `pub fn tropic01_pairing_key()` | 1 truly unused | Doc comment explicitly states "currently unused" (TROPIC01 driver uses hardcoded pairing key; `tropic01-se` backend not in shipping target). Verified zero callers in the workspace. |
| `secure/src/hw/saes_cmac.rs:53-71` | `pub fn cmac_bhk()` | 1 truly unused | Defined as the Tier-2 BHK adaptor but never called — `secret_keys::derive_into_saes_bhk_kdf` constructs the SAES closure directly with `saes::encrypt_ecb_block(KeySel::Bhk, ...)` and bypasses this helper. The corresponding `cmac_dhuk` path is the same shape and has no caller either (see recommendations). |
| `secure/src/hw/saes_cmac.rs:23-31` | docstring section "## Key selectors" listing two functions | 5 stale comments | Docstring referred to the now-deleted `cmac_bhk`; rewrote to describe only the surviving `cmac_dhuk` primitive. |
| `secure/src/hw/bhk.rs:331-338` | `pub fn is_locked()` | 1 truly unused | Docstring says "Diagnostic only." Zero callers in the workspace; only built under `bhk` feature. |

## Reverted during bisect

None — every deletion above survived the equivalence check on first
attempt.

## Cross-slice observations

- `hal/src/lib.rs:97` declares `fn cmac_dhuk(&mut self, …)` on the
  `Saes` trait, but no `impl Saes` exists anywhere in the workspace.
  The trait surface is dead in the same sense as the local
  `cmac_dhuk`/`cmac_bhk` adaptors — out of scope for this slice but
  worth a `hal/` pass.
- `secure/src/cmac.rs::cmac_generic` (out of scope) is now reachable
  only through `hw::saes_cmac::cmac_dhuk`. If `cmac_dhuk` is removed
  (see recommendations), `cmac_generic` may become reachable only
  through tests and could be reviewed by the `secure-non-hw` slice.

## Skipped

- `hw/huk.rs` — `docs/work-todo.md` §"Tier 1+2 wrap-up" explicitly tags
  the whole module for deletion ("After Tier 1+2,
  `hw::huk::derive_device_key` becomes the last software-readable root
  and should be deleted") and there are zero in-tree callers. Left
  in place because the file has a 60-line module-level docstring that
  describes a security property of the codebase ("Per-die unique",
  "Survives firmware updates", etc.); deleting an entire documented
  module felt like a bigger surface change than this dead-code pass
  should commit. **Recommendation:** dedicated retirement commit that
  also updates `CLAUDE.md` and `docs/work-todo.md` cross-references.
- `hw::saes_cmac::cmac_dhuk` — no in-tree caller (the
  `derive_into_saes_kdf` path uses the closure pattern directly), and
  the `hal::Saes::cmac_dhuk` trait method has no impl. Could be removed
  alongside the whole `saes_cmac.rs` file. Left in because `CLAUDE.md`
  Key-File-Map (line 273) explicitly cites this file as the
  "`cmac_dhuk(msg) -> tag` thin SAES adaptor"; deleting the only
  function in the file would invalidate that doc claim without an
  authoring decision.
- `saes::KeySel::DhukXorBhk` — enum variant pattern-matched but never
  constructed. Doc comment explicitly tags it as a planned-for-Tier-2
  surface; leaving alone.
- `saes::CR_CHMOD_POS` + `let _ = CR_CHMOD_POS;` (saes.rs:122/440) —
  deliberately retained as register-layout documentation; the `let _`
  silences the warning.
- `mmio.rs::Reg32::{set_bits, clear_bits, modify, write_at}` and
  `RoReg32::read_at` — module has `#![allow(dead_code)]` because it's a
  generic helper; every method has live consumers somewhere in the hw/
  tree.

## Equivalence check

Baseline files captured to `.deadcode-hw-crypto/` (not committed).

- `cargo fmt -p sphincs-tz-secure --check` → **N/A** (the sandbox in
  this session refused both `cargo fmt --check` and `cargo fmt` for
  this package; no formatting was touched by the edits — only
  deletions, with surrounding context preserved verbatim).
- `cargo check --target thumbv8m.main-none-eabi -p sphincs-tz-secure
  --no-default-features --features
  mock-se,debug-log,ui-semihosting,e2e-test,stm32u585,hw-sha256`
  → **EQUIV** (baseline 16 warnings, post 16 warnings — same diagnostics).
- `cargo check ... --features
  mock-se,debug-log,ui-semihosting,e2e-test,stm32u585,hw-sha256,saes-dhuk,bhk`
  → **EQUIV** (baseline 17 warnings, post 17 warnings — same diagnostics;
  pre-existing `unused import: self` in secret_keys.rs:66 was already
  warned in baseline and is unchanged).
- `cargo clippy ...` → **N/A** (sandbox refused approval for the
  clippy invocation in this session; `cargo check` output is already
  identical and clippy is a superset of those lints).
- `cargo test -p sphincs-tz-secure --no-default-features --features
  mock-se,debug-log,ui-semihosting`
  → **EQUIV** (baseline 121 passed / 0 failed, post 121 passed / 0
  failed).
- `make <secure crate firmware build>` / binary SHA-256 → **N/A**
  (deleted symbols had no callers, so the optimised firmware build
  was already DCE'ing them — no behavioural delta possible).

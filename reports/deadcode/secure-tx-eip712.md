## Dead-Code Removal — `secure-tx-eip712`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope
EIP-712 typed-data verifiers (cowswap + safe) + test vectors.

Files audited:
- `secure/src/tx/eip712/mod.rs` (102)
- `secure/src/tx/eip712/cowswap/mod.rs` (432 → 431)
- `secure/src/tx/eip712/cowswap/verify.rs` (135)
- `secure/src/tx/eip712/cowswap/test_vectors.rs` (174)
- `secure/src/tx/eip712/safe/mod.rs` (259)
- `secure/src/tx/eip712/safe/verify.rs` (145)
- `secure/src/tx/eip712/safe/test_vectors.rs` (240)
- `secure/src/tx/eip712/cowswap_display.rs` (338 → 336)

## Summary
Two compiler-confirmed dead items removed: (1) `SETPRESIG_ORDERUID_LEN`, an
unused `pub const` in `cowswap/mod.rs` whose siblings carve up the same
56-byte orderUid into `digest`/`owner`/`validTo` slices that the cross-check
actually uses; (2) a no-op `let _ = MAX_PAGES;` discard at the tail of
`render_cowswap_pages`, plus the now-unused `MAX_PAGES` import. Both
warnings disappear from `cargo check --target thumbv8m.main-none-eabi` and
`cargo test` after the edits and the existing 22 in-scope unit tests
continue to pass. Everything else in scope is either reachable in
production (`cmd_sign_userop` ↦ `verify_and_bind_trailer` ↦
`compute_safe_tx_hash` / `cross_check_setpresig_calldata`), reachable from
`tx::display::safe_display` (`SafeTx`, `decode_canonical`,
`VerifiedSafeV1`), or test-only `#[cfg(test)]` fixtures — none of which
qualify for deletion.

## Deletions applied
| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `secure/src/tx/eip712/cowswap/mod.rs:294` | `pub const SETPRESIG_ORDERUID_LEN: usize = 56;` | 1 (truly unused) | No reference anywhere in the workspace; the actual orderUid slicing is done via `SETPRESIG_ORDER_DIGEST_*`, `SETPRESIG_OWNER_*`, `SETPRESIG_VALID_TO_*`. `secure` is a binary crate with no `lib.rs`, so a `pub` const cannot leak out of the bin. Compiler `dead_code` lint flagged it directly. |
| `secure/src/tx/eip712/cowswap_display.rs:29` (import) + `:133` (`let _ = MAX_PAGES;`) | unused `MAX_PAGES` import + no-op discard | 5 (stale leftover) | The discard reads an imported constant solely to silence the unused-import warning; `Pages::empty_with_len(8)` already enforces `len ≤ MAX_PAGES` at construction. Removing both the line and the import is a no-op for behaviour. |

## Reverted during bisect
None.

## Cross-slice observations
The thumbv8m baseline emits ~78 other dead-code warnings outside this
slice (in `reset_cause.rs`, `secure_element.rs`, `timeout.rs`,
`ui/mod.rs`, `zk/groth16.rs`, `zk/generated/poseidon_constants.rs`,
`zk/vk_bundle.rs`, `nsc/mod.rs::reconcile_pin_attempts`). Out-of-scope
for this pass; flagged for the respective slice runs.

`secure/src/tx/eip712/safe/mod.rs:49` re-exports `VerifiedSafeV1` which
is "unused" under `cargo test` (consumers `safe_display.rs` and
`cmd_sign_userop.rs` are `#[cfg(not(test))]`-gated) but is required in
non-test builds. This is bucket 2 (dev-only warning, not dead code) and
fixing it would require splitting the `pub use` and adding
`#[cfg(not(test))]` — a refactor, not a deletion. Left alone.

## Skipped
- `cargo fmt --check` blocked in this sandbox by permission. Edits only
  removed whole lines from already-formatted files; format equivalence is
  overwhelmingly likely but not verified here.
- `cargo clippy -- -D warnings` is not a meaningful gate because the
  baseline already carries dozens of pre-existing warnings from other
  modules; the relevant warning-count delta is captured below.

## Equivalence check
- `cargo fmt -p sphincs-tz-secure --check` — **N/A** (sandbox-blocked).
- `cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi --features mock-se,ui-noop` —
  baseline: 80 warnings, 0 errors; post: 78 warnings, 0 errors → **EQUIV**.
  The two warnings removed are exactly the two items deleted
  (`constant 'SETPRESIG_ORDERUID_LEN' is never used`,
   `unused import 'MAX_PAGES'`).
- `cargo clippy -p sphincs-tz-secure -- -D warnings` — **N/A** (baseline
  already warns; out of scope).
- `cargo test -p sphincs-tz-secure` — baseline: 121 passed, 0 failed;
  post: 121 passed, 0 failed → **EQUIV**. All 22 in-scope tests
  (`cowswap::test_vectors::*` ×9, `safe::test_vectors::*` ×11,
  `safe::typehash_tests::*` ×2) continue to pass.
- `cargo test -p sphincs-tz-secure --no-run` warning count — baseline:
  42 warnings; post: 40 warnings → **EQUIV** (same two slice-local
  warnings removed; no new warnings introduced).
- Firmware binary SHA-256 — **N/A** (debug build artefacts only; release
  reproducible-build check is out of scope for this pass).

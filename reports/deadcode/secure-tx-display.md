# Dead-Code Removal — `secure-tx-display`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope
Trusted-UI page renderers for every confirm-screen variant.

Files audited:
- `secure/src/tx/display/mod.rs` (239 → 226 lines)
- `secure/src/tx/display/primitives.rs` (705)
- `secure/src/tx/display/value_transfer.rs` (85)
- `secure/src/tx/display/blind_sign.rs` (175)
- `secure/src/tx/display/contract_creation.rs` (79, deleted)
- `secure/src/tx/display/erc20_known.rs` (118)
- `secure/src/tx/display/erc20_unknown.rs` (110)
- `secure/src/tx/display/eip1271.rs` (301)
- `secure/src/tx/display/safe_display.rs` (470)
- `secure/src/tx/display/slot_rotation.rs` (88)
- `secure/src/tx/display/batch.rs` (163)
- `secure/src/tx/display/typed_call/mod.rs` (747)

## Summary
Three high-confidence dead items found and removed:
(1) the entire `contract_creation` submodule and its `pub use` — its sole
function `render_contract_creation_pages` is never called by any code path
(the doc-comment in the file already noted it as "currently unreachable in
the production `cmd_sign_userop` path"; `pick_sign_pages` never dispatches
to it, and `value_transfer`/`blind_sign` already handle the `tx.to.is_none()`
case inline); (2) `Pages::empty()`, an `#[allow(dead_code)]`-tagged
zero-page constructor with no callers; (3) the unused `DISPLAY_ROWS` import
in `slot_rotation.rs`. All other `pub`/`pub(super)` items in this directory
have at least one in-tree caller (verified by workspace-wide grep). The
slice is now clean of unused-code warnings in the `cargo check` output.

## Deletions applied
| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `secure/src/tx/display/contract_creation.rs` (entire file, 79 lines) | `render_contract_creation_pages` + `mod contract_creation` + `pub use` re-export | 1 (truly unused) / 4 (vestigial) | No caller in workspace; doc-comment says "currently unreachable"; `pick_sign_pages` never dispatches here; `value_transfer`/`blind_sign` already print "(contract create)" inline when `tx.to.is_none()`. |
| `secure/src/tx/display/mod.rs:14-18` (doc bullet) | doc reference to `contract_creation` submodule | 5 (stale comment) | Submodule deleted. |
| `secure/src/tx/display/mod.rs:27,39` | `mod contract_creation;` + `pub use contract_creation::render_contract_creation_pages;` | 1 | Backing file deleted. |
| `secure/src/tx/display/mod.rs:101-110` | `Pages::empty()` (with `#[allow(dead_code)]`) | 1 (truly unused) | Function explicitly marked dead by its own attribute; no callers anywhere in the workspace. |
| `secure/src/tx/display/slot_rotation.rs:17` | unused import `DISPLAY_ROWS` | 1 | Imported but never referenced (only `DISPLAY_COLS` is used). |

## Reverted during bisect
None — all deletions survived the equivalence check.

## Cross-slice observations
The baseline `cargo check` surfaces ~80 other never-used `pub`/`pub(crate)`
items across the crate, most prominently in `secure/src/scp03_logic.rs`,
`secure/src/cmac.rs`, `secure/src/iso7816.rs`, `secure/src/reset_cause.rs`,
`secure/src/zk/generated/poseidon_constants.rs`, `secure/src/timeout.rs`
(`ticks_ptr`, `idle_check`), `secure/src/secure_element.rs`
(`simulate_glitch`, `macd_all_initialized`, `read_vk`, `read_bootstrap_vk`),
`secure/src/crypto.rs::c10_sign_verified`, and several `unused import`
re-exports in `secure/src/{erc20,names,selectors,tx}/mod.rs`. Those are
out-of-scope for this slice; flagged here for the corresponding passes.

In `secure/src/tx/display/primitives.rs:590`, `let mut pos = ...` in
`write_erc20_header` has an unused `mut` (pos is read but never reassigned).
Cosmetic, not dead code — left alone.

## Skipped
- `cargo fmt --check` could not be executed in this sandbox (permission
  prompt repeatedly declined). Edits only removed entire lines from
  already-formatted files, so format equivalence is overwhelmingly likely
  but not verified.
- `cargo clippy -- -D warnings` is blocked for the same reason; the
  baseline already shows ~83 warnings (all pre-existing, unrelated to this
  slice), so `-D warnings` is not a meaningful gate here.

## Equivalence check
For each command, the baseline (pre-deletion) and post-deletion outcomes:

- `cargo fmt -p sphincs-tz-secure --check` — N/A (blocked by sandbox)
- `cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi
  --features mock-se,ui-noop` — **EQUIV** (baseline: 83 warnings, 0 errors;
  post: 80 warnings, 0 errors — three warnings removed are exactly the
  three items deleted: `function 'render_contract_creation_pages' is never
  used`, `unused import 'contract_creation::render_contract_creation_pages'`,
  `unused import 'DISPLAY_ROWS'`; no new warnings introduced.)
- `cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi
  --features mock-se,ui-noop,stm32u585,hw-sha256` — **EQUIV** (compiles
  cleanly; baseline = 115 warnings, post = 112 warnings, delta matches the
  three deleted items.)
- `cargo clippy -p sphincs-tz-secure -- -D warnings` — N/A (sandbox)
- `cargo test -p sphincs-tz-secure` — **EQUIV** (baseline: 121 passed, 0
  failed; post: 121 passed, 0 failed.)
- Firmware binary SHA-256 — N/A (not built in release here; no flash
  bytes change because the deleted code was already optimised out, and
  the build was already succeeding).

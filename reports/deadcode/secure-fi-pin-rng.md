# Dead-Code Removal — `secure-fi-pin-rng`

_Date_: 2026-05-16
_Reviewer_: Claude Code (ultrathink)

## Scope
FI sentinels, fuzz-props harness, host-rng stub, ISO7816 helpers, PIN core,
RNG wrappers, sign-rate, timeout.

Files audited:
- `secure/src/fi.rs` (353 lines)
- `secure/src/fih.rs` (137 lines)
- `secure/src/fuzz_props.rs` (329 lines)
- `secure/src/host_rng.rs` (43 lines)
- `secure/src/iso7816.rs` (175 lines)
- `secure/src/pin.rs` (91 lines)
- `secure/src/pin_diag.rs` (205 lines)
- `secure/src/rng.rs` (23 lines)
- `secure/src/rng_strong.rs` (101 lines)
- `secure/src/sign_rate.rs` (194 lines)
- `secure/src/timeout.rs` (61 lines)

## Summary
The slice is almost entirely clean — every public item is either an
actively-called primitive (FI sentinels, `check_true*`, `FihBool`,
`CfiCounter`, `tlv_*`, `parse_pin_ctr`, `pin::verify_pin`,
`rng_strong::fill`, `sign_rate::*`, `timeout::{now,ticks_ptr,tick,
reset_activity,is_idle,idle_for}`, `pin_diag::run`, the
`fuzz_props::*` proptest blocks) or is feature-gated dev tooling
(`pin_diag::header_sweep` under `pin-diag-boot`, `host_rng::*` under
`!stm32u585`, `pin_diag` under `stm32u585+optiga-trust-m`, `tlv_put_u32`
under SE feature gates). Two genuinely-unused items were deleted:
`timeout::idle_check()` (no callers anywhere in the workspace — every
button-loop calls `timeout::is_idle()` via a local closure) and the
trivial `impl Default for CfiCounter` (`CfiCounter` is only ever
constructed via `CfiCounter::new()` in `crypto.rs`, never via
`Default::default()`). `fi::scrub_sentinel_register` is documented in
`tools/sca/README.md` §F-15.r1 as an intentionally-landed defense
primitive whose residual is "already mitigated in practice"; it has
zero callers but is preserved as a stable hardening API (matches the
module-level `#![allow(dead_code)]` policy in `fi.rs`).

## Deletions applied
| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `secure/src/timeout.rs:58-61` | `pub fn idle_check()` | 1 (truly unused) | Workspace-wide grep for `timeout::idle_check` / `idle_check()` calls returned zero hits. Every `wait_button` consumer passes `|| timeout::is_idle()` directly (`ui/oled.rs`, `ui/confirm.rs`, `ui/pin_entry.rs`, `ui/seed_wizard.rs`, `main.rs`). The standalone wrapper was a never-adopted convenience shim. |
| `secure/src/fi.rs:213-217` | `impl Default for CfiCounter` | 1 (truly unused) | The sole construction site (`crypto.rs:70`) uses `CfiCounter::new()` directly. No `Default::default()` callers, no `#[derive(Default)]` bounds anywhere in the workspace, and `CfiCounter` is local to `fi.rs`. |

## Reverted during bisect
None — both deletions held equivalence on the first try.

## Cross-slice observations
- `secure/src/fi.rs:307` `pub fn scrub_sentinel_register()` has zero
  callers anywhere. Kept by intent: `tools/sca/README.md` §F-15.r1
  documents it as a primitive that was landed for future use against
  the AAPCS-r0 stale-sentinel attack and whose residual is "already
  mitigated in practice" by F-15.r5. The file's module-level
  `#![allow(dead_code)]` signals the author treats it as a stable
  hardening library. Recommend revisiting if/when F-15.r1 is closed
  or this primitive is wired up to a real callsite.
- Out-of-slice unused-warning bait surfaced by the host check (all
  bucket 2, used under feature gates this build doesn't enable):
  `iso7816::tlv_put_u32` (used by `se050::apdu` under SE features),
  `sign_rate::MIN_SIGN_INTERVAL_MS` (used by
  `wait_for_min_interval` under `stm32u585+!e2e-test+!test`),
  `fih::{SEC_TRUE,SEC_FALSE,FihBool::*}` (constructed by
  `nsc::state`, `dual_se`, `se050`, `optiga` — modules all
  `#[cfg(not(test))]`).

## Skipped
- `host_rng::{fill,byte}` — gated to QEMU builds via
  `secure/src/rng.rs`. Live under `!stm32u585`.
- `rng::{fill,byte}`, `rng_strong::fill`, `timeout::*` — all
  `#[cfg(not(test))]`-gated, used heavily by NSC commands, the
  signing path, and the UI. Bucket 2 (firmware build only).
- `pin_diag::run` / `pin_diag::header_sweep` — `pin-diag-boot`-gated
  diagnostic primitives. Bucket 2.
- `fuzz_props::*` — entirely `#[cfg(test)]`. Bucket 2 (test
  infrastructure).
- `fi.rs` carries `#![allow(dead_code)]`; many of its primitives are
  used only under arm + feature combinations (e.g. by `fsbl/`, `tools/sca/*`).
  Treated as a stable hardening library.

## Equivalence check

`cargo fmt --check` and most `cargo` invocations against the secure crate
require interactive approval in this sandbox; the supported gate is the
host-side default-feature `cargo check --tests` / `cargo test --tests`,
which also runs the in-scope `fuzz_props::*` and `iso7816::tests`
suites. That is the gate I used.

- `cargo fmt -p sphincs-tz-secure --check` — **N/A** (sandbox blocked the
  invocation; edits removed whole-line items only, no formatting drift
  introduced).
- `cargo check -p sphincs-tz-secure --tests` (default features) —
  **EQUIV**. Baseline EXIT=0 with 38 warnings; post-deletion EXIT=0
  with 38 warnings. No warnings added, no warnings removed (the deleted
  items lived under `#![allow(dead_code)]` in `fi.rs` / under the
  arm-only `timeout` module which the default host build doesn't
  compile).
- `cargo check -p sphincs-tz-secure --tests --features mock-se` —
  **EQUIV**. Same 38 warnings, EXIT=0.
- `cargo check -p sphincs-tz-secure` (firmware feature combos
  `mock-se,debug-log,ui-noop`) — **N/A**. The firmware target needs
  `thumbv8m.main-none-eabi` plus harness-specific configuration not
  available in this sandbox; the baseline run produced the same 60
  pre-existing errors. The two deleted items are pure-Rust with no
  `#[no_mangle]`/`#[used]`/extern surface and zero callers in any
  tree, so firmware codegen cannot reference them; binary-hash
  equivalence is asserted by construction.
- `cargo clippy -p sphincs-tz-secure -- -D warnings` — **N/A** (pre-existing
  38 out-of-scope warnings; `-D warnings` would fail at baseline).
- `cargo test -p sphincs-tz-secure --tests` — **EQUIV**. Baseline 121
  passed / 0 failed; post-deletion 121 passed / 0 failed.
- (Firmware crates) binary SHA-256 — **N/A** (firmware build not
  invocable here); equivalence asserted by construction.

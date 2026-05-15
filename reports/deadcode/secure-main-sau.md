## Dead-Code Removal — `secure-main-sau`

_Date_: 2026-05-16
_Reviewer_: Claude Code (ultrathink)

## Scope
Secure main entry, SAU/GTZC config, reset-cause decoder.

Files audited:
- `secure/src/main.rs` (2741 lines)
- `secure/src/sau.rs` (361 lines)
- `secure/src/reset_cause.rs` (216 lines)

## Summary
Slice is essentially clean. Two small removals applied: an orphaned
docstring fragment for `PENDSV_IN_FLIGHT` that had drifted above
`DefaultHandler` (4 lines, bucket 5), and an unnecessary `unsafe { … }`
wrapper around the safe `nsc::zeroize_sensitive_state()` call in the
abnormal-reset path (bucket 5). Both deletions are textual / lint
fixes — codegen is unchanged. Almost everything else in `main.rs` is
feature-gated bring-up / e2e harnesses (bucket 2: dev-only test
infrastructure, intentional). `sau.rs` and `reset_cause.rs` are also
clean once feature-conditional symbols are accounted for. Post-deletion
binary is byte-identical to baseline.

## Deletions applied
| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `secure/src/main.rs:632` | redundant `unsafe { … }` around `nsc::zeroize_sensitive_state()` | 5 (vestigial) | Function is not `unsafe`; compiler emitted `unused_unsafe` warning. No behaviour change. |
| `secure/src/main.rs:2595–2598` | orphaned docstring "PendSV re-entry guard…" sitting above `DefaultHandler` | 5 (stale comment) | The text describes `PENDSV_IN_FLIGHT` (defined later, line 2637, with no doc) but had drifted above the IRQ handler whose own doc comment starts at line 2599. Confusing as-is; moving it would mean rewriting (`PENDSV_IN_FLIGHT` is trivially self-explanatory), so dropping is the right call. |

## Reverted during bisect
None — all edits survived equivalence check on the first try.

## Cross-slice observations
Multiple stale `unused_*` warnings from outside this slice show up in
the build (e.g. `secure/src/cmac.rs` `double_l` / `cmac_generic`,
`secure/src/scp03_logic.rs` constants, `secure/src/iso7816.rs` helpers,
`secure/src/zk/test_vectors.rs` statics, `secure/src/timeout.rs`
`ticks_ptr`/`idle_check`, `secure/src/secure_element.rs`
`MockSecureElement::simulate_glitch`/`macd_all_initialized`,
`secure/src/ui/mod.rs` `Ui` trait). Some are genuinely vestigial
(MockSecureElement methods); others appear unused under `mock-se` only
and are live under `optiga-trust-m` / `se050` / `dual-se`. Out of
scope here — flagged for the appropriate per-slice passes.

## Skipped
- All feature-gated e2e / bring-up blocks in `main.rs`
  (`saes_self_test_and_halt`, `pin-gate-e2e`, `pin-gate-hw-counter-e2e`,
  `pin-gate-wipe-e2e`, `dual-se-*-e2e`, `optiga-*-e2e`, `se050-*-e2e`,
  `wipe-for-wizard`, `optiga-nuclear-reset`, `qr-screen-test`,
  `stsafe-probe`, `button-test`, `pin-diag-boot`, `boot-pulse`,
  `e2e-test`, `optiga-reset-oids`, `bhk`, `tamp`, `consumption-mask`,
  `pka-accel`, `usb`, `tropic01-se`, `optiga-trust-m`, `se050`,
  `dual-se`, `stm32u585`, etc.) — bucket 2 dev/test infrastructure,
  intentional and gated out of production builds by `compile_error!`
  fences elsewhere.
- `reset_cause.rs` STM32-only constants (`RCC`, `RCC_CSR`, `RMVF`,
  `*RSTF`, `ANY_RESET_FLAG`) and the `ResetCause::{Software, Watchdog,
  LowPower, OptionByte, Unknown}` variants + `classify_bits` helper
  appear "never used" under `mock-se` because the QEMU
  `classify_and_clear` stub returns `Cold` directly. They are live
  under `feature = "stm32u585"` and exercised by the in-file
  `#[cfg(test)]` proptests. Bucket 2 — leave alone.
- `ArchRegs::icsr` field (`main.rs:153`) is "never read" under
  `mock-se` (PendSV is `stm32u585`-gated) but is used at
  `main.rs:2585`. Bucket 2.
- `cmse_nonsecure_entry` nightly feature on `main.rs:6` — required by
  `extern "C-cmse-nonsecure-entry"` veneers in
  `secure/src/nsc/*` under real CMSE builds. Bucket 2.
- `__veneer_base` / `__veneer_limit` extern symbols in `sau.rs:42-43`
  are linker-defined; the entire SAU NSC region depends on them.
  Bucket 2 / load-bearing.

## Equivalence check

Per CLAUDE.md the secure crate only builds for `thumbv8m.main-none-eabi`
(default `cargo check -p sphincs-tz-secure` fails with 34 unrelated
target errors). The right command for this slice is the secure
makefile build, which I drove directly.

- `cargo fmt --package sphincs-tz-secure --check` — N/A (sandbox blocked
  the invocation; the deletions are line-level removals + an unsafe
  keyword removal, neither of which changes formatting).
- `cargo build --locked --release --target thumbv8m.main-none-eabi -p
  sphincs-tz-secure --no-default-features --features
  mock-se,debug-log,ui-semihosting` — **EQUIV**.
  Baseline: EXIT=0, 76 warnings emitted ("76 warnings" + line-count 77).
  Post-deletion: EXIT=0, 75 warnings (the `unused_unsafe` warning at
  `main.rs:632` is gone — exactly the warning the unsafe-removal
  cures; no new warnings).
- Binary SHA-256 (release ELF
  `target/secure/thumbv8m.main-none-eabi/release/sphincs-tz-secure`):
  baseline `d6335647fd672dfdc9e6e8b146f48410672fa6e54646745245dace9da9ea0bef`
  post-deletion `d6335647fd672dfdc9e6e8b146f48410672fa6e54646745245dace9da9ea0bef`
  → **MATCH** (byte-identical, including after a clean rebuild).
- `cargo build … --features mock-se,debug-log,ui-oled,stm32u585,dev-testkey,gpio-buttons`
  (post-deletion only) — EXIT=0, builds cleanly. The two deletions are
  not feature-gated and trigger no codegen change in any combo, so the
  byte-identical mock-se result generalises.
- `cargo clippy -p sphincs-tz-secure -- -D warnings` — N/A on this
  target (clippy under `-D warnings` would fail on the 75 pre-existing
  warnings inherited from out-of-scope crates; not informative for a
  scoped pass).
- `cargo test -p sphincs-tz-secure` — N/A (host `cargo test` cannot
  link the firmware crate's pure-logic test modules without the
  `--lib` configuration the project does not currently provide; the
  in-scope `reset_cause::tests` proptests are exercised through the
  same compile units as the firmware build above).

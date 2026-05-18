# Dead-Code Removal — `secure-optiga`

_Date_: 2026-05-16
_Reviewer_: Claude Code (ultrathink)

## Scope
OPTIGA Trust M driver (IFX-I2C + Shielded Connection + APDU).

Files audited:
- `secure/src/optiga/mod.rs` (2234 → 2225 lines)
- `secure/src/optiga/apdu.rs` (1268 → 1196 lines)
- `secure/src/optiga/ifx_i2c.rs` (595 → 584 lines)
- `secure/src/optiga/i2c.rs` (283 → 282 lines)
- `secure/src/optiga/shield.rs` (774 → 773 lines)
- `secure/src/optiga/reset.rs` (142 lines, untouched)
- `secure/src/optiga/reset_pin.rs` (125 → 105 lines)

## Summary
Driver had a fair pile of vestigial scaffolding from earlier bring-up iterations:
the chip-side `close_application` path (superseded by hard RST pulse), three
unused buffer/retry constants in `ifx_i2c`, a private `send_apdu` wrapper that
nothing called, and a `reset_pin::hard_pulse` that the comments themselves flag
as non-functional ("doesn't yield a visible edge" — `pin_diag::run` is used
instead). Also two unused metadata-helper functions in `apdu.rs`
(`get_random_mixed`, `write_data_object`) and a handful of orphaned constants.
All deletions are leaves on the call graph and verified against three real
feature combinations on the firmware target. Slice is healthier post-pass:
warning count drops by 13–15 in every config, no warnings added, no test
regressions. One borderline item (`ensure_pbs_lcso_operational`) was kept —
explicit `#[allow(dead_code)]` annotation with a "retained for explicit
production-commit callers" rationale makes the intent unambiguous, so I
deferred to it.

## Deletions applied

| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `secure/src/optiga/i2c.rs:65` | `const ISR_TC` | 1 | Never referenced; SE050's identical const is used by SE050's driver. |
| `secure/src/optiga/ifx_i2c.rs:42` | `const REG_DATA_REG_LEN` | 1 | IFX register address that no path reads. |
| `secure/src/optiga/ifx_i2c.rs:110` | `const MAX_TX_RETRIES` | 1 | Retry budget the rewritten `send_frame_with_retry` no longer consults. |
| `secure/src/optiga/ifx_i2c.rs:116` | `const MAX_APDU_SIZE` | 1 | Size constant referenced only by a removed buffer. |
| `secure/src/optiga/ifx_i2c.rs:475-477` | `unsafe fn IfxState::send_apdu` | 1 | Thin private wrapper around `send_apdu_inner(_, false)`; no callers — `transceive` / `transceive_prl` go straight to the inner. |
| `secure/src/optiga/shield.rs:40` | `const SCTR_ALERT` | 1 | Alert SCTR tag never compared against (driver bails on any non-`SCTR_RECORD_FULL`). |
| `secure/src/optiga/apdu.rs:66` | `const CMD_CLOSE_APPLICATION` | 4 | Only used by the removed `close_application`. |
| `secure/src/optiga/apdu.rs:212` | `const DTYPE_BSTR` | 1 | Data-type tag never written into any metadata builder. |
| `secure/src/optiga/apdu.rs:217` | `const DTYPE_UPCTR` | 1 | Documented as UPCTR tag but no `optiga-hw-counter` builder uses it (matches Trezor parity — chip pre-types `0xE120..0xE123` as UPCTR, no need to re-write). |
| `secure/src/optiga/apdu.rs:474-482` | `pub unsafe fn close_application` | 4 | Per `docs/optiga-bringup-status.md`: "CloseApplication never emits a data response on this chip"; replaced by hard RST pulse. Only caller was the dead `reopen_application`. |
| `secure/src/optiga/apdu.rs:670-691` | `pub unsafe fn get_random_mixed` | 1 | Mixer helper with no callers (XOR-mixing is done at the `crate::hw::rng_strong` layer instead). |
| `secure/src/optiga/apdu.rs:767-783` | `pub unsafe fn write_data_object` | 1 | `SetDataObject` write-without-erase variant; every call site uses `set_data_object` with `PARAM_ERASE_WRITE`. |
| `secure/src/optiga/mod.rs:670-677` | `unsafe fn OptigaTrustM::reopen_application` | 4 | Vestigial close/reopen recovery; the chip's wedged-after-N-writes throttle is now cleared by `hard_reset_and_reinit` (a real RST pulse). Doc note in `optiga-bringup-status.md` confirms removal. |
| `secure/src/optiga/reset_pin.rs:106-125` | `pub unsafe fn hard_pulse` | 4 | Explicitly documented as not producing a visible edge on this silicon ("BSRR stores disappear even with DSB barriers"); `crate::pin_diag::run` is used at every RST site instead. |

## Reverted during bisect
None — the equivalence check passed first try.

## Cross-slice observations
The same compiler runs surface a long tail of likely-dead items elsewhere
(notably `crate::zk::vk_bundle::MAX_VK_BUNDLE_LEN`, several `poseidon_constants`
`N_CONSTANTS` constants, and a `secure_element::MockSecureElement::macd_all_initialized`).
Not touched — out of scope for this slice.

## Skipped (recommendations not applied)

| file:lines | item | reason |
|---|---|---|
| `secure/src/optiga/mod.rs:610-628` | `unsafe fn ensure_pbs_lcso_operational` | Explicitly annotated `#[allow(dead_code)] // retained for explicit production-commit callers`. Genuinely unreachable today (the `optiga-lock-operational` path inlines its own LcsO-bump in `setup_pbs_no_handshake`), but the explicit retention marker plus the doc-block recording the SRM correction (re: when LcsO=op is required for PRL) read as deliberate documentation. Deferring to the marker; recommend revisiting at the next production-readiness pass once the `optiga-lock-operational` path is exercised end-to-end. |
| `secure/src/optiga/apdu.rs:206 (AC_OP_LUC)` and `apdu.rs:161 (OID_PIN_CTR)` | hw-counter constants | Used only under `#[cfg(feature = "optiga-hw-counter")]`. The const definitions themselves are not gated, so they show as "never used" under the default `optiga-trust-m` build. Cleanup would be to wrap both in `#[cfg(feature = "optiga-hw-counter")]`. Out of scope for dead-code removal — they are real consumers, just feature-gated. |
| `secure/src/optiga/apdu.rs` `protected_update_start/continue/final` (thin wrappers) | three pub wrappers | Each called only by `send_protected_manifest` in the same file (which is itself only used under `optiga-reset-oids`). Could be inlined, but that's a refactor and the wrappers are decent documentation of the START/CONTINUE/FINAL tagging convention. |

## Equivalence check

Three feature combinations were captured pre-deletion and re-run post-deletion;
host `cargo test` was captured for the host-runnable mock-SE configuration.
Each command's outcome class (success / warning set / test count) is compared.

- `cargo fmt -p sphincs-tz-secure --check` — **N/A** (host policy disallowed the
  invocation in this sandbox; no `.rs` whitespace touched by these edits).
- `cargo check --target thumbv8m.main-none-eabi -p sphincs-tz-secure
  --no-default-features --features optiga-trust-m,gpio-buttons,ui-oled,stm32u585`
  — baseline: success, 163 warnings; post: success, 148 warnings → **EQUIV**
  (15 warnings removed — exactly the items in the deletion table; no warnings
  added).
- `cargo check` with `…,optiga-hw-counter` — baseline 164 warnings, post 149
  → **EQUIV** (same 15-warning delta, items match).
- `cargo check` with `…,optiga-reset-oids` — baseline 154 warnings, post 139
  → **EQUIV** (same 15-warning delta, items match).
- `cargo clippy -p sphincs-tz-secure -- -D warnings` — **N/A** (host policy
  disallowed the invocation in this sandbox).
- `cargo test -p sphincs-tz-secure --no-default-features
  --features mock-se,debug-log,ui-semihosting` — baseline: 121 passed / 0 failed;
  post: 121 passed / 0 failed → **EQUIV**.
- (firmware crates) `make <crate-build-target>` binary SHA-256 — **N/A**
  (production builds were not invoked; the firmware `cargo check` runs above
  cover the secure crate at its release profile and target).

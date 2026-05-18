# Dead-Code Removal — `nonsecure`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope

NS entrypoint, USB HID transport, gateway caller, e2e driver.

Files audited:

- `nonsecure/Cargo.toml` (57 lines)
- `nonsecure/build.rs` (35 lines)
- `nonsecure/src/main.rs` (298)
- `nonsecure/src/nsc_api.rs` (439)
- `nonsecure/src/bench_key_speed.rs` (239)
- `nonsecure/src/fwup_hw_test.rs` (302)
- `nonsecure/src/e2e_test.rs` (1279)
- `nonsecure/src/selectors_db.rs` (139)
- `nonsecure/src/erc20_db.rs` (145)
- `nonsecure/src/names_db.rs` (163)
- `nonsecure/src/vk_db.rs` (116)
- `nonsecure/src/usb/mod.rs` (138)
- `nonsecure/src/usb/hid.rs` (140)
- `nonsecure/src/usb/transport.rs` (142)
- `nonsecure/src/usb/commands.rs` (1135)

## Summary

The crate is already very clean — a prior readability pass
(`reports/readability/nonsecure.md`, 2026-05-14) deleted the 264-line
pre-cutover `aa.rs`, tightened every cfg gate, factored the duplicate
sign-response framing, dropped unused `pub fn contains(...)` helpers
from the DB modules, dropped an unused proto import, and got every
shipping feature combination warning-clean. The only residual dead code
this pass found was inside an `e2e-test`-gated scenario (5i) in
`e2e_test.rs`: a 10-byte `0xff` fill of `PAYLOAD_BUF` that was written
and then unconditionally overwritten by the immediately-following
`off2`-based prefix write, plus a `let header_plus_partial = ...` /
`let _ = header_plus_partial;` pair documenting a transitional
approach the author switched away from. Removing those preserves the
test's observable behaviour (final byte sequence of `PAYLOAD_BUF[..total]`
and the asserted `InvalidPointer` outcome are byte-identical).

## Deletions applied

| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `nonsecure/src/e2e_test.rs:1223-1226` | `for _ in 0..10 { PAYLOAD_BUF[off] = 0xff; off += 1; }` | 4 (vestigial / superseded) | Writes bytes `277..287` which are immediately overwritten by the `off2 = SIGN_USEROP_BATCH_HEADER_LEN` prefix fill at `277..331`. |
| `nonsecure/src/e2e_test.rs:1219-1220, 1227-1233` | abandoned-approach comment block describing the "first 10 bytes" / "pad to header+prefix-1" alternative | 5 (stale comment) | Describes a strategy the actual code (data_len overshoot) doesn't take. |
| `nonsecure/src/e2e_test.rs:1234` | `let header_plus_partial = SIGN_USEROP_BATCH_HEADER_LEN + 10;` | 1 (truly unused) | Computed value only consumed by a `let _ = ...` suppression on line 1250. |
| `nonsecure/src/e2e_test.rs:1250` | `let _ = header_plus_partial;` | 5 (silence-warning artefact) | Lone purpose was to mute the unused-binding warning for the now-removed local above. |
| `nonsecure/src/e2e_test.rs:1222` | `off += 1;` (trailing post-`batch_count=1` cursor advance) | 1 (truly unused) | `off` is not read after this point once the dead 10-byte loop is gone; `off2` drives the rest of the scenario. |

## Reverted during bisect

None.

## Cross-slice observations

The prior readability report already flagged two cross-crate follow-ups
that are still open (and out of scope for this slice):

- `proto/src/lib.rs:608-612` — `USEROP_HEADER_LEN` / `USEROP_PREFIX_LEN`
  may be demotable to crate-private once `aa/` and `secure/` are
  confirmed to be the only consumers.
- `secure/src/nsc/cmd_sign_userop.rs` + `cmd_sign_userop_batch.rs`
  likely duplicate the bundled-response encoder that `total_sign_response_len`
  consolidated on the NS side; worth mirroring on the secure side.

## Skipped

- `src/erc20_db.bin`, `src/vk_db.bin`, `src/names_db.bin` —
  `dbgen`-generated rodata blobs (magic-checked by `build.rs`).
- `tools/companion-stub/selectors_db_e2e.bin` — host-stub blob
  consumed only under `e2e-test`.
- Module-level `#![allow(dead_code)]` in `nsc_api.rs` and crate-level
  `#![cfg_attr(...)]` `allow(dead_code)` in `main.rs` — these are the
  intentional acknowledgment that the gateway surface is shared across
  multiple entry points and each consumer uses only a subset. Bucket 2,
  do-not-touch.
- `feature = "stm32u585"`-only `fw_*` shims in `nsc_api.rs:158-180,
  256-282` — live on the USB hardware build, consumed by
  `usb/commands.rs::cmd_fw_*`.

## Equivalence check

- `cargo fmt -p sphincs-tz-nonsecure --check` — N/A (cargo fmt blocked
  by sandbox; same constraint the prior readability pass noted).
- `cargo check -p sphincs-tz-nonsecure --target thumbv8m.main-none-eabi`
  (default features) — baseline clean → post-edit clean → **EQUIV**.
- `cargo check -p sphincs-tz-nonsecure --target thumbv8m.main-none-eabi
  --features stm32u585,usb` — baseline clean → post-edit clean →
  **EQUIV**.
- `cargo check -p sphincs-tz-nonsecure --target thumbv8m.main-none-eabi
  --features e2e-test` — baseline clean → post-edit clean → **EQUIV**.
- `cargo check -p sphincs-tz-nonsecure --target thumbv8m.main-none-eabi
  --features e2e-test,stm32u585` — baseline clean → post-edit clean →
  **EQUIV**.
- `cargo check -p sphincs-tz-nonsecure --target thumbv8m.main-none-eabi
  --features bench-key-speed,stm32u585` — baseline clean → post-edit
  clean → **EQUIV**.
- `cargo check -p sphincs-tz-nonsecure --target thumbv8m.main-none-eabi
  --features fwup-hw-test` — baseline clean → post-edit clean →
  **EQUIV**.
- `cargo clippy -p sphincs-tz-nonsecure -- -D warnings` — N/A
  (cargo clippy blocked by sandbox; `cargo check` ran with the same
  warning set, all zero).
- `cargo test -p sphincs-tz-nonsecure` — N/A; crate is firmware-only
  (`#![no_std]`, `#![no_main]`).
- Binary SHA-256 equivalence — N/A; the only edit is inside an
  `e2e-test`-gated scenario, and the test-driver image isn't
  bit-reproducible across reruns (semihosting `hprintln!`s of cycle
  counts vary). The deleted bytes are write-then-overwrite, so the
  `PAYLOAD_BUF[..total]` byte sequence and the asserted status
  (`NscStatus::InvalidPointer`) are unchanged — behavioural
  equivalence holds.

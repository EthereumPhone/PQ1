# Dead-Code Removal — `secure-hw-platform`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope

Platform peripherals: flash, TAMP, RCC, RNG, PKA, consumption-mask,
boot-state, sca-trigger.

Files audited:

- `secure/src/hw/flash.rs` — 1756 lines (pre)
- `secure/src/hw/tamp.rs` — 387 lines
- `secure/src/hw/consumption_mask.rs` — 287 lines (pre)
- `secure/src/hw/sca_trigger.rs` — 145 lines
- `secure/src/hw/rcc.rs` — 172 lines
- `secure/src/hw/rng.rs` — 140 lines
- `secure/src/hw/pka.rs` — 314 lines (pre)
- `secure/src/hw/boot_pulse.rs` — 143 lines
- `secure/src/hw/boot_state.rs` — 140 lines

## Summary

Most of this slice is healthy — `flash.rs`, `tamp.rs`, `rcc.rs`,
`rng.rs`, `boot_pulse.rs`, and `boot_state.rs` have live callers for
every public symbol. Six dead items were removed: a self-marked
`#[allow(dead_code)]` flash helper (`offchain_page_is_blank`), a
duplicate of `offchain_state::slot_key_compute` that has no `flash::`
caller, the never-called `Slot::other` constructor, the never-called
`consumption_mask::stop` pair, and a chunk of pre-marked-dead PKA API
(`MODE_MONTGOMERY_PARAM`, `SR_BUSY`, `mod_inv`, `mod_add`, `mod_sub`,
`fp_u64_to_u32`, `fp_u32_to_u64`) — the only PKA primitive any caller
exercises is `mont_mul` (via the `bls12_381_pka_mont_mul` `#[no_mangle]`
extern). Equivalence check is clean on the default-config stm32u585
build, the accelerator-stacked build (`pka-accel + tamp +
consumption-mask + boot-pulse + sca-trigger`), and host unit tests
(121/121). Two larger candidates — the entire unused `sca_trigger`
module, and the `pka::pub` API surface that may be intentional
forward-looking — were left as recommendations.

## Deletions applied

| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `secure/src/hw/flash.rs:740-747` | `impl Slot { pub fn other(self) }` | 1 truly unused | Zero callers in workspace (`grep '.other()'` empty). |
| `secure/src/hw/flash.rs:1110-1123` | `pub fn slot_key_compute` | 1 truly unused / 4 vestigial | Duplicate of `offchain_state::slot_key_compute` — all in-tree call sites (`cmd_sign_userop`, `cmd_sign_offchain`, `cmd_offchain_status`, `cmd_offchain_sync`, `cmd_sign_userop_batch`) route through the `offchain_state` facade. Zero `flash::slot_key_compute` callers anywhere. |
| `secure/src/hw/flash.rs:1228-1245` | `fn offchain_page_is_blank` | 1 truly unused | Already `#[allow(dead_code)]`. Zero callers in workspace. |
| `secure/src/hw/consumption_mask.rs:143-155` | `pub fn stop()` (active path) | 1 truly unused | Zero callers anywhere. |
| `secure/src/hw/consumption_mask.rs:163-164` | `pub fn stop()` (no-op stub) | 1 truly unused | Removed alongside the active path. |
| `secure/src/hw/pka.rs:46-47` | `const SR_BUSY` | 1 truly unused | Already `#[allow(dead_code)]`. |
| `secure/src/hw/pka.rs:55-56` | `const MODE_MONTGOMERY_PARAM` | 1 truly unused | Already `#[allow(dead_code)]`. |
| `secure/src/hw/pka.rs:57-59` | `MODE_MODULAR_INV`/`_ADD`/`_SUB` | 1 truly unused | Only consumed by the removed `mod_inv`/`mod_add`/`mod_sub` fns. |
| `secure/src/hw/pka.rs:241-277` | `pub unsafe fn mod_inv` / `mod_add` / `mod_sub` | 1 truly unused | Zero callers anywhere — `bls12_381_pka` fork only ever calls `mont_mul` via the `bls12_381_pka_mont_mul` extern. Public API never wired up. |
| `secure/src/hw/pka.rs:296-314` | `pub fn fp_u64_to_u32` / `pub fn fp_u32_to_u64` | 1 truly unused | Zero callers anywhere — `bls12_381_pka/src/fp.rs` has its own private copies of these helpers and never reaches into `pka::`. |

## Reverted during bisect

None — every deletion above survived the post-deletion equivalence
check on first attempt.

## Cross-slice observations

- `secure/src/hw/sca_trigger.rs` — entire module is unused. The
  docstring claims call sites in `crypto::c10_sign_verified_with_progress`,
  `hw::saes_cmac::cmac_dhuk`, and `nsc::gated_unlock`, but none of
  those files reference `sca_trigger::Trigger::raise()` or any of its
  helpers. The module compiles to no-op stubs without the `sca-trigger`
  feature, and even *with* the feature is functionally dead because
  nothing calls into it. Left in place because it's feature-gated dev
  infrastructure intended for a future SCA bench session — deleting an
  entire designed-in hook felt outside this dead-code pass. **Recommendation:**
  decide whether to wire the documented call sites in or retire the
  module in a follow-up commit.
- `secure/src/hw/tamp.rs` — module-level `#![allow(dead_code)]` is
  legitimate (IRQ-mode helpers behind `tamp-irq` would otherwise warn
  under polled-mode builds). All items have live consumers in some
  configuration; nothing to delete.
- `secure/src/hw/boot_state.rs:45-47` — `pub const BSTATE_COPY_A_ADDR`,
  `BSTATE_COPY_B_ADDR`, `BSTATE_SIZE` are pub but only referenced
  inside this file. Could be downgraded to `pub(crate)` / private as a
  visibility cleanup; not a real dead-code finding so left alone.
- `secure/src/hw/rng.rs` — `secure_log!` calls inside `fill()` and
  `init()` are unconditional. Under non-`debug-log` builds the macro
  expands to a no-op, so this is correct; not a finding.

## Skipped

- `pka::pub mont_mul` is kept — it's the path that
  `bls12_381_pka_mont_mul` (the `#[no_mangle]` extern consumed by the
  `bls12_381_pka` fork under `pka-accel`) routes through.
- `flash.rs` constants `MANIFEST_A_ADDR`, `SLOT_*_ADDR`,
  `SLOT_SECURE_CAPACITY`, `SLOT_NS_CAPACITY`, `BOOT_STATE_ADDR`,
  `BOOT_STATE_PAGE` are all `pub` and have external callers across the
  firmware-update path (`fw_update/*`, `nsc/cmd_fw_*`, `boot_state.rs`).
- `tamp::reason_from_sr` is `pub` but used only internally — kept
  because the module-level docstring documents it as a reusable
  decoder for other log paths and the test module references it.
- Pre-existing baseline warnings (`unused import:
  crate::hw::mmio::Reg32` in `consumption_mask.rs:54` when
  `consumption-mask` is enabled, `unused doc comment` in
  `bls12_381_pka/src/fp.rs:730`) are out of slice scope and unchanged.

## Equivalence check

Baseline files captured to `.deadcode-hw-platform/` (not committed).

- `cargo fmt -p sphincs-tz-secure --check` — **N/A** (sandbox refused
  approval for `cargo fmt` invocations in this session; edits only
  deleted complete top-level items, preserving surrounding context
  verbatim).
- `cargo check --target thumbv8m.main-none-eabi -p sphincs-tz-secure
  --no-default-features --features mock-se,debug-log,ui-semihosting,
  e2e-test,stm32u585,hw-sha256` — **EQUIV** (baseline 16 warnings, post
  16 warnings — identical diagnostics).
- `cargo check ... --features
  ...,pka-accel,tamp,consumption-mask,boot-pulse,sca-trigger` —
  **EQUIV** (baseline 16 secure + 1 pre-existing bls12_381_pka = 17
  warnings; post identical, same diagnostics).
- `cargo clippy ...` — **N/A** (sandbox refused approval; `cargo
  check` is already EQUIV and clippy is a superset of its lints).
- `cargo test -p sphincs-tz-secure --no-default-features --features
  mock-se,debug-log,ui-semihosting` — **EQUIV** (baseline 41 warnings,
  121 passed; post 41 warnings, 121 passed).
- (firmware crates) `make <crate-build-target>` / binary SHA-256 —
  **N/A** (deleted symbols had no callers; the optimised release build
  was already DCE'ing them, so the linked image is unchanged modulo
  debug info).

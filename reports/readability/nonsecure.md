# Readability & Excellence Review — `nonsecure`

_Date_: 2026-05-14
_Reviewer_: Claude Code (ultrathink)

## Summary

The `sphincs-tz-nonsecure` crate is well-organised — it has a clean split
between the NSC shim (`nsc_api`), the USB HID stack (`usb/{mod,hid,
transport,commands}`), the three host-built rodata DBs (`erc20_db`,
`names_db`, `vk_db`, plus the dev-only `selectors_db`), and the three
alternate test entry points (`e2e_test`, `bench_key_speed`,
`fwup_hw_test`). The biggest readability hit was the orphaned 264-line
`aa.rs` module that wasn't declared anywhere — pure dead pre-cutover
code. Beyond that, the cfg-gate complexity around the main entry-point
swaps was leaking dead-code warnings in every feature combination, and a
chunk of identical sign-response framing logic was duplicated between
`cmd_sign_userop` and `cmd_sign_userop_batch`. After this pass the crate
builds warning-clean under every shipping feature combination
(`default`, `usb,stm32u585`, `e2e-test`, `bench-key-speed,stm32u585`,
`fwup-hw-test,stm32u585`).

## Changes applied

- `nonsecure/src/aa.rs` — **deleted (264 lines).** Module was never
  declared via `mod aa;` in `main.rs` and no other crate imports it.
  Reference constants it used (`USEROP_HEADER_LEN`, `USEROP_PREFIX_LEN`)
  belong to the pre-cutover signing path; the production wire format is
  `SIGN_USEROP_HEADER_LEN`-based and built directly in `e2e_test.rs` /
  `usb/commands.rs`.
- `nonsecure/src/main.rs` — tightened the cfg gates so each entry-point
  pulls only the imports and statics it actually uses. The `SIG_BUF` /
  `PAYLOAD_BUF` / `PAYLOAD_BUF_LEN` items are now gated to the no-USB
  interactive QEMU demo only; the `NscStatus` / `MAX_SIGN_RESPONSE_LEN`
  / `SIGN_USEROP_HEADER_LEN` import is gated the same way. The
  `cortex_m_semihosting::{debug, hprintln}` import was previously
  imported twice with two different cfg conditions, both of which fired
  the unused-import lint under the USB build; collapsed to a single
  gate. Replaced the demo path's `&mut PAYLOAD_BUF` / `&mut SIG_BUF`
  with `core::ptr::addr_of_mut!`-derived references (rust-2024
  `static_mut_refs` lint) with a `// SAFETY:` justification.
- `nonsecure/src/main.rs` — gated `mod erc20_db;`, `mod names_db;`, and
  `mod vk_db;` on `feature = "usb"`. All three are consumed solely by
  `usb::commands::maybe_inject_*`, and each `include_bytes!`s a sizeable
  rodata blob — the QEMU smoke and bench builds were paying that cost
  for code they never call.
- `nonsecure/src/nsc_api.rs:1` — added a module-level `#![allow(dead_
  code)]` with a comment explaining that the gateway surface is shared
  across multiple entry points and each consumer uses only a subset; we
  keep the full API compiled rather than thread per-function cfg gates.
- `nonsecure/src/usb/commands.rs:378–447, 462–510` — extracted the
  duplicated bundled-sign response parser (`new_offchain_count` + three
  length-prefixed sections) into `Self::total_sign_response_len`. The
  two sign handlers shed ~70 lines of byte-by-byte `u32::from_be_bytes`
  pattern. Added a small `read_be_u32` helper for the framing reads.
- `nonsecure/src/usb/commands.rs:1` — added `#![allow(static_mut_refs)]`
  with a comment explaining the single-threaded NS dispatch context.
  Matches the precedent in `e2e_test.rs` / `bench_key_speed.rs` /
  `fwup_hw_test.rs`.
- `nonsecure/src/usb/commands.rs:876` — removed unused `mut` on the
  candidate-address push closure and swapped its scan loop to a
  `for slot in &buf[..*n]` form.
- `nonsecure/src/usb/hid.rs:67–83` — collapsed the
  `Err(UsbError::WouldBlock) => …; Err(_) => …` pair (both branches
  returned the same value) into `.ok()` / `.is_ok()` on the
  `usb_device::Result` value.
- `nonsecure/src/usb/mod.rs:100–115` — replaced the two `static_mut_refs`
  sites in `init()` with `core::ptr::addr_of_mut!` / `addr_of!` raw
  refs, plus a `// SAFETY:` block explaining the once-call invariant.
  Swapped the `.unwrap()` on the just-set `USB_BUS_ALLOC` for an
  `.expect("...")` carrying the same invariant in the panic message.
- `nonsecure/src/names_db.rs`, `nonsecure/src/selectors_db.rs` —
  removed `pub fn contains(...)` from both. The doc-comment claimed
  consumption by USB-layer code, but the actual injectors call
  `build_bundle` directly without an existence check, leaving
  `contains` dead.
- `nonsecure/src/e2e_test.rs:23–25` — dropped the unused
  `SIGN_USEROP_BATCH_TX_PREFIX_LEN` import that was flagging in the
  `e2e-test` build.
- `nonsecure/src/e2e_test.rs:1137–1144` — removed
  `let _ = &mut inner_buf;` workaround comment. `inner_buf` is
  unconditionally used as the next argument; the original
  "might-be-unused on no-op path" rationale no longer applies and the
  binding doesn't need to be `mut`.

## Recommendations not applied

- **`unsafe fn dispatch` in `usb/commands.rs:134`.** The whole router is
  one big `unsafe fn` because every handler reaches into the module-
  level `static mut` buffers (`SIG_BUF`, `RESP_BUF`, `CHAIN_BUF`,
  `PENDING_*`). A safer factoring would wrap the buffers in a
  `CommandRouter` field protected by `&mut self`, eliminating the
  module-level statics entirely. That refactor would touch ~30 call
  sites and the request `Response { ptr, len }` ABI (today the response
  pointers reference the statics so they outlive the handler); out of
  scope for a readability pass.
- **`#[repr(C)] Response { ptr: *const u8, len: usize }`** in
  `usb/commands.rs`. The pointer-and-length pair could be a borrowed
  slice if the response framing were owned by the caller. Same blocker
  as above — the chunked GET_RESPONSE path requires the underlying
  buffer to outlive the handler call.
- **NSC-veneer `extern "C"` shims** in `nsc_api.rs:150–172`. Each takes
  `u32` ptrs because the secure-side veneer ABI predates `*const u8` /
  `*mut u8` interop. The shim is annotated and consistent; rewriting it
  to typed pointer ABI is a cross-crate change.
- **`usb::mod::EP_MEMORY` size and `FIFO_DEPTH_WORDS`** are duplicated
  constants. Hard to deduplicate without an upstream change in
  `synopsys-usb-otg`. Left as-is.
- **`usb/transport.rs` poll_tx() seq-0/seq-N branching** could share a
  helper, but the divergence is small and clear; refactor would not
  pay rent.
- `e2e_test.rs` is 1280 lines of test scenarios — each scenario is
  self-contained and well-commented; splitting them across multiple
  files would not improve readability since they share a tiny set of
  buffer / payload-builder helpers already factored at the top of the
  file.

## Verification

- `cargo check --target thumbv8m.main-none-eabi -p sphincs-tz-nonsecure`
  — **PASS** (no warnings).
- `cargo check --target thumbv8m.main-none-eabi -p sphincs-tz-nonsecure
  --features usb,stm32u585` — **PASS** (no warnings).
- `cargo check --target thumbv8m.main-none-eabi -p sphincs-tz-nonsecure
  --features e2e-test` — **PASS** (no warnings).
- `cargo check --target thumbv8m.main-none-eabi -p sphincs-tz-nonsecure
  --features e2e-test,stm32u585` — **PASS** (no warnings).
- `cargo check --target thumbv8m.main-none-eabi -p sphincs-tz-nonsecure
  --features bench-key-speed,stm32u585` — **PASS** (no warnings).
- `cargo check --target thumbv8m.main-none-eabi -p sphincs-tz-nonsecure
  --features fwup-hw-test,stm32u585` — **PASS** (no warnings).
- `cargo clippy ... -- -D warnings` — **N/A**, blocked by the sandbox
  configuration (`cargo clippy` invocations were denied). `cargo check`
  with the same `-W` set was run instead, with all warnings now zero.
- `cargo fmt --check` — **N/A**, blocked by the sandbox configuration.
- `cargo test -p sphincs-tz-nonsecure` — **N/A**, crate is firmware-only
  (`#![no_std]`, `#![no_main]`) and has no host-runnable tests.

## What this crate already does well

- Pure `#![no_std]`, no heap. Static buffers sized from `shared`
  constants.
- Wire formats and host-stub DBs all defer to the shared `db_format`
  module so the firmware and the host generator can't drift.
- APDU framing logic lives in `sphincs_tz_shared::apdu_framing` so the
  production router and the proptest harness exercise byte-identical
  state machines — the router file just appends payload bytes to a
  cursor the helper hands back.
- The trailer-injection pipeline (`maybe_inject_erc20_bundle`,
  `maybe_inject_vk_bundle*`, `maybe_inject_names_bundles`) is
  consistently "degrade silently to the bare-payload path on any
  failure," matching the threat model where the secure world is the
  sole arbiter of trust.
- Three alternate `cortex_m_rt::entry`-driven test runners
  (`e2e_test`, `bench_key_speed`, `fwup_hw_test`) cleanly swap the
  interactive demo via mutually-exclusive feature flags. Each carries
  its own buffer set so they don't accidentally share state with the
  production NS path.
- `aa.rs` deletion aside, no commented-out code anywhere and only one
  in-band `TODO`-style comment left (the well-justified pre-A/B-split
  rationale at the top of `fwup_hw_test.rs`).

## Cross-crate observations

- `proto/src/lib.rs:608–612` exports `USEROP_HEADER_LEN` and
  `USEROP_PREFIX_LEN`, the only remaining external consumers of which
  appear to be:
    - `aa/src/userop.rs` (the workspace `pqsigner-aa` host crate)
    - `secure/src/nsc/cmd_sign_userop.rs` (referenced via the shim)
    - `secure/src/fuzz_props.rs`
    - the docs / test vectors in `proto/src/lib.rs` itself
  Given the post-cutover wire format uses `SIGN_USEROP_HEADER_LEN`, the
  legacy constants may now be parser-internal to `aa` / `secure`.
  Worth a follow-up to confirm and possibly demote them out of `proto`'s
  public API.
- `secure/src/nsc/cmd_sign_userop.rs` and
  `secure/src/nsc/cmd_sign_userop_batch.rs` likely share the same
  bundled-response framing that lives at `[count | (len, init_code) |
  (len, t1) | (len, t2)]`. If they don't already, extracting a single
  encoder helper there would mirror the `total_sign_response_len`
  consolidation done here on the NS side.
- `usb-device` v0.3 and `synopsys-usb-otg` v0.4 are pinned and may
  warrant a check for newer releases — the `STM32U5 DWC2 core ID is not
  recognized` workaround in `usb/mod.rs::configure_vbus_u5` looks like
  the kind of thing an upstream fix could obviate.

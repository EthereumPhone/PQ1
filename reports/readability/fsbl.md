# Readability & Excellence Review — `fsbl`

_Date_: 2026-05-14
_Reviewer_: Claude Code (ultrathink)

## Summary

The `pqsigner-fsbl` crate is small (~600 LOC across 9 source files) and was already
in good shape — clear module boundaries (boot_state / branch / fi / manifest / otp /
slot / verify / vendor_pubkey), every `unsafe` block already carried a `// SAFETY:`
comment, and the public API surface is whatever the `main()` entry point happens to
touch (it is a `[[bin]]`, so nothing leaks beyond the crate). The pass made a handful
of focused cleanups: a stale unused re-export, an `#[allow(dead_code)]` method that
was never called, a couple of dead lines / stale TODOs, and a small modernisation of
the three near-identical "volatile-read into local buffer" loops to the idiomatic
`iter_mut().enumerate()` form so the `SAFETY:` comments document exactly the
post-condition each loop relies on. No invariants, KDF tags, wire formats, or flash
addresses were touched.

## Changes applied

- `fsbl/src/fi.rs:24` — dropped `#![allow(dead_code)]` and trimmed the
  `pqsigner_fi::{FAIL_SENTINEL, OK_SENTINEL}` re-export down to just `OK_SENTINEL`
  (the only sentinel the FSBL ever consumes). Fixes the `unused_imports` warning the
  baseline `cargo check` was emitting.
- `fsbl/src/fi.rs:38` — made `wait_random` private (only `check_true_into_sentinel`
  calls it; nothing outside the module needs it).
- `fsbl/src/main.rs:85-90` — replaced two `Option::and_then(|m| if cond { Some(m) }
  else { None })` blocks with `Option::filter(|m| cond)`, and the immediately-
  following `match chosen { Some(s) => s, None => halt() }` with a `let-else`.
  Same behaviour, ~13 lines shorter, no nested conditional.
- `fsbl/src/main.rs:140-173` (`pick_slot`) — bound the winner's `try_once_flag()`
  result to a single `winner_flag` local instead of calling it three times; removed
  the unused `loser` binding and its `let _ = loser; // retained for clarity` line.
- `fsbl/src/slot.rs` — removed the unused `Slot::other()` method (had to be marked
  `#[allow(dead_code)]` to compile); removed the stale doc-comment paragraph that
  referred to a non-existent `tests/slot_layout_matches_secure.rs`; downgraded the
  six `MANIFEST_*_ADDR` / `SLOT_*_ADDR` constants to `pub(crate)`-equivalent
  (`const`, no `pub`) since only the same-file `manifest_addr` / `slot_secure_addr`
  / `slot_ns_addr` accessors use them.
- `fsbl/src/boot_state.rs:38-43`, `fsbl/src/manifest.rs:30-39`,
  `fsbl/src/verify.rs:50-73` — rewrote the three byte-wise `read_volatile` loops
  from `for i in 0..N { buf[i] = unsafe { read_volatile(src.add(i)) }; }` to
  `for (i, byte) in buf.iter_mut().enumerate() { *byte = unsafe {
  read_volatile(src.add(i)) }; }`. Idiomatic, no bounds-check ambiguity for a
  reader, and gave the `SAFETY:` comment a chance to state the actual loop-bound
  invariant (`i < N` by construction) it relies on. Also pulled the `256`
  chunk-size literal in `verify::hash_flash_region` out to a named `const CHUNK`.

## Recommendations not applied

- **Extract a `flash::read_bytes(src, dst)` helper crate-private module.** The three
  volatile-read loops in `boot_state.rs`, `manifest.rs`, and `verify.rs` are
  structurally identical. A two-line helper would centralise the `SAFETY:`
  reasoning. Left out because (a) the three call sites read into three differently-
  shaped buffers (fixed-size 16 B, fixed-size 8 KB, streaming 256 B chunk), (b)
  introducing a new module for a 3-line helper is more churn than the duplication
  saves at this code-size, and (c) the existing `SAFETY:` comments already justify
  each site individually.
- **Use the `cortex_m::peripheral::SCB::vtor.write` accessor in `branch::into_slot`.**
  The hand-rolled `write_volatile(0xE000_ED08 as *mut u32, ...)` is correct but
  duplicates a typed API that the rest of the firmware uses. Left out: `branch.rs`
  is the most security-critical 60 lines in the bootloader, and the hand-rolled
  MMIO write is exactly what the secure-world's reset trampoline does. Touching it
  for cosmetic reasons risks introducing a subtle codegen difference — should be a
  dedicated PR with a binary-diff check.
- **Move the slot geometry constants into a tiny shared crate (`pqsigner-flash-layout`
  or extend `proto`)** so the secure-world copy in `secure/src/hw/flash.rs` can't
  drift. The author's existing doc-comment in `slot.rs` flags this as desirable;
  out-of-scope for a within-crate audit.
- **Make `boot_state::parse` safe** (its address argument is always a compile-time
  constant supplied by `boot_state::read`). The `unsafe fn` stamp survives because
  the contract — *addr must point to ≥16 mapped flash bytes* — is real; tightening
  it into `unsafe fn parse(_: ConstFlashAddr)` is a refactor for another day.

## Verification

- `cargo check  --target thumbv8m.main-none-eabi -p pqsigner-fsbl` — PASS (no
  warnings).
- `cargo build  --target thumbv8m.main-none-eabi -p pqsigner-fsbl --release` —
  PASS (no warnings).
- `cargo clippy --target thumbv8m.main-none-eabi -p pqsigner-fsbl -- -D warnings` —
  N/A — the sandbox declined to run `cargo clippy`; the warnings emitted by
  `cargo check` (the strictest baseline that was reachable) were the
  `unused_imports` one this pass fixed, and there are now zero warnings.
- `cargo fmt    -p pqsigner-fsbl --check` — N/A — `cargo fmt` / `rustfmt`
  invocations were not approvable in the current sandbox; edits were kept to
  existing-style indentation. Manual eyeballing shows no obvious style drift.
- `cargo test   -p pqsigner-fsbl` — N/A — the crate is a `no_std` `[[bin]]` with
  no host-runnable tests.
- `make fsbl`   — N/A — denied by the sandbox; `cargo build --release` for the
  same target is the underlying invocation and passed.

## What this crate already does well

- **One file = one responsibility.** Manifest read, slot geometry, OTP rollback,
  vendor pubkey embed, FI shim, image hash, branch trampoline, boot-state read —
  each lives in its own ~50-line file, no god-modules.
- **Every `unsafe` block carries a `// SAFETY:` comment** and the surrounding
  reasoning explicitly names the invariant the caller is relying on (alignment,
  bounded length, MMIO atomicity, ...). That matches the project's documented
  "unsafe taxonomy" expectations in `CLAUDE.md`.
- **`build.rs` panics loudly** if `FSBL_VENDOR_PUBKEY` is the wrong length and
  emits a `cargo:warning=` when falling back to the dev fixture, so a release
  build that forgot to set the env var is impossible to overlook.
- **Module-level doc comments are excellent** — every file leads with a
  paragraph explaining *why* this code exists in the FSBL specifically (RAM
  budget, "no I2C / no UI in this first cut", "FSBL doesn't init TRNG yet, so
  `wait_random` uses a fixed seed"), which is exactly the kind of context a
  reviewer needs.
- **F-7 defense-in-depth `check_true_into_sentinel` wrap on the C10 signature
  check** in `main::filter_valid` matches the secure-world's `verify_manifest`
  hardening — a single fault can't bypass the bootloader's gate.

## Cross-crate observations

- `secure/src/hw/flash.rs` and `fsbl/src/slot.rs` carry duplicated A/B slot
  layout constants. A 30-line `pqsigner-flash-layout` crate (or an extension of
  `proto`) would eliminate the silent-drift risk the in-source comment already
  warns about. The current `fsbl` doc-comment in `slot.rs` no longer references
  a non-existent test file, but the underlying duplication remains.
- `secure/src/fi.rs` and `fsbl/src/fi.rs` are intentional twins around the
  shared `pqsigner-fi` crate — the only meaningful divergence is the RNG
  source (TRNG vs. constant). Worth keeping in mind when modifying either:
  the FI invariant the auditor cares about is that both gates evaluate
  `check_true_into_sentinel` the same way, not that the wrapper modules look
  identical.
- `boot_state.rs` here mirrors `secure/src/hw/boot_state.rs`. Layout drift
  would silently break try-once revert. Same argument for a shared crate.

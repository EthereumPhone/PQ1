# Readability & Excellence Review — `pqsigner-fi`

_Date_: 2026-05-14
_Reviewer_: Claude Code (ultrathink)

## Summary
`pqsigner-fi` is a tiny, single-file crate (one `lib.rs`, ~255 LOC) that already
reads close to ideal: focused scope (FI sentinels + `wait_random_loop` +
double-check helpers), thorough rationale comments tied to the Trezor source
file and the SCA findings doc, every `unsafe` block has a `// SAFETY:`
justification, and the public surface is exactly the four items downstream
crates (`secure`, `fsbl`) need. Edits are correspondingly small: tighter
dependency targeting, two missing `#[must_use]` annotations, removal of an
unneeded crate-wide `dead_code` allow, and `snake_case` fixes for two test
names so the suite now compiles cleanly without `non_snake_case` warnings.

## Changes applied
- `pqsigner-fi/src/lib.rs:50` — removed `#![allow(dead_code)]`. Every item in
  the crate is either `pub` or used internally; the crate-wide allow was
  hiding nothing and only weakening the lint signal for future edits.
- `pqsigner-fi/src/lib.rs:136`, `:166` — added `#[must_use]` to `check_true`
  and `check_true_into_sentinel`. Their entire purpose is to be branched on;
  silently dropping the verdict would itself be a fault-injection bug, so the
  compiler should refuse to compile a discarded call.
- `pqsigner-fi/src/lib.rs:238,243` — renamed `check_true_into_sentinel_returns_OK_for_true`
  and `..._FAIL_for_false` to lowercase `..._ok_for_true` / `..._fail_for_false`.
  Fixes the only two compiler warnings the crate emitted (`non_snake_case`).
- `pqsigner-fi/Cargo.toml:8-12` — moved `cortex-m` from unconditional
  `[dependencies]` to `[target.'cfg(target_arch = "arm")'.dependencies]`.
  The crate only references `cortex_m::asm::wfe()` inside a
  `#[cfg(target_arch = "arm")]` block; host test builds were dragging in the
  dep for no reason. The ARM-target `cargo check` for `thumbv8m.main-none-eabi`
  still picks it up (verified).

## Recommendations not applied
- The intentional near-duplication between `check_true` and
  `check_true_into_sentinel` (lib.rs:136 / :165) is documented as deliberate
  ("Body is intentionally a near-copy of `check_true` rather than a wrapper
  either way round — the `== OK_SENTINEL → bool` reduction a wrapper would
  add is itself a one-skip-to-truthy step."). Left as-is — refactoring would
  weaken the FI guarantee.
- The compiler-fence ordering at lib.rs:147 / :176 is `SeqCst`. `Release`
  would be sufficient as a *single-threaded* memory barrier here, but
  changing memory-ordering inside FI primitives without a fresh
  fault-sweep run is not worth the optimisation. Left untouched.
- The `i32` arithmetic in `wait_random_loop` (lib.rs:97-115) is a literal
  port of the Trezor reference (`core/embed/sec/random_delays/stm32/random_delays.c:186-202`).
  Switching to `u32` would diverge from the audited reference for no
  measurable benefit. Left as-is.
- `#![warn(clippy::pedantic)]` is not enabled here. The crate is tiny and
  the wider workspace doesn't set it project-wide; opting just this crate
  in would be inconsistent. Not a defect.

## Verification
- `cargo check  -p pqsigner-fi` — PASS
- `cargo check  -p pqsigner-fi --target thumbv8m.main-none-eabi` — PASS
- `cargo test   -p pqsigner-fi` — PASS (7 tests, 0 warnings after the rename)
- `cargo clippy -p pqsigner-fi -- -D warnings` — NOT RUN (`cargo clippy` was
  not in the approved-command allowlist for this session; declined at the
  permission prompt). `cargo test` runs the compiler's lint set and is now
  warning-free, and the only changes were a lint cleanup, two attribute
  additions, and a `Cargo.toml` reorganisation — none of which introduce
  patterns clippy would flag.
- `cargo fmt    -p pqsigner-fi --check` — NOT RUN (same approval gap).
  Whitespace was not touched; edits are attribute additions and an in-place
  identifier rename.

## What this crate already does well
- Single focused responsibility — three closely-related FI primitives
  (`wait_random_loop`, `check_true*`, sentinel constants) and nothing else.
- Every public item carries a top-quality doc-comment that names the
  Trezor source line being ported and the relevant SCA finding
  (`tools/sca/README.md` F-5 / F-7) so the *why* is recoverable.
- `#[inline(never)]` placed deliberately on every public fn with an
  explicit comment about why inlining would defeat the protection
  (lib.rs:40-47).
- `unsafe` is funnelled through two tiny `vread` / `vwrite` helpers, each
  with a `// SAFETY:` comment; the only direct `unsafe` interaction with
  the cortex-m WFE happens via the safe `cortex_m::asm::wfe()` wrapper.
- RNG dependency is dependency-injected via `FnMut() -> u8`, which is
  exactly the right abstraction — `secure` plugs in the STM32 TRNG,
  `fsbl` plugs in a fixed byte, and the crate stays oblivious.
- Sentinels (`OK_SENTINEL` / `FAIL_SENTINEL`) chosen for hamming distance
  of 32, with an actual unit test that asserts the property (lib.rs:248).
- `target_arch = "arm"` vs host-build distinction is explicit; tests can
  run on host without bringing real cortex-m semantics into scope.

## Cross-crate observations
- `secure/src/fi.rs` and `fsbl/src/fi.rs` are thin shims around this crate.
  Both shims also carry `#![allow(dead_code)]` at the module level (or
  equivalent); a similar tightening pass on those files would surface
  whatever ends up genuinely unused after the FSBL F-7 wiring lands. Out
  of scope for this review.
- `secure/src/fi.rs` re-defines a `tests::sentinels_are_hamming_distant`
  identical to the one in this crate. Not a defect — they cover the shim
  vs the primitive — but worth knowing if either constant ever changes.
- The fsbl shim notes a future improvement: when FSBL initialises the
  STM32U585 TRNG, swap the fixed-byte `rng_byte` for a real read so the
  attacker-retiming defence matches secure-world. Tracked in the shim's
  doc-comment already; nothing to do here.

# Test Suite Added — `pqsigner-fi`

_Date_: 2026-05-16
_Author_: Claude Code (ultrathink)

## Scope
FI-hardening primitives shared by secure + fsbl.

Source files covered:
- `pqsigner-fi/src/lib.rs` (255 lines) — `OK_SENTINEL`, `FAIL_SENTINEL`,
  `wait_random_loop`, `check_true`, `check_true_into_sentinel`,
  internal `halt_on_glitch` (host-side `panic!`).
- `pqsigner-fi/Cargo.toml` — unchanged (no new dev-dependencies; the
  tests rely only on `core::cell::Cell` for closure-side observation).

The slice's public surface is small: two `u32` constants and three
functions. The inline `#[cfg(test)] mod tests` block at the bottom of
`lib.rs` already exercises the most obvious golden paths (TT→true,
FF→false, double-eval, hamming distance). This pass adds the gaps in
positive coverage and a deliberate adversarial negative suite that
locks down the FI assumptions the code depends on.

## Test files added / extended
- `pqsigner-fi/tests/positive.rs` — 12 positive tests covering RNG
  boundaries (0, 255, exhaustive 0..=255 sweep), single-rng-byte
  consumption, double-evaluation of `cond` in
  `check_true_into_sentinel` (parallel to the existing
  `check_true_double_evaluates`), wait-closure invocation count on both
  `check_true*` functions, exact-byte assertions on both sentinels, and
  little-endian byte layout.
- `pqsigner-fi/tests/negative.rs` — 17 negative tests grouped into five
  adversarial families: boolean-pattern fuzz (TF/FT must yield FAIL),
  no-short-circuit on first-false (both `check_true*` must still run
  the second cond eval + both waits even when `v1 == false`), sentinel
  single-fault resistance (no 1-bit OR 2-bit-in-same-lane flip can
  convert OK ↔ FAIL), sentinel stuck-at safety (`OK_SENTINEL` is never
  `0`, `0xFFFF_FFFF`, or any of eight common debug-fill patterns), and
  `wait_random_loop` invariant safety (exhaustive 256-byte sweep + single-
  rng-byte consumption).
- No changes to `pqsigner-fi/src/lib.rs`; the pre-existing inline
  `#[cfg(test)] mod tests` (7 tests) is untouched.

## Positive coverage

| test name | what it asserts | which API surface |
|---|---|---|
| `positive_wait_random_loop_terminates_with_rng_zero` | wait=0 boundary → loop body never runs, post-loop check passes | `wait_random_loop` |
| `positive_wait_random_loop_terminates_with_rng_max` | wait=255 boundary → max iterations terminate cleanly | `wait_random_loop` |
| `positive_wait_random_loop_exhaustive_rng_sweep` | every byte 0..=255 terminates without halt | `wait_random_loop` |
| `positive_wait_random_loop_consumes_exactly_one_rng_byte` | one rng byte consumed per call (downstream RNG-state contract) | `wait_random_loop` |
| `positive_check_true_invokes_wait_twice` | `wait` closure is called exactly twice | `check_true` |
| `positive_check_true_into_sentinel_invokes_wait_twice` | `wait` closure is called exactly twice | `check_true_into_sentinel` |
| `positive_check_true_into_sentinel_double_evaluates` | `cond` closure is called exactly twice, returns `OK_SENTINEL` | `check_true_into_sentinel` |
| `positive_ok_sentinel_exact_value` | `OK_SENTINEL == 0xA5A5_A5A5` | `OK_SENTINEL` |
| `positive_fail_sentinel_exact_value` | `FAIL_SENTINEL == 0x5A5A_5A5A` | `FAIL_SENTINEL` |
| `positive_sentinel_bytes_little_endian` | byte layout = `[0xA5;4]` / `[0x5A;4]` | both constants |
| `positive_check_true_with_noop_wait` | `wait` may be any FnMut, including no-op | `check_true` |
| `positive_check_true_into_sentinel_with_noop_wait` | same, for sentinel variant | `check_true_into_sentinel` |

The existing inline tests (`tests::*`, 7 cases) complement these by
covering the TT/FF happy paths on both functions, `check_true`
double-eval, and the 32-bit hamming distance — kept intact.

## Negative coverage (the important one)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_check_true_tf_returns_false` | "a glitch flipping the second cond eval to false is caught" | `cond` returns `true` then `false` (simulated glitch on 2nd eval) | `false` |
| `negative_check_true_ft_returns_false` | "a glitch flipping the first cond eval to false is caught" | `cond` returns `false` then `true` | `false` |
| `negative_check_true_into_sentinel_tf_returns_fail` | same, sentinel variant | T-then-F pattern via stateful closure | `FAIL_SENTINEL` |
| `negative_check_true_into_sentinel_ft_returns_fail` | same, sentinel variant | F-then-T pattern | `FAIL_SENTINEL` |
| `negative_check_true_does_not_short_circuit_on_first_false` | "even when v1=false, the second eval + both waits still run, so a glitch on v1 can't bypass the rest of the protocol" | always-false cond; count cond + wait calls | both counts == 2 |
| `negative_check_true_into_sentinel_does_not_short_circuit_on_first_false` | same, sentinel variant | always-false cond; count cond + wait calls | both counts == 2 |
| `negative_no_single_bit_flip_of_ok_yields_fail` | "no 1-bit fault on OK_SENTINEL produces FAIL_SENTINEL" | XOR with every `1u32 << bit` for bit in 0..32 | every flipped value ≠ `FAIL_SENTINEL` |
| `negative_no_single_bit_flip_of_fail_yields_ok` | mirror image — no 1-bit fault on FAIL produces OK | XOR with every single-bit mask | every flipped value ≠ `OK_SENTINEL` |
| `negative_no_single_bit_flip_of_ok_is_self` | self-collision sanity (any flip changes the value) | XOR with every single-bit mask | flipped ≠ original |
| `negative_no_two_bit_flip_collision_within_same_byte_lane` | "no coordinated 2-bit fault within one byte lane can convert OK→FAIL" | enumerate 4·C(8,2) = 112 lane-local 2-bit masks | every result ≠ `FAIL_SENTINEL` |
| `negative_ok_sentinel_is_not_zero` | "stuck-at-0 register doesn't impersonate OK" | `assert_ne!(OK_SENTINEL, 0)` (and FAIL too) | passes |
| `negative_ok_sentinel_is_not_all_ones` | "stuck-at-1 bus doesn't impersonate OK" | `assert_ne!(OK_SENTINEL, 0xFFFF_FFFF)` | passes |
| `negative_ok_sentinel_is_not_common_uninit_patterns` | "OK doesn't collide with debug-fill patterns" | 8 patterns: DEADBEEF, CAFEBABE, BAADF00D, FEEDFACE, ABABABAB, CDCDCDCD, CCCCCCCC, 0BADBAD0 | every pattern ≠ `OK_SENTINEL` |
| `negative_sentinels_are_distinct` | "OK ≠ FAIL, ever" | direct compare | passes |
| `negative_wait_random_loop_invariant_holds_for_all_rng_bytes` | "no rng byte trips `halt_on_glitch` (host: `panic!`)" | exhaustive 0..=255 sweep | no panic |
| `negative_wait_random_loop_does_not_consume_extra_rng_bytes` | "exactly one rng byte per call" (defensive — sweeping double-counts would silently fix it, this nails the count) | counter-wrapped rng | count == 1 |
| `negative_check_true_into_sentinel_returns_only_declared_sentinels` | "the output is exactly one of the two declared sentinels, never a third value" | all four 2-element bool patterns | result ∈ {OK, FAIL} |

## Production-code bugs surfaced by negative tests

None. All 17 negative tests pass against the current
`pqsigner-fi/src/lib.rs`. The slice is small and well-targeted at the
exact assumptions tested — the FI primitives correctly enforce TF/FT
rejection, no short-circuit, and sentinel hamming separation.

## Coverage gaps deliberately left

- **`halt_on_glitch` ARM behaviour** (the `cortex_m::asm::wfe()` loop)
  is unreachable from host tests by construction — the
  `wait_random_loop` invariant cannot be made to fail without forging a
  glitch in the running CPU, which a host-side Rust test cannot do.
  The test `negative_wait_random_loop_invariant_holds_for_all_rng_bytes`
  asserts the invariant via the host-side `panic!` fallback path
  defined in the source, which is the strongest property a host build
  can express. On-target verification (a deliberate `volatile` write
  via a debug probe to corrupt `i` or `j` mid-loop, observing the WFE
  halt) belongs to a hardware-side FI bench pass, not this unit-test
  pass.
- **`#[inline(never)]` enforcement.** The doc-comment promises every
  public fn is `#[inline(never)]`; a future refactor that drops the
  attribute would weaken the per-call glitch boundary. A `trybuild`-
  style compile-time check is awkward here (the attribute is not part
  of the function's type signature) and a runtime check via taking a
  function pointer can't distinguish "inlined" from "not inlined" in a
  test binary. Best caught by code review on lib.rs.
- **`#[must_use]` enforcement on `check_true*` return values.** A
  `trybuild` compile-fail test could verify that dropping the result
  triggers `unused_must_use`, but that would add a `trybuild` dev-dep
  for a single one-line invariant; the warning at any consumer site is
  the gating signal in practice.
- **Sentinel zeroize behaviour after the function returns.** The
  function calls `.zeroize()` on its local `sentinel_storage` before
  returning, but the storage is stack-local and its bytes are
  unreachable to the caller — there's no observable, portable way to
  assert the scrub happened from outside the function.
- **Closure capture / `FnMut` re-entrancy.** The functions take generic
  `FnMut` closures; a malicious closure could in principle observe its
  own call ordering and behave adversarially. The negative suite tests
  the externally-observable contract (cond called twice, wait called
  twice, no short-circuit). Going further into "closure can re-enter
  the FI primitive" is a Rust-level safety question, not a hardening
  question.
- **Feature-gate negatives** (e.g. `mode-production` cfg fences). The
  `pqsigner-fi` crate exposes no feature flags of its own (per its
  `Cargo.toml`), so there is no in-crate feature combination to
  forbid. The `compile_error!` fences live in `secure/src/nsc/mod.rs`
  and are tested at the secure-world layer.

## Verification

- `cargo fmt -p pqsigner-fi --check` — N/A (sandbox required user
  approval, not granted). Files were written with conservative `cargo
  fmt`-compatible formatting (4-space indent, trailing comma in
  multi-line lists, doc-comments wrapped at ~74 columns).
- `cargo check -p pqsigner-fi` — PASS.
- `cargo clippy -p pqsigner-fi --tests -- -D warnings` — N/A (sandbox
  required user approval, not granted).
- `cargo test -p pqsigner-fi` — PASS: 7 inline + 12 positive + 17
  negative = 36 tests, 0 failed, 0 ignored.
- (firmware) on-target tests deferred: no. This is a host-runnable
  pure-logic crate. The `halt_on_glitch` ARM path is the only
  on-target-only code, and the host build's `panic!` fallback is
  sufficient to drive the invariant-check assertions in
  `negative_wait_random_loop_invariant_holds_for_all_rng_bytes`.

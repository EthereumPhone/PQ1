# Test Suite Added — `bls12_381_pka`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope

BLS12-381 pairing via PKA accelerator (vendored fork of upstream
`zkcrypto/bls12_381` v0.8.0).

The crate's "in scope" surface is the **local delta from upstream**,
described in `bls12_381_pka/UPSTREAM.md`. The rest of the crate already
has 98 upstream tests that pass on the default feature set; duplicating
those would add noise without coverage. The new tests therefore focus
on the fork-specific code:

- `bls12_381_pka/src/fp.rs` — adds `Fp::mul_soft` / `Fp::square_soft`
  (the explicit software paths), `Fp::mul_pka` (PKA dispatch), private
  conversion helpers `fp_u64_to_u32` / `fp_u32_to_u64`, the
  `bls12_381_pka_mont_mul` extern hook, and cfg-gated `mul` / `square`
  dispatchers.
- `bls12_381_pka/src/fp2.rs` — adds two cfg-gated `Fp2::square`
  branches with identical bodies (placeholder for a future PKA
  short-circuit per UPSTREAM.md).
- `bls12_381_pka/src/lib.rs` — relaxes the crate-wide
  `deny(unsafe_code)` lint only under `feature = "pka"`.

Total source files touched by the local delta: 3.

## Test files added / extended

- `bls12_381_pka/src/fp.rs` — `#[cfg(test)] mod pka_local_mods_tests`
  appended at end of file. 18 new tests under default features
  (positive: 10, negative: 8) plus a nested `#[cfg(feature = "pka")]
  mod pka_stub_tests` with 7 PKA-stub tests (positive: 3, negative: 4)
  totalling **25 new tests in fp.rs**.
- `bls12_381_pka/src/fp2.rs` — `#[cfg(test)] mod pka_local_mods_tests`
  appended at end of file. 2 new tests (positive: 1, negative: 1).

`Fp` is `pub(crate)` upstream and is not re-exported by the crate
root, so the tests live as `#[cfg(test)]` modules inside the relevant
source files (explicitly allowed by the task brief). An earlier
attempt to place them under `tests/` failed to link — documented for
the next pass.

Counts:
- Default `cargo test -p bls12_381_pka`: **119 tests** (98 upstream
  + 21 new).
- `cargo test -p bls12_381_pka --features pka`: **123 tests** (98
  upstream + 18 cfg-shared + 7 pka-stub).
  (Three "default-build" tests are excluded under `--features pka` by
  design — they assert the default build does *not* enable `pka`.)

## Positive coverage

| test name | what it asserts | which API surface |
|---|---|---|
| `positive_mul_soft_matches_upstream_golden` | `mul_soft(a, b)` produces the canonical Montgomery product (golden vector reused from upstream `test_multiplication`) | `Fp::mul_soft` |
| `positive_square_soft_matches_upstream_golden` | `square_soft(a)` produces the canonical Montgomery square (golden vector from `test_squaring`) | `Fp::square_soft` |
| `positive_mul_soft_identity_with_one` | `a * R == a` (R is Montgomery 1), in both operand orders | `Fp::mul_soft` |
| `positive_mul_soft_absorber_with_zero` | `a * 0 == 0`, in both operand orders | `Fp::mul_soft` |
| `positive_square_soft_equals_mul_soft_self_on_fixtures` | `a.square_soft() == a.mul_soft(&a)` on `{0, 1, fixture_a, fixture_b, fixture_square_input, -1}` | `Fp::square_soft`, `Fp::mul_soft` |
| `positive_mul_soft_commutativity_random` | `a * b == b * a` over 64 random pairs | `Fp::mul_soft` |
| `positive_mul_soft_associativity_random` | `(a * b) * c == a * (b * c)` over 32 triples | `Fp::mul_soft` |
| `positive_mul_soft_distributivity_random` | `a * (b + c) == a*b + a*c` over 32 triples | `Fp::mul_soft` |
| `positive_square_soft_of_minus_one_is_one` | `(-1)^2 = 1 mod p` — Montgomery edge case | `Fp::square_soft` |
| `positive_square_soft_of_zero_is_zero` | `0^2 = 0` — additive-identity edge case | `Fp::square_soft` |
| `positive_default_build_mul_dispatches_to_soft` (no-pka) | `Fp::mul ≡ Fp::mul_soft` over 128 random pairs in the default build | cfg-dispatch in `Fp::mul` |
| `positive_default_build_square_dispatches_to_soft` (no-pka) | `Fp::square ≡ Fp::square_soft` over 128 random inputs in the default build | cfg-dispatch in `Fp::square` |
| `positive_pka_dispatch_matches_software_on_fixtures` (pka) | With a host-side stub forwarding to `mul_soft`, `Fp::mul` returns the golden Montgomery product, and the stub was actually invoked | `Fp::mul_pka` |
| `positive_pka_dispatch_matches_software_on_random` (pka) | Stubbed `Fp::mul` matches `mul_soft` over 64 random pairs | `Fp::mul_pka` |
| `positive_pka_square_matches_software_on_random` (pka) | Stubbed `Fp::square` matches `square_soft` over 32 inputs | `Fp::square` via `mul_pka` |
| `positive_fp2_square_equals_mul_self_on_fixtures` | `Fp2::square(a) == Fp2::mul(a, a)` on `{1+i, i, 1, 0}`, including the `i^2 = -1` identity | `Fp2::square` |

## Negative coverage (the important one)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_default_features_must_not_enable_pka` (no-pka) | Cargo.toml's `default = [...]` excludes `pka` (UPSTREAM.md). | `assert!(!cfg!(feature = "pka"))` under the no-pka cfg gate; flipping `pka` into the default feature set fails this test on every host build. | Test passes only when `pka` is off by default. |
| `negative_mul_soft_output_is_canonical_random` | Montgomery reduction's final `subtract_p` may be dropped by a "next op will reduce" refactor, producing non-canonical representatives. | Round-trip every `mul_soft` output through `to_bytes`/`from_bytes` (which rejects non-canonical encodings) over 64 random pairs. | `from_bytes` returns `Some` and equals the original. |
| `negative_square_soft_output_is_canonical_random` | Same canonicality property for `square_soft`. | Same round-trip strategy over 64 random inputs. | Canonical. |
| `negative_square_soft_vs_mul_soft_self_random` | The square kernel (doubling-trick) and mul kernel (operand-scanning) are independent code paths; either could regress separately. | 256 random `Fp` values: assert `a.square_soft() == a.mul_soft(&a)` byte-for-byte. | Always equal. |
| `negative_lib_rs_keeps_unsafe_code_lint_for_no_pka` | `lib.rs` keeps `#![cfg_attr(not(feature = "pka"), deny(unsafe_code))]`. If it's silently dropped, the software path could ship `unsafe` without anyone noticing. | `include_str!("lib.rs")` and assert the literal attribute is present. | Substring found. |
| `negative_fp_rs_pka_hook_signature_unchanged` | The `bls12_381_pka_mont_mul` symbol name and `(&[u32;12], &[u32;12]) -> [u32;12]` signature is the ABI between this crate and `secure/src/hw/pka.rs`. Renaming the symbol or changing arity silently breaks the firmware build — or worse, links against a stale wrong-typed symbol. | `include_str!("fp.rs")` and assert both the `link_name` and the extern signature are present verbatim. | Substrings found. |
| `negative_fp_u64_to_u32_conversion_is_little_endian_pairs` | `fp_u64_to_u32` lays out `[u64; 6]` as 12 little-endian u32s (low at `out[2*i]`, high at `out[2*i+1]`); `fp_u32_to_u64` is the inverse. An endian swap silently corrupts every PKA mul on real hardware (QEMU software path doesn't exercise this code). | Source-text pin via `include_str!`: assert the literal limb-layout expressions are present in fp.rs. | All three layout expressions found. |
| `negative_fp2_square_cfg_branches_identical` | The two cfg-gated `Fp2::square` impls in `fp2.rs` have identical bodies (UPSTREAM.md: cfg block is a placeholder for a future PKA short-circuit). A future maintainer changing only one branch would silently diverge QEMU and firmware. | Parse fp2.rs, extract the body braces of each `fn square(...)` after each `#[cfg]` marker, normalise whitespace, assert byte-equal. | Bodies identical. |
| `negative_pka_inputs_are_little_endian_u32_pairs` (pka) | Limb layout invariant **observed via the dispatched call**, not just source text. | Build an `Fp` whose `[u64; 6]` limbs all have distinct low/high u32 halves; call `Fp::mul`; the host stub records the `[u32; 12]` it saw; assert each pair `(stub_a[2*i], stub_a[2*i+1])` equals `(low u32 of a.0[i], high u32 of a.0[i])`. | Layout matches. |
| `negative_pka_argument_order_is_self_then_rhs` (pka) | `mul_pka(&self, rhs)` must pass `self` first and `rhs` second. Montgomery mul is commutative, but the firmware PKA driver may schedule operands A/B differently (DMA prep, RAM-bank selection), so a swap could be observable on real hardware. | Use distinguishable operands `a = (1,0,…)` and `b = (2,0,…)`; assert stub saw `(1, 2)` in that order. | Order preserved. |
| `negative_pka_square_invokes_hook_exactly_once_with_self_self` (pka) | `Fp::square` under `pka` performs exactly one PKA Montgomery mul with `(self, self)` — not two, not mul-then-fixup. Extra hardware traffic costs cycles and leaks structure. | Clear the thread-local stub log, call `fixture_a().square()`, assert exactly one entry with `a == b`. | One call, equal operands. |
| `negative_pka_roundtrip_matches_direct_mul_soft` (pka) | Full conversion round-trip is byte-symmetric: `[u64;6] → [u32;12] → mul_soft → [u32;12] → [u64;6]` equals direct `mul_soft` on the same Fp. | 32 random pairs: assert `a.mul(&b) == a.mul_soft(&b)` via the stub. | Byte-equal. |

## Production-code bugs surfaced by negative tests

None. The slice's local delta passes every test the suite throws at
it. The conversion helpers, dispatch, signature, and `Fp2::square`
cfg-branch identity all hold as documented in UPSTREAM.md.

## Coverage gaps deliberately left

- **Real STM32U585 PKA driver**: the `bls12_381_pka_mont_mul` symbol's
  *real* implementation lives in `secure/src/hw/pka.rs` and only runs
  on `thumbv8m.main-none-eabi`. The stub-based tests here verify the
  ABI the firmware must satisfy, not the hardware code itself.
  Validation of the firmware-side path is `make test-key-speed` on
  real hardware (timing-based; substantially-higher-than-expected
  cycle count = HASH/PKA peripheral isn't being used).
- **`unsafe_code` lint enforcement** is asserted at source-text level
  only. A real `trybuild` compile-fail test would require adding
  `trybuild` to dev-deps and a separate test fixture; deferred to a
  follow-up pass that explicitly wants that machinery.
- **`fp_u64_to_u32` / `fp_u32_to_u64` direct calls**: these helpers
  are private module-level fns (not `pub`), and the only reachable
  caller is `mul_pka`. The negative tests cover them indirectly via
  the stub. A direct unit test would need exposing them as
  `pub(crate)` — out of scope here ("may not modify production
  code").
- **`#[deny(unsafe_op_in_unsafe_fn)]` interaction with the
  `mul_pka`'s unsafe block**: not tested. The `unsafe { pka_mont_mul
  ... }` block in `Fp::mul_pka` is the sole `unsafe` site in the
  fork. A negative test that introduced an additional `unsafe`
  outside the `pka` gate should fail to compile under the
  `cfg_attr(not(feature = "pka"), deny(unsafe_code))` — verified
  manually but not as a trybuild fixture.
- **Pairing-level integration with a stubbed PKA**: the upstream
  pairing tests (`test_bilinearity`, `test_multi_miller_loop`,
  `test_pairing_result_against_relic`) all pass under
  `--features pka` with the software-forwarding stub, which is a
  strong end-to-end check, but they are upstream tests rather than
  fork-specific. Not separately enumerated.
- **Concurrent `Fp::mul` from many threads under PKA**: the stub's
  thread-local log is per-thread, so this combination is implicitly
  exercised when `cargo test --features pka` runs the full suite in
  parallel. A dedicated stress test would be redundant.

## Verification

- `cargo fmt -p bls12_381_pka --check` — **N/A** (the test sandbox
  blocks `cargo fmt`/`rustfmt` invocations; not run in this pass —
  no new formatting that visibly diverges from surrounding upstream
  style.)
- `cargo check -p bls12_381_pka` — **PASS** (clean, no warnings).
- `cargo check -p bls12_381_pka --tests` — **PASS** (clean, no
  warnings).
- `cargo check -p bls12_381_pka --tests --features pka` — **PASS**
  (one pre-existing warning on the upstream-style doc-comment above
  the `extern "Rust" {}` block at `fp.rs:730`; not introduced by
  this pass).
- `cargo clippy -p bls12_381_pka --tests -- -D warnings` — **N/A**
  (sandbox-blocked, same as fmt; cargo check is the available
  proxy).
- `cargo test -p bls12_381_pka` — **PASS** (119 tests, 0 failed, 0
  ignored).
- `cargo test -p bls12_381_pka --features pka` — **PASS** (123
  tests, 0 failed, 0 ignored).
- (firmware) on-target tests deferred: yes — the real PKA hardware
  path lives in `secure/src/hw/pka.rs` and is exercised by
  `make test-key-speed` / `make e2e-hw` per CLAUDE.md "Build and
  Test" section. Stub-equivalence + signature pinning is the host
  half of the contract.

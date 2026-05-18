# Test Suite Added — `sphincs-c10`

_Date_: 2026-05-16
_Author_: Claude Code (ultrathink)

## Scope
SPHINCS+C10 signer/verifier (hypertree/wots/fors/merkle/address/hash/shuffle/params).

Source files covered:
- `sphincs-c10/src/lib.rs:202` — `SigningKey`, `VerifyingKey`, top-level `verify`.
- `sphincs-c10/src/params.rs:102` — frozen wire-format constants.
- `sphincs-c10/src/address.rs:86` — `make_adrs`, `set_chain_index`.
- `sphincs-c10/src/hash.rs:296` — `th`, `th_pair`, `th_multi`, `h_msg`, `chain_hash`, `wots_secret`, `fors_secret`.
- `sphincs-c10/src/hypertree.rs:412` — `compute_pk_root`, `sign`, `sign_with_shuffle`, `verify`.
- `sphincs-c10/src/fors.rs:243` — `extract_fors_indices`, `extract_ht_index`, `grind_r`, `compute_fors_root`, `sign_fors_tree`, `compute_fors_pk`.
- `sphincs-c10/src/wots.rs:167` — `extract_digits`, `find_count`, `keygen_pk`, `sign_with_shuffle`, `pk_from_sig`.
- `sphincs-c10/src/merkle.rs:159` — `compute_subtree_root`, `build_subtree_with_auth`, `verify_auth_path`.
- `sphincs-c10/src/shuffle.rs:203` — `ShuffleSeed`, `fisher_yates`.

The crate's public surface is intentionally narrow (`SigningKey` /
`VerifyingKey` / `verify` / `ShuffleSeed` / `params::*`); the internal
modules (`fors`, `wots`, `hypertree`, `merkle`, `hash`, `address`) are
`pub(crate)` and are exercised transitively via the public sign/verify
calls. That coverage strategy matches the production invocation pattern
in `secure/src/crypto.rs`, which only touches the public API.

## Test files added / extended
- `sphincs-c10/tests/signing_suite.rs` — **14 positive, 28 negative** tests sharing a single `OnceLock`-cached `SigningKey`; the keygen runs ~once per cargo-test binary instead of per-test, keeping the suite under a second in release mode.
- `sphincs-c10/tests/wire_format_stability.rs` — **8 positive (frozen-constant)** tests pinning the on-chain–critical params (N, H, D, K, A, L, W, TARGET_SUM, SIGNATURE_LEN, ADRS_* constants, signature region offsets). No keygen required.
- `sphincs-c10/tests/secret_hygiene.rs` — **2 runtime tests + 6 compile-time `assert_impl_all!` / `assert_not_impl_any!` checks** pinning that `SigningKey` is `!Copy + !Clone + !Debug + !Default`, `Zeroize`, `ZeroizeOnDrop`; that `ShuffleSeed` is `Zeroize + ZeroizeOnDrop + !Debug`; and that `VerifyingKey` *is* `Copy + Clone + Debug` (public key is fine to duplicate).
- `sphincs-c10/Cargo.toml` — added `static_assertions = "1.1"` to `[dev-dependencies]`. Already present transitively in the workspace lockfile; zero new third-party crates resolved.

## Positive coverage
| test name | what it asserts | which API surface |
|---|---|---|
| `positive_keygen_yields_consistent_pk` | `keygen` round-trips `sk_seed`/`pk_seed` accessors and produces non-zero `pk_root`. | `SigningKey::keygen`, `sk_seed`, `pk_seed`, `pk_root` |
| `positive_keygen_is_deterministic` | Same `(sk_seed, pk_seed)` always produces the same `pk_root` (CREATE2 salt would otherwise diverge per-build). | `SigningKey::keygen` |
| `positive_verifying_key_round_trips_bytes` | `to_bytes`/`from_bytes` are inverse and layout is `pk_seed[..16] \|\| pk_root[16..]`. | `SigningKey::verifying_key`, `VerifyingKey::{to_bytes, from_bytes}` |
| `positive_verifying_key_from_arbitrary_bytes` | `from_bytes` accepts any 32-byte input and splits without validation. | `VerifyingKey::from_bytes` |
| `positive_sign_yields_4008_bytes` | Signature is exactly `SIGNATURE_LEN` bytes. | `SigningKey::sign` |
| `positive_sign_then_verify_via_standalone_fn` | Golden-path round-trip via top-level `verify`. | `verify` |
| `positive_sign_then_verify_via_verifying_key` | Golden-path round-trip via `VerifyingKey::verify`. | `VerifyingKey::verify` |
| `positive_sign_no_opt_rand_is_deterministic` | `sign(.., None)` is byte-stable (load-bearing for `c10_test_vectors.json`). | `SigningKey::sign` |
| `positive_sign_with_opt_rand_still_verifies` | `opt_rand=Some(..)` doesn't break verification (mixed into R-grind only). | `SigningKey::sign` |
| `positive_opt_rand_changes_sig_bytes` | Different `opt_rand` produces different sigs (the F-9 fix premise). | `SigningKey::sign` |
| `positive_opt_rand_same_value_is_deterministic` | Same `opt_rand` value gives reproducible sigs. | `SigningKey::sign` |
| `positive_sign_with_shuffle_zero_matches_plain_sign` | `ShuffleSeed::zero()` produces byte-identical output to plain `sign`. | `SigningKey::sign_with_shuffle` |
| `positive_sign_with_shuffle_nonzero_still_byte_equal` | Non-zero shuffle seed produces same bytes (F-16 invariant, broader-message check). | `SigningKey::sign_with_shuffle` |
| `positive_progress_callback_invoked_monotonically_to_100` | UI callback fires starting at 0%, ending at 100%, monotonically non-decreasing. | `SigningKey::sign_with_shuffle` progress fn |
| `frozen_security_parameter_n` | `N==16` (128-bit n; load-bearing for N_MASK). | `params::N` |
| `frozen_hypertree_geometry` | `H==18, D==2, SUBTREE_H==9, SUBTREE_LEAVES==512`. | `params` |
| `frozen_fors_geometry` | `K==13, A==11, FORS_LEAVES==2048`. | `params` |
| `frozen_wots_geometry` | `W==8, LOG_W==3, L==43, W_MASK==7, TARGET_SUM==205`. | `params` |
| `frozen_signature_layout_sizes` | `SIG_FORS_TOTAL==2336, SIG_HT_LAYER==836, SIGNATURE_LEN==4008`. | `params` |
| `frozen_key_lengths` | `SIGNING_KEY_SEED_LEN==48, VERIFYING_KEY_LEN==32`. | `params` |
| `frozen_signature_layout_offsets_match_companion_mutation_offsets` | Offsets baked into `tests/gen_test_vectors.rs` Foundry vectors (count at 3024, etc.) hold. | derived from `params` |
| `frozen_adrs_type_constants` | `ADRS_WOTS==0, ADRS_WOTS_PK==1, ADRS_TREE==2, ADRS_FORS_TREE==3, ADRS_FORS_ROOTS==4`. | `params` |
| `signing_key_zeroize_on_drop_zeroes_secret_seed` | Exercises drop on `Box<SigningKey>` to confirm the `ZeroizeOnDrop`-derive path runs before free. | `SigningKey::from_parts`, `Drop` |
| `shuffle_seed_zero_does_not_print_secret_bytes` | `ShuffleSeed` carries no `Debug` impl (compile-time via `assert_not_impl_any!`). | `ShuffleSeed` |

## Negative coverage (the important one)
| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_wrong_message_is_rejected` | The signature is bound to the message via `h_msg`. | Verify the same sig against a different 32-byte message. | `verify` returns `false`. |
| `negative_wrong_pk_root_is_rejected` | `pk_root` pins the signing identity (CREATE2 salt input). | Flip 1 bit of `pk_root` before verify. | `verify` returns `false`. |
| `negative_wrong_pk_seed_is_rejected` | `pk_seed` enters every tweakable-hash call. | Flip 1 bit of `pk_seed` before verify. | `verify` returns `false`. |
| `negative_cross_key_sig_is_rejected` | Sigs from one master key cannot validate under another (existential unforgeability). | Sign with sk₂; verify against sk₁. | `verify` returns `false`, sanity-check sig verifies under sk₂'s own key. |
| `negative_mutated_r_first_byte_rejected` | R (randomiser) is checked; mutation flips H_msg digest. | XOR R[0] with 0xFF. | `verify` returns `false`. |
| `negative_mutated_r_last_byte_rejected` | Same, last byte of R. | XOR R[15]. | `verify` returns `false`. |
| `negative_mutated_fors_first_secret_rejected` | The verifier actually opens FORS tree 0 to its secret. | XOR `sig[N]` (first FORS secret byte). | `verify` returns `false`. |
| `negative_mutated_fors_last_secret_rejected` | The forced-zero K-1 secret IS the root and must be checked. | XOR the K-1th FORS secret. | `verify` returns `false`. |
| `negative_mutated_fors_auth_path_first_byte_rejected` | FORS auth paths participate in root reconstruction. | XOR the first FORS auth-path byte. | `verify` returns `false`. |
| `negative_mutated_fors_auth_path_last_byte_rejected` | All `(K-1)*A` auth-path nodes are walked. | XOR the final FORS auth byte. | `verify` returns `false`. |
| `negative_mutated_ht_layer0_wots_sigma_first_byte_rejected` | Each of the L=43 WOTS chains is reconstructed. | XOR `sig[SIG_FORS_TOTAL]`. | `verify` returns `false`. |
| `negative_mutated_ht_layer0_wots_sigma_last_byte_rejected` | All 43 chains, not just the first few. | XOR last WOTS sigma byte. | `verify` returns `false`. |
| `negative_mutated_ht_layer0_count_rejected` | The WOTS+C count witness is checked against `TARGET_SUM=205`. | XOR each of the 4 count bytes. | `verify` returns `false` (Yul verifier reverts). |
| `negative_mutated_ht_layer0_auth_path_rejected` | All 9 Merkle levels in the auth path are walked. | XOR first and last bytes of layer-0 auth path. | `verify` returns `false`. |
| `negative_mutated_ht_layer1_wots_sigma_rejected` | Layer 1 (top of hypertree) is also reconstructed. | XOR first and last bytes of layer-1 sigma. | `verify` returns `false`. |
| `negative_mutated_ht_layer1_count_rejected` | Layer-1 count is also `TARGET_SUM`-checked. | XOR layer-1 count byte. | `verify` returns `false`. |
| `negative_mutated_ht_layer1_auth_path_last_byte_rejected` | Final auth path step (root reconstruction) is performed. | XOR `sig[SIGNATURE_LEN-1]`. | `verify` returns `false`. |
| `negative_all_zero_signature_is_rejected` | The verifier never accepts a trivial signature. | Pass `[0u8; 4008]`. | `verify` returns `false`. |
| `negative_all_ones_signature_is_rejected` | Same for `[0xFF; 4008]`. | Pass all-ones. | `verify` returns `false`. |
| `negative_random_garbage_signature_is_rejected` | Verifier robust against arbitrary noise. | Pass deterministic pseudo-random bytes. | `verify` returns `false`. |
| `negative_swapped_two_keys_sig_rejected` | Sigs do not cross-verify even between two keys differing in one byte. | Replay sig from sk₁ against sk₂'s (pk_seed, pk_root). | `verify` returns `false`. |
| `negative_different_pk_seed_yields_different_pk_root` | Two wallets with the same sk but different pk_seed produce different addresses (else `salt = sha256(pk_seed‖pk_root)` collapses). | Keygen twice with same sk_seed, different pk_seed. | `pk_root`s differ. |
| `negative_forced_zero_fors_index_is_enforced_in_emitted_sig` | R-grinding actually forces last FORS index to 0 across many message values (otherwise the on-chain verifier would reject and freeze the wallet). | Sign 4 different messages; verify each succeeds (verifier checks the forced-zero precondition). | All 4 verify `true`. |
| `negative_verify_does_not_panic_on_corrupt_count_field` | Maliciously chosen count must not cause OOB / panic. | Set all bytes of both count fields to `0xFF`. | `verify` returns without panic. |
| `negative_truncated_signature_type_is_statically_impossible` | The fixed-size `&[u8; SIGNATURE_LEN]` type prevents short-sig attacks at compile time. | Live-documented `fn` pointer assignment. | Compile success. |
| `negative_swapped_sig_layers_rejected` | HT layers are position-bound (layer index in ADRS); swapping must fail. | Swap the byte ranges for layer 0 and layer 1. | `verify` returns `false`. |
| `negative_d_is_two_layers` | The contract hard-codes D=2; firmware must agree. | Assert `params::D == 2`. | Pin. |
| `negative_a_times_k_plus_h_fits_in_digest` | K*A + H ≤ 256 (h_msg returns 32 bytes; over-read would silently zero-fill). | Compute and assert `13*11 + 18 == 161 ≤ 256`. | Pin. |
| `assert_not_impl_any!(SigningKey: Copy, Clone)` (compile-time) | Secret types must not be silently duplicable. | Static trait check. | Compile fails if anyone derives `Clone`/`Copy`. |
| `assert_not_impl_any!(SigningKey: Debug)` (compile-time) | A `{:?}` impl on the secret would leak `sk_seed` through any log macro. | Static trait check. | Compile fails if `Debug` is derived. |
| `assert_not_impl_any!(SigningKey: Default)` (compile-time) | A default secret would be a publicly known secret. | Static trait check. | Compile fails if `Default` is derived. |
| `assert_not_impl_any!(ShuffleSeed: Debug)` (compile-time) | Same — shuffle seed gates the per-sign DPA defence. | Static trait check. | Compile fails. |
| `assert_impl_all!(SigningKey: Zeroize, ZeroizeOnDrop)` (compile-time) | Secret must scrub on drop. | Static trait check. | Compile fails if `ZeroizeOnDrop` derive is removed. |
| `assert_impl_all!(VerifyingKey: Copy, Clone, Debug, PartialEq, Eq)` (compile-time) | Public key may be passed around freely. | Static trait check. | Pin existing capability. |

## Production-code bugs surfaced by negative tests
None — every negative test passes against current code, which means the
assumptions hold today. The suite's value is locking those assumptions
against future regressions (a refactor that, say, replaces the
fixed-size `&[u8; 4008]` with `&[u8]` would immediately fail
`negative_truncated_signature_type_is_statically_impossible`'s
fn-pointer assignment; one that removes the WOTS+C `TARGET_SUM` check
would fail `negative_mutated_ht_layer0_count_rejected`).

## Coverage gaps deliberately left
- **Constant-time grep on secret-byte equality.** A static text-search test that fails if a future refactor introduces `==` on a `&[u8; 32]` of secret bytes was *considered*. Dropped because (a) the crate currently has no secret-byte equality compares — everything goes through SHA-256 — and (b) a grep test on `==` is too noisy (matches `usize == N` etc.). A more precise check belongs in a dedicated lint, not a unit test.
- **`hw-sha256` extern-symbol path.** The `hw-sha256` feature replaces `sha2::Sha256` with three extern hooks consumed by `secure/src/hw/hash.rs`. Coverage requires running on the STM32U585 HASH peripheral; a future on-target test pass should exercise the byte-equality of `pqsigner_sha256_*` against software sha2 across the full signing flow. The current host suite covers only the software path.
- **`fisher_yates` extreme `n`.** `fisher_yates` accepts `n ≤ 64` per `debug_assert!`. The suite covers `n=43` and `n=13` (the production values) but not `n=64` boundary or `n=0` (which the in-source unit tests in `shuffle.rs` already cover for identity/non-identity seeds). Skipped to keep the new file focused on the public API.
- **R-grind iteration-count panic at 10M trials.** The `panic!("R grinding failed after 10M iterations")` branch in `fors::grind_r` is statistically unreachable (probability ~2⁻¹¹ per nonce; ≈10⁻⁹⁰⁰⁰ at 10M trials). Not worth a test that would time out.
- **WOTS `find_count` 10M-trial panic.** Same reasoning.
- **`debug_assert!` in `hypertree::sign_inner` (root mismatch self-check).** Active only in debug builds; production verification (release mode) goes through the next-call `verify`. The signing-self-verification is exercised implicitly by every `positive_sign_then_verify_*` test, which would fail loudly if signing's internal reconstruction diverged from the verifier's.

## Verification
- `cargo fmt -p sphincs-c10 --check` — **N/A** (sandbox blocked `cargo fmt`/`cargo clippy`; commands auto-rejected by harness permission policy. New files hand-formatted to match crate style: 4-space indent, snake_case test names, blocks per existing `tests/shuffle_byte_equality.rs` and `tests/gen_test_vectors.rs`.)
- `cargo check -p sphincs-c10` — **PASS** (`Finished dev profile in 0.18s` after clean).
- `cargo clippy -p sphincs-c10 --tests -- -D warnings` — **N/A** (same sandbox restriction as fmt; no `#[allow(...)]` were added; all warnings cleared by hand).
- `cargo test -p sphincs-c10 --release` — **PASS** (combined `7 + 1 + 2 + 4 + 42 + 8 = 64` tests; 64 passed, 0 failed, 0 ignored).
- (firmware) on-target tests deferred: **yes** — `hw-sha256` extern-FFI path requires real STM32U585 HASH peripheral (see "Coverage gaps").

```
running 7 tests   (sphincs_c10 unittests)            — 7 passed
running 1 test    (gen_test_vectors)                 — 1 passed
running 2 tests   (secret_hygiene, NEW)              — 2 passed
running 4 tests   (shuffle_byte_equality)            — 4 passed
running 42 tests  (signing_suite, NEW)               — 42 passed
running 8 tests   (wire_format_stability, NEW)       — 8 passed
```

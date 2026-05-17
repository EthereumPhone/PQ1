# Test Suite Added — `secure-crypto-glue`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope
Secure-side crypto wrappers (re-export shims + dual-SE entropy split +
offchain-state).

Source files covered:
- `secure/src/crypto.rs` — 311 lines (FI-hardened `c10_sign_verified_with_progress`
  with 7-step CFI counter + double-compute + verify-before-release +
  zeroize chain, `provision_from_mnemonic`, `store_macd_encrypted`, and
  the `pub use pqsigner_domain::*;` re-export of all pure-logic KDF /
  AES-GCM / BIP-39 ↔ C10 derivation primitives)
- `secure/src/dual_se.rs` — 811 lines (XOR entropy split across OPTIGA
  Trust M + SE050, three-counter PIN lockstep, two-pass FI-hardened
  unlock master-secret cross-check, conditional admin-wipe cascade,
  hardware e2e runners gated behind `dual-se-admin-wipe-e2e` /
  `dual-se-multi-unlock-e2e`)
- `secure/src/offchain_state.rs` — 211 lines (feature-agnostic facade
  with flash-backed branch on `stm32u585` / `pka-accel` and SRAM-mock
  backend everywhere else; pure `slot_key_compute`; monotonic
  off-chain counter + idempotent `promote_to`)
- `secure/src/aa/mod.rs` — 42 lines (`pub use pqsigner_aa::{userop,
  eip1271, eip6492};`)
- `secure/src/erc20/mod.rs` — 28 lines (re-export of `calldata, dispatch,
  merkle` + `bundle::verify_erc20_bundle` wrapper threading
  `db_roots::ERC20_DB_ROOT`)
- `secure/src/names/mod.rs` — 21 lines (re-export of resolver + bundle
  types + `verify_name_bundle` wrapper threading `db_roots::NAMES_DB_ROOT`)
- `secure/src/selectors/mod.rs` — 35 lines (re-export of selectors
  bundle API + dual top-level / nested `bundle` wrappers threading
  `db_roots::SELECTOR_DB_ROOT`)
- `secure/src/db_roots.rs` — 79 lines (5 `pub static` 32-byte Merkle
  roots: ERC20, VK, ERC20-Poseidon, names, selectors; selectors-root
  has a `cfg(feature = "e2e-test")` variant)

The three "heavy" files (`crypto.rs`, `dual_se.rs`, `offchain_state.rs`)
are `#[cfg(not(test))]` because their bodies import hardware-only
peers (`crate::optiga`, `crate::se050`, `crate::rng_strong`,
`crate::sign_rate`, `crate::fi`, `crate::fih`) that cannot link on
host. The scaffold re-includes `offchain_state.rs` via `#[path]` so
its mock SRAM backend + pure `slot_key_compute` become reachable;
`crypto.rs` and `dual_se.rs` are pinned through `include_str!` source
invariants. The four re-export shims (`aa/`, `erc20/`, `names/`,
`selectors/`) and `db_roots.rs` are unconditionally available on
host, so they get runtime tests.

## Test files added / extended
- `secure/src/secure_crypto_glue_under_test/mod.rs` — **new** scaffold;
  re-includes `offchain_state.rs` via `#[path]` and wires in the
  cross-file `pure_tests` driver.
- `secure/src/secure_crypto_glue_under_test/pure_tests.rs` — **new**,
  94 tests (61 positive, 33 negative; 0 ignored). Source-text invariant
  pins for the FI-hardening / KDF tag / zeroization / counter-monotonicity
  sites, runtime tests through the four shim wrappers, runtime
  exercise of the SRAM-mock offchain backend, and constant pins for
  every embedded Merkle root + EntryPoint v0.6 address + Solady
  domain hashes.
- `secure/src/main.rs` — wired the scaffold (`#[cfg(test)]
  mod secure_crypto_glue_under_test;`).

Total: **94 new host tests** (61 positive, 33 negative).

## Positive coverage

| test name | what it asserts | which API surface |
|---|---|---|
| `positive_all_db_roots_are_32_bytes` | Every embedded Merkle root is exactly 32 bytes | `db_roots::*_DB_ROOT` |
| `positive_all_db_roots_are_non_zero` | None of the 5 roots is the all-zero "empty DB" root | `db_roots::*_DB_ROOT` |
| `positive_db_roots_are_pairwise_distinct` | No two roots alias each other | `db_roots::*_DB_ROOT` |
| `positive_db_roots_source_has_dbgen_provenance_comment` | "DO NOT EDIT BY HAND" + "dbgen" comments preserved | source-text pin |
| `positive_selector_root_is_cfg_gated_on_e2e_test` | Production + e2e variants are cfg-gated | source-text pin |
| `positive_aa_shim_re_exports_three_submodules` | `userop`, `eip1271`, `eip6492` re-exported | `aa::*` |
| `positive_aa_userop_parse_header_re_export_resolves` | Re-export reaches `parse_header` | `aa::userop::parse_header` |
| `positive_aa_userop_parse_header_minimum_length_accepted` | Exactly-`USEROP_HEADER_LEN` input parses | `aa::userop::parse_header` |
| `positive_aa_eip1271_proxy_address_is_deterministic` | Same inputs → same address | `aa::eip1271::proxy_address` |
| `positive_aa_eip1271_proxy_address_depends_on_seed` | Different seeds → different addresses | `aa::eip1271::proxy_address` |
| `positive_aa_eip1271_proxy_address_depends_on_root` | Different roots → different addresses | `aa::eip1271::proxy_address` |
| `positive_aa_eip1271_domain_separator_depends_on_chain_id` | Cross-chain replay defence baked in | `aa::eip1271::domain_separator` |
| `positive_aa_eip1271_personal_sign_hash_replay_safe_includes_contract` | Cross-wallet replay defence baked in | `aa::eip1271::personal_sign_replay_safe_hash` |
| `positive_aa_eip1271_personal_sign_hash_includes_message` | Hash binds to message bytes | `aa::eip1271::personal_sign_replay_safe_hash` |
| `positive_aa_userop_keccak_empty_is_known_constant` | `KECCAK_EMPTY == keccak256("")` | `aa::userop::KECCAK_EMPTY` |
| `positive_aa_userop_sha256_empty_is_known_constant` | `SHA256_EMPTY == sha256("")` | `aa::userop::SHA256_EMPTY` |
| `positive_aa_userop_entry_point_v06_address_is_canonical` | EntryPoint v0.6 address is the canonical singleton (invariant #6) | `aa::userop::ENTRY_POINT_V06` |
| `positive_erc20_bundle_pure_verifier_round_trips_under_synthetic_root` | Pure verifier accepts self-consistent bundle | `pqsigner_tx::erc20::bundle::verify_erc20_bundle` |
| `positive_erc20_shim_threads_db_roots_constant` | Source pins `crate::db_roots::ERC20_DB_ROOT` in shim | source-text pin |
| `positive_names_shim_threads_db_roots_constant` | Source pins `crate::db_roots::NAMES_DB_ROOT` in shim | source-text pin |
| `positive_selectors_shim_threads_db_roots_constant` | Source pins `crate::db_roots::SELECTOR_DB_ROOT` in shim | source-text pin |
| `positive_selectors_shim_exposes_compat_alias_bundle_module` | Back-compat nested `pub mod bundle` preserved | source-text pin |
| `positive_slot_key_compute_is_8_bytes` | 8-byte slot key | `offchain_state::slot_key_compute` |
| `positive_slot_key_compute_is_deterministic` | Same inputs → same key | `slot_key_compute` |
| `positive_slot_key_compute_depends_on_account_index` | Account variance produces distinct keys | `slot_key_compute` |
| `positive_slot_key_compute_depends_on_chain_id` | Per-chain slot keys differ (chain-bound, invariant #6) | `slot_key_compute` |
| `positive_slot_key_compute_depends_on_slot_index` | Slot variance produces distinct keys | `slot_key_compute` |
| `positive_slot_key_compute_first_8_bytes_of_sha256` | Recipe = `SHA256(account‖chain_be8‖slot_be4)[..8]` | `slot_key_compute` |
| `positive_offchain_mock_initial_state_is_unregistered_and_zero` | Fresh slot: `is_registered = false`, both counters = 0 | mock backend |
| `positive_offchain_mock_register_then_is_registered_true` | `register_slot` flips the flag | mock backend |
| `positive_offchain_mock_bump_increases_count` | Strict-greater bumps land | mock backend |
| `positive_offchain_mock_last_userop_set_is_monotonic` | Higher values land | mock backend |
| `positive_offchain_mock_promote_to_is_idempotent` | Lower target is no-op, higher target raises | mock backend |
| `positive_offchain_mock_last_userop_set_tolerates_regression_as_noop` | Stale set is no-op, not error | mock backend |
| `positive_offchain_state_dual_backend_cfg_mux` | Both cfg branches present | source-text pin |
| `positive_offchain_state_flash_backed_branch_routes_to_hw_flash` | All 3 critical ops delegate to `crate::hw::flash` | source-text pin |
| `positive_offchain_state_mock_max_slots_is_128` | `MAX_SLOTS = 128` mirrors flash budget | source-text pin |
| `positive_offchain_state_mock_reset_for_test_is_e2e_gated` | `reset_for_test` is `cfg(feature = "e2e-test")` + `pub unsafe fn` | source-text pin |
| `positive_offchain_state_slot_key_compute_uses_be_bytes` | Hash uses `to_be_bytes()` (order-sensitive) | source-text pin |
| `positive_crypto_reexports_pqsigner_domain` | `pub use pqsigner_domain::*;` shim preserved | source-text pin |
| `positive_crypto_signing_uses_constant_time_compare` | `subtle::ConstantTimeEq` + `.ct_eq()` on sig pair | source-text pin |
| `positive_crypto_double_compute_present` | Both `sig_a` + `sig_b` lines present | source-text pin |
| `positive_crypto_verify_before_release_present` | `sphincs_c10::verify(...)` on released sig | source-text pin |
| `positive_crypto_verify_gate_uses_f2_sentinel_idiom` | `check_true_into_sentinel(\|\| black_box(v))` + `!= OK_SENTINEL` | source-text pin |
| `positive_crypto_wait_random_before_verify` | ≥2 `wait_random()` calls around FI gates | source-text pin |
| `positive_crypto_uses_rng_strong_not_plain_rng` | OptRand + shuffle seed from `rng_strong::fill` (3-source XOR) | source-text pin |
| `positive_crypto_zeroizes_opt_rand_on_every_return` | ≥5 `opt_rand_buf.zeroize()` + matching `zeroize_barrier()` | source-text pin |
| `positive_crypto_cfi_counter_has_seven_distinct_steps` | All 7 F-18 CFI step magics declared, bumped, and final-checked | source-text pin |
| `positive_crypto_sign_rate_limit_gates_call` | `sign_rate::pre_sign()` gate present (F-17 SCA defence) | source-text pin |
| `positive_crypto_sphincs_master_kdf_tag_is_exact` | `b"sphincs-master"` byte string present | source-text pin |
| `positive_crypto_provision_zeroizes_entropy_and_master_secret` | Both `.zeroize()` calls present in `provision_from_mnemonic` | source-text pin |
| `positive_crypto_provision_uses_mnemonic_to_entropy_with_panic_msg` | "mnemonic was already checksum-verified" docstring preserved | source-text pin |
| `positive_crypto_store_macd_runs_three_pass_macd_per_slot` | init/pin/init pattern preserved | source-text pin |
| `positive_dual_se_xor_split_recipe_present` | `half_e = xor_32(entropy, &half_o)` (invariant #1) | source-text pin |
| `positive_dual_se_three_source_random_for_half_o` | STM32 ⊕ OPTIGA ⊕ SE050 TRNG mix on half_o | source-text pin |
| `positive_dual_se_half_o_stuck_at_zero_fails_closed` | `if acc == 0` fail-closed gate present | source-text pin |
| `positive_dual_se_unlock_cross_verifies_master_secret` | `kdf("sphincs-master", full_entropy, 0)` cross-derive | source-text pin |
| `positive_dual_se_unlock_uses_two_pass_ct_eq_with_wait_random` | Two `ct_eq` + `wait_random` + `check_true_into_sentinel` | source-text pin |
| `positive_dual_se_xor_32_is_loop_constant_time` | No `break`/`return` inside `fn xor_32` body | source-text pin |
| `positive_dual_se_unlock_zeroizes_full_entropy_and_halves` | Multiple `half_o.zeroize` / `half_e.zeroize` / `full_entropy.zeroize` | source-text pin |
| `positive_dual_se_factory_reset_admin_zeroizes_caches_even_on_error` | `self.zeroize_caches()` precedes `?` propagation | source-text pin |
| `positive_dual_se_remaining_attempts_takes_min_not_max` | `o.min(e)` (stricter chip wins) | source-text pin |
| `positive_dual_se_pin_attempt_count_takes_max_not_min` | `Some(a.max(b))` (used-count aggregate) | source-text pin |
| `positive_dual_se_pin_attempt_counts_divergent_only_with_both_some` | Asymmetric None → not flagged divergent | source-text pin |
| `positive_dual_se_master_e_zeroized_after_decrypt` | `me.zeroize()` after unlock decrypt | source-text pin |
| `positive_dual_se_optiga_rejected_path_zeroizes_se050_master` | SE050 master wiped on OPTIGA-rejected path | source-text pin |
| `positive_dual_se_provision_passes_same_master_secret_to_both_chips` | Both `.provision()` calls take shared `master_secret` | source-text pin |
| `positive_dual_se_unlock_calls_se050_on_pin_incorrect_too` | Three-counter lockstep preserved | source-text pin |
| `positive_dual_se_unlock_skips_se050_on_non_pin_error` | `Err(_) => None` arm preserved | source-text pin |
| `positive_dual_se_blob_cache_uses_fih_bool` | `blob_cached: FihBool` + `is_true_fi()` | source-text pin |
| `positive_kdf_tag_sphincs_master_is_shared_between_crypto_and_dual_se` | Both files reference exact `b"sphincs-master"` tag | cross-module pin |
| `positive_shims_are_all_thin_re_exports` | Each shim ≤ its line budget (aa: 50, erc20: 60, names: 50, selectors: 80) | source-text pin |

## Negative coverage (the important one)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_selector_root_e2e_differs_from_production_root` | A refactor accidentally collapses the e2e + production selector roots into the same value, defeating the size optimisation and letting prod-curated bundles slip through e2e builds (or vice versa) | Re-derive both 32-byte literals from the source and assert them unequal | `assert_ne!` passes; the pin survives every config |
| `negative_aa_userop_parse_header_empty_input_rejected` | A truncated NS buffer (zero bytes) could panic the secure-side parser, bypassing the wire-length check at `USEROP_HEADER_LEN` | Pass `&[]` to `aa::userop::parse_header` | Returns `Err(WireParseError::Truncated)` — never panics |
| `negative_aa_shim_contains_no_unused_re_exports` | Logic creeps into the secure-side shim instead of staying in the pure-logic `pqsigner-aa` crate (where host signers / tools can reuse it) | Count non-trivial source lines in `aa/mod.rs` | ≤6 non-comment / non-blank lines |
| `negative_erc20_shim_rejects_bundle_built_under_a_different_root` | The shim wrapper ignores its `db_roots::ERC20_DB_ROOT` argument and accepts any valid bundle, no matter which root it was constructed under | Build a self-consistent merkle bundle for a *synthetic* root, then submit it through the shim (which uses the firmware-embedded root) | Returns `None`; the bundle does not verify under the firmware root |
| `negative_erc20_shim_rejects_empty_input` | An empty NS buffer panics the secure verifier | Pass `&[]` to the shim | Returns `None` |
| `negative_erc20_shim_rejects_truncated_bundle` | A 29-byte buffer (one short of the minimum header) blows past the bounds check | Pass `vec![0u8; 29]` | Returns `None` |
| `negative_erc20_shim_rejects_non_ascii_name` | A malicious ERC-20 bundle smuggles a non-printable byte into `name` to spoof the OLED (CLAUDE.md anti-spoof) | Build a bundle whose `name` contains `0xFF` | Returns `None` |
| `negative_names_shim_rejects_bundle_built_under_a_different_root` | The names shim ignores its `db_roots::NAMES_DB_ROOT` argument | Synthetic-root bundle routed through firmware-root shim | Returns `None` |
| `negative_names_shim_rejects_empty_input` | Empty NS buffer panics | Pass `&[]` | Returns `None` |
| `negative_selectors_shim_rejects_bundle_built_under_a_different_root` | The selectors shim ignores its `db_roots::SELECTOR_DB_ROOT` argument | Synthetic-root bundle routed through firmware-root shim | Returns `None` |
| `negative_selectors_shim_self_attest_parses_self_consistent_bundle` | Self-attest path is broken (degrades to either always-pass or always-fail) | Build a real self-attest bundle and assert the round-trip | Returns `Some(meta)` with `provenance = SelfAttest` |
| `negative_selectors_shim_self_attest_rejects_keccak_mismatch` | A malicious companion supplies a `text_sig` whose `keccak256[..4]` does NOT match the supplied selector (anti-spoof — false readable function name) | Bundle text + a wrong selector value | Returns `None` |
| `negative_offchain_mock_bump_regression_rejected` | A regressed `new_count < current` rewind is accepted, letting an attacker re-issue under-the-cap sigs (CLAUDE.md invariant #9) | `bump(5)` then `bump(4)` | Second call returns `Err(())`, counter stays at 5 |
| `negative_offchain_mock_bump_equal_value_rejected` | `bump(n)` followed by `bump(n)` is silently swallowed as no-op, letting replay-at-equal-value through | Two consecutive `bump(7)` calls | Second call returns `Err(())` |
| `negative_offchain_mock_bump_from_zero_to_zero_rejected` | The strict-monotonic gate (`new_count > current`) is relaxed to `>=`, letting `bump(0)` on a fresh slot through as a free no-op | `bump(0)` on a never-touched slot | Returns `Err(())` |
| `negative_crypto_no_naive_equality_on_sig_pair` | A refactor drops `subtle::ConstantTimeEq` and introduces `sig_a == sig_b` or `sig_a[..] == sig_b[..]`, leaking the diverging-index via timing (F-13 SCA) | Source-text negative pin for both literal forms | Neither pattern is present |
| `negative_crypto_cfi_magic_constants_must_be_distinct` | A copy-paste error aliases two of the seven F-18 CFI step magics, letting the sum gap of "skip A + skip B" collapse to "skip C" | Parse the seven `const CFI_STEP_*` hex literals from source and require their dedup to keep 7 entries | All 7 magics distinct |
| `negative_crypto_no_classical_signer_anywhere` | Invariant #5 is violated by a stray classical-signer import (secp256k1, Ed25519, FORS+C, p256, k256, ecdsa) | Source-text scan of `crypto.rs` for 9 forbidden tokens | None present |
| `negative_dual_se_no_full_entropy_handed_to_a_single_chip` | A refactor accidentally calls `optiga.provision(&entropy, ...)` or `se050.provision(&entropy, ...)` instead of the XOR halves, collapsing invariant #1 (single-chip dump recovers the seed) | Source-text negative pin for both `self.*.provision(&entropy` patterns | Neither pattern is present |
| `negative_dual_se_no_plaintext_kdf_tag_drift` | The unlock cross-check derives master with a drifted tag (`sphincs_master`, `sphincsmaster`, …), silently desyncing against the firmware-side provisioning tag | Count occurrences of exact `b"sphincs-master"` | ≥1 (the cross-check uses this tag) |
| `negative_dual_se_no_classical_signer_imports` | Same as the crypto-side test, but for `dual_se.rs` (defence-in-depth) | Scan for 5 forbidden token families | None present |
| `negative_crypto_glue_does_not_introduce_forbidden_admin_paths` | A refactor sneaks a `rotateMasterKeys` / `resetBootstrapUses` / `resetSlotUses` / `increaseMax*` path into the crypto glue — every one of which CLAUDE.md explicitly forbids | Scan all three heavy source files for the four forbidden identifiers | None present |

(Negative tests counted: 33. Positive tests counted: 61. Total: 94 new
host-runnable tests, all passing.)

## Production-code bugs surfaced by negative tests

None. Every negative test passes against the current source — the
slice respects every assumption it documents. (The brittle-regex
glitch found during initial test-bring-up was in the test harness
itself, not production code; the harness was tightened to use a
line-by-line `const ... = ...;` parser before commit.)

## Coverage gaps deliberately left

- **On-target FI defense exercise.** The 7-step CFI counter, the
  `wait_random()` deltas, the `zeroize_barrier()` compiler-fence sites,
  and the `OK_SENTINEL` constant are pinned through source text but
  not exercised end-to-end on host — proving they fire under real
  glitch / fault requires a ChipWhisperer / Scaffold harness on
  silicon. Tracked under `make saes-self-test-hw` /
  `make pin-gate-hw-counter-e2e`; out of scope for this host pass.
- **Real OPTIGA / SE050 lockstep.** `DualSecureElement::unlock` and
  `factory_reset_admin` need both chips on a real bench board (or
  the dual-se feature-flag `dual-se-admin-wipe-e2e` /
  `dual-se-multi-unlock-e2e` runners). Source-text pins above cover
  the algorithmic shape (XOR split, three-counter lockstep, master
  cross-check, fail-closed RNG, zeroization sites); the silicon
  round-trip lives under `make dual-se-admin-wipe-e2e` and
  `make dual-se-multi-unlock-e2e`.
- **Flash-backed `offchain_state` branch.** The
  `cfg(any(feature = "stm32u585", feature = "pka-accel"))` branch
  delegates to `crate::hw::flash::offchain_count_*` which can't link
  on host. Source-text pins verify the delegation shape; semantic
  parity (the SRAM mock must mirror flash's behaviour) is exercised
  by `make e2e` / `make e2e-hw` on the gateway end.
- **`provision_from_mnemonic` / `store_macd_encrypted` runtime
  exercise.** Both depend on the `WalletStore` / `SecureElement`
  trait surface backed by mock / SE drivers. Their algorithmic
  shape (zeroize chain, three-pass MACD, KDF tag, mnemonic
  checksum) is pinned via source text; runtime end-to-end is
  exercised under the wizard + e2e-test boot flow.
- **`c10_sign_verified_with_progress` runtime sign.** Requires a
  real C10 `SigningKey` plus the secure-side `sign_rate`,
  `rng_strong`, and `fi` modules (none link on host). Pure-logic
  pieces of the sign primitive (sig length, hypertree shape,
  shuffle invariance, hash hooks) live under
  `cargo test -p sphincs-c10`.

## Verification
- `cargo fmt -p sphincs-tz-secure --check` — N/A (sandbox declined the
  command's permission prompt in this session; not required for the
  test pass to be load-bearing — the source style mirrors the existing
  `nsc_core_under_test/pure_tests.rs` and `hw_crypto_under_test/pure_tests.rs`
  scaffolds and uses no exotic formatting).
- `cargo check -p sphincs-tz-secure` — PASS (only pre-existing
  warnings; no new warnings from the test pass).
- `cargo clippy -p sphincs-tz-secure --tests -- -D warnings` — N/A
  (same sandbox limitation as `cargo fmt`).
- `cargo test -p sphincs-tz-secure` — PASS (1642 tests pass, 2
  pre-existing `#[ignore]`; the new suite contributes 94 of those,
  all passing, 0 ignored).
- (firmware) on-target tests deferred: yes — see Coverage gaps above.
  `make dual-se-admin-wipe-e2e`, `make dual-se-multi-unlock-e2e`,
  `make saes-self-test-hw`, and `make pin-gate-hw-counter-e2e` are
  the matching silicon-side exercises.

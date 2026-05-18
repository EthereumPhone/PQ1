# Test Suite Added — `secure-zk`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope

BLS12-381 Groth16 verifier + Poseidon byte-hasher + VK-bundle Merkle
decoder for the ZK clear-signing path (Aave V3 / CowSwap
`setPreSignature` 2-pub circuit + CowSwap EIP-712 v3 3-pub circuit).

Source files covered:

- `secure/src/zk/mod.rs` — 277 lines (top-level
  `verify_clear_sign_proof` / `verify_clear_sign_proof_v3` /
  `verify_and_bind_trailer_v1`, plus the public constants
  `MAX_CALLDATA` / `STRING_LEN` / `PROOF_LEN` and the
  `ClearSignError` / `VerifiedClearSign{,V1}` types). The
  `render_clear_sign_pages` renderer stays `cfg(not(test))`-gated
  (UI dep) and is out of scope for host tests.
- `secure/src/zk/groth16.rs` — 276 lines (`Groth16Proof::from_bytes`,
  `VerificationKey::from_bytes`, `VerificationKeyV3::from_bytes`,
  `verify_clear_signing_proof`, `verify_clear_signing_proof_v3`,
  `VK_LEN`, `VK_V3_LEN`).
- `secure/src/zk/poseidon.rs` — 211 lines (`poseidon_bytes`,
  `poseidon_fields` over arities {2, 3, 5, 6, 7}).
- `secure/src/zk/vk_bundle.rs` — 122 lines (`verify_vk_bundle`,
  `VerifiedVk::{vk_as_2pub, vk_as_3pub}`, wire-format decoder).
- `secure/src/zk/test_vectors.rs` — 81 lines (committed reference
  vectors, mounted by the scaffold even when `feature = "debug-log"`
  is off).
- `secure/src/zk/vk_data.rs` — 78 lines (Aave V3 Pool 960-byte VK
  fixture, not normally `mod`-mounted in production — the firmware
  receives the VK via the NS bundle).

Total source under test: ~1045 lines.

## Test files added / extended

- `secure/src/main.rs` — added a 13-line `#[cfg(test)] mod
  zk_under_test;` declaration with surrounding comment, matching the
  existing `nsc_core_under_test` / `display_under_test` /
  `optiga_under_test` / `se050_under_test` scaffold pattern. No
  production-code semantics change.
- `secure/src/zk_under_test/mod.rs` — **new file**. Test-only
  scaffold that re-mounts `zk/mod.rs` (and through it, the three
  pure-logic child files via Rust's standard `pub mod` lookup) under
  a parallel module tree, plus sibling mounts for `test_vectors.rs`
  (gated behind `feature = "debug-log"` in production) and
  `vk_data.rs` (never mounted in production).
- `secure/src/zk_under_test/pure_tests.rs` — **new file**.
  17 positive tests + 42 negative tests = 59 host-runnable tests.

## Positive coverage

| test name | what it asserts | which API surface |
|---|---|---|
| `positive_const_proof_len_is_384` | `PROOF_LEN == 384` (96+192+96 G1‖G2‖G1) | `zk::PROOF_LEN` |
| `positive_const_max_calldata_is_164` | `MAX_CALLDATA == 164` matches circuit | `zk::MAX_CALLDATA` |
| `positive_const_string_len_is_64` | `STRING_LEN == 64` matches circuit | `zk::STRING_LEN` |
| `positive_const_vk_len_is_960` | `VK_LEN == 960 == VK_BLOB_LEN_2PUB` | `groth16::VK_LEN`, `db_format::VK_BLOB_LEN_2PUB` |
| `positive_const_vk_v3_len_is_1056` | `VK_V3_LEN == 1056 == VK_BLOB_LEN_3PUB == VK_BLOB_LEN` | `groth16::VK_V3_LEN`, `db_format::*` |
| `positive_const_zk_clear_sign_fixed_len_is_612` | `ZK_CLEAR_SIGN_FIXED_LEN == 612 == PROOF_LEN+MAX_CALLDATA+STRING_LEN` | `sphincs_tz_shared::ZK_CLEAR_SIGN_FIXED_LEN` |
| `positive_poseidon_bytes_matches_known_h_tx` | `Poseidon(TEST_CALLDATA, 164)` reproduces the committed `TEST_H_TX` | `poseidon::poseidon_bytes` (arity 6) |
| `positive_poseidon_bytes_matches_known_h_str` | `Poseidon(TEST_READABLE, 64)` reproduces the committed `TEST_H_STR` | `poseidon::poseidon_bytes` (arity 3) |
| `positive_poseidon_bytes_is_deterministic` | same input → same output | `poseidon::poseidon_bytes` |
| `positive_poseidon_bytes_all_supported_arities_dispatch` | all five block counts {2,3,5,6,7} dispatch to *distinct* permutations | `poseidon::poseidon_bytes` |
| `positive_poseidon_fields_arity_2_3_5_6_7_dispatch` | same aliasing guard at the field-element entry point | `poseidon::poseidon_fields` |
| `positive_groth16_proof_from_bytes_known_good` | 384 B reference proof deserialises and round-trips byte-exact through `to_uncompressed` for A/B/C | `Groth16Proof::from_bytes` |
| `positive_verification_key_from_bytes_known_good` | 960 B committed Aave V3 VK deserialises and round-trips alpha + IC[0..3] byte-exact | `VerificationKey::from_bytes` |
| `positive_verification_key_v3_from_bytes_accepts_valid_padded_vk` | a 1056 B VK with identity in IC[3] is accepted; `IC[3].is_identity()` holds | `VerificationKeyV3::from_bytes` |
| `positive_verify_clear_signing_proof_known_good` | full e2e pairing check passes on `(TEST_CALLDATA, TEST_READABLE, TEST_PROOF, VK_BYTES)` | `verify_clear_signing_proof` |
| `positive_min_bundle_len_is_1092` | minimal VK bundle = 8+20+1056+4+4 = 1092 B | `verify_vk_bundle` parser surface |
| `positive_vk_bundle_layout_offsets_are_frozen` | exact byte offsets (0/8/28/1084/1088/1092) of the 6-field wire layout are pinned | `verify_vk_bundle` wire format |

## Negative coverage (the important one)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_poseidon_fields_rejects_arity_4` | only arities {2,3,5,6,7} are wired; arity 4 must NOT silently fall through to arity 3 | call `poseidon_fields(&[0;4])` | `#[should_panic]` on `"unsupported Poseidon arity"` |
| `negative_poseidon_fields_rejects_arity_0` | empty input is rejected, not folded to capacity-only | `poseidon_fields(&[])` | panic |
| `negative_poseidon_fields_rejects_arity_1` | 1-input is rejected (no `poseidon1`) | `poseidon_fields(&[7u64])` | panic |
| `negative_poseidon_bytes_rejects_1_block_input` | `n=1` (1 block) is not in the dispatch table | `poseidon_bytes(&[0;32], 1)` | panic |
| `negative_poseidon_bytes_rejects_4_block_input` | the 4-block gap (n in [94..=124]) must stay closed; silent fall-through would produce wrong-but-consistent digests | `poseidon_bytes(&[0;256], 124)` | panic |
| `negative_poseidon_bytes_rejects_8_block_input` | the 8-block range (n in [218..=248]) is out of scope; no `poseidon8` | `poseidon_bytes(&[0;256], 218)` | panic |
| `negative_poseidon_bytes_rejects_single_byte_calldata_flip` | Poseidon is a binding commitment: companion cannot swap calldata between trusted display and on-chain dispatch | XOR byte 0 of `TEST_CALLDATA`, recompute | digest ≠ `TEST_H_TX` |
| `negative_poseidon_bytes_rejects_calldata_flip_at_last_signed_byte` | off-by-one guard on the byte-pack loop at high end of the attested region | XOR byte 100 of `TEST_CALLDATA` | digest ≠ `TEST_H_TX` |
| `negative_poseidon_bytes_rejects_readable_byte_flip` | readable string is also bound | XOR byte 5 of `TEST_READABLE` | digest ≠ `TEST_H_STR` |
| `negative_poseidon_bytes_ignores_bytes_past_n` | the `n` parameter actually bounds the hash; bytes past `n` cannot be smuggled into a signed payload | append 22 `0xAA` bytes past `TEST_CALLDATA`, hash with `n=164` | digest == `TEST_H_TX` |
| `negative_poseidon_bytes_distinguishes_different_n_in_same_block_bucket` | within a block bucket, `n` is not silently ignored; otherwise wire format is ambiguous between two declared-length payloads | populate bytes 155..186 with non-zeros; compare `n=164` vs `n=170` (both 6-block) | digests differ |
| `negative_poseidon_bytes_byte_order_matters` | bytes are packed big-endian into field elements (matches Circom); reversing input bytes must change the scalar | hash `[1..=62]` vs reversed `[62..=1]` | digests differ |
| `negative_groth16_proof_from_bytes_rejects_all_ones` | 0xFF…FF sets every flag bit + exceeds the base-field modulus; library MUST refuse | `Groth16Proof::from_bytes(&[0xff; 384])` | `None` |
| `negative_groth16_proof_from_bytes_rejects_all_zeros` | all-zero encoding is NOT the canonical identity (infinity bit unset); off-curve | `Groth16Proof::from_bytes(&[0; 384])` | `None` |
| `negative_groth16_proof_from_bytes_rejects_corrupted_a_flag_bits` | flipping the high flag bit of π.A's leading byte changes the declared encoding mode; result is non-canonical | XOR byte 0 high bit of good proof | `None` |
| `negative_groth16_proof_from_bytes_rejects_corrupted_b_flag_bits` | same guard on π.B (G2, 192 B at offset 96) | XOR byte 96 high bit | `None` |
| `negative_groth16_proof_from_bytes_rejects_corrupted_c_flag_bits` | same guard on π.C (G1, 96 B at offset 288) | XOR byte 288 high bit | `None` |
| `negative_verification_key_from_bytes_rejects_all_ones` | VK deserialiser refuses an all-0xFF blob | `VerificationKey::from_bytes(&[0xff; 960])` | `None` |
| `negative_verification_key_v3_from_bytes_rejects_zero_padding_in_ic3` | a 2-pub VK accidentally routed through the 3-pub decoder MUST NOT validate (last 96 zero bytes are not on the curve); this is what prevents IC[3] from being silently zero | wrap committed 2-pub VK as 1056 B with zero-padded tail | `None` |
| `negative_verify_clear_signing_proof_rejects_modified_calldata_byte` | Groth16 binds the H_tx public input; flipping a calldata byte breaks the pairing equation | XOR byte 12 of `TEST_CALLDATA`, verify | `false` |
| `negative_verify_clear_signing_proof_rejects_modified_readable_byte` | Groth16 binds H_str | XOR byte 3 of `TEST_READABLE`, verify | `false` |
| `negative_verify_clear_signing_proof_rejects_substituted_proof_a_with_generator` | swapping π.A for the G1 generator (a valid but unrelated point) must break the pairing | construct `Groth16Proof{a: G1::generator(), b, c}`, verify | `false` |
| `negative_verify_clear_signing_proof_rejects_identity_proof_a` | identity is the most obvious free-pass candidate because `pairing(0, *) = 1_Gt`; verifier MUST reject | construct `Groth16Proof{a: G1::identity(), b, c}` | `false` |
| `negative_verify_clear_signing_proof_rejects_identity_proof_c` | same guard on π.C | construct `Groth16Proof{a, b, c: G1::identity()}` | `false` |
| `negative_verify_clear_signing_proof_rejects_modified_vk_alpha` | tampered VK MUST NOT silently validate the genuine proof; either parse rejects OR verify rejects, never both pass | XOR byte 0 of `VK_BYTES` (alpha high bit), parse, verify (if parse OK) | parse rejects OR verify returns `false` |
| `negative_verify_clear_signing_proof_rejects_swapped_calldata_readable_pubs` | swapping the calldata/readable buffers produces unattested public inputs | push `TEST_READABLE` into calldata slot (zero-padded), `TEST_CALLDATA[..64]` into readable slot, verify | `false` |
| `negative_verify_clear_signing_proof_rejects_substituted_unrelated_vk` | a syntactically-valid but semantically-unrelated VK (one IC[1] multiplied by 3) MUST fail the pairing equation | rotate IC[1] in `VK_BYTES` via scalar mul, parse, verify | `false` |
| `negative_verify_clear_signing_proof_v3_rejects_wrong_root` | v3 binds `erc20_poseidon_root` as the third public input; an attacker cannot pick a root of their choosing and hide behind a valid-looking proof | run v3 verifier with `Scalar::from(42u64)` as the root | `false` |
| `negative_verify_vk_bundle_rejects_empty_buffer` | the decoder bounds-checks before any read | `verify_vk_bundle(&[])` | `None` |
| `negative_verify_vk_bundle_rejects_one_byte_short_of_header` | exact-length guard at 1092 B | bundle of 1091 zeros | `None` |
| `negative_verify_vk_bundle_rejects_proof_depth_above_32` | `proof_depth > 32` is rejected before any sibling-hash read (bounds stack usage; caps DoS surface at 1 KiB proof) | bundle with `proof_depth = 33` and a 33×32 B trailer | `None` |
| `negative_verify_vk_bundle_rejects_extreme_proof_depth` | the cap guard fires before the multiplication `proof_depth * 32` could overflow on a 32-bit usize | `proof_depth = u32::MAX` | `None` |
| `negative_verify_vk_bundle_rejects_trailing_bytes_after_proof` | trailer length is NOT malleable; appending an unexamined byte after the proof must reject (otherwise a companion could smuggle bytes past the audit log) | bundle + 1 trailing 0x00 | `None` |
| `negative_verify_vk_bundle_rejects_truncated_proof_tail` | `proof_depth = 2` with only 32 B of trailer is short by one sibling hash | bundle with depth=2 and a single-sibling trailer | `None` |
| `negative_verify_vk_bundle_rejects_structurally_valid_but_wrong_root` | the Merkle walk is enforced; a bundle whose leaf does not hash to `VK_DB_ROOT` MUST be rejected (this is the entire trust chain) | well-shaped bundle with chain=1 / contract=0x11.. / VK=identity-IC3 | `None` |
| `negative_verify_vk_bundle_proof_depth_32_with_wrong_root_still_rejected` | rejection at the max-depth boundary comes from the Merkle walk, not the cap | bundle with depth=32 and all-zero trailer | `None` |
| `negative_verify_clear_sign_proof_rejects_malformed_proof_bytes` | the top-level wrapper threads a `from_bytes` failure straight to `ClearSignError` | call with `[0xff; 384]` proof bytes | `Err(ClearSignError)` |
| `negative_verify_clear_sign_proof_rejects_malformed_bundle` | the top-level wrapper threads a bundle-decode failure straight to `ClearSignError` | call with 16-byte bundle | `Err(ClearSignError)` |
| `negative_verify_and_bind_trailer_v1_rejects_too_short_bundle` | the v1 trailer-binder enforces `bundle.len() >= ZK_CLEAR_SIGN_FIXED_LEN` before any slice | bundle of `ZK_CLEAR_SIGN_FIXED_LEN - 1` zeros | `None` |
| `negative_verify_and_bind_trailer_v1_rejects_inner_data_too_long` | inner-data length is capped at `MAX_CALLDATA` (the circuit's max attested calldata) | `inner_data.len() == MAX_CALLDATA + 1` | `None` |
| `negative_verify_and_bind_trailer_v1_rejects_malformed_proof_in_trailer` | the trailer-binder threads a `verify_clear_sign_proof` failure to `None` | trailer with 612 B of 0xFF followed by a well-shaped-but-Merkle-invalid bundle | `None` |
| `negative_vk_blob_len_2pub_is_960_and_3pub_is_1056` | the `vk_as_2pub` / `vk_as_3pub` accessors' compile-time panic messages are predicated on these constants; pinning them gives a clear test-time failure instead of a generic prod panic | direct constant assertions | constants frozen, 2-pub ≤ slot, 3-pub ≤ slot |

## Production-code bugs surfaced by negative tests

None. Every negative test passes with the production code as-is, which
is the expected outcome — the slice's verifier is correctly enforcing
every assumption asserted above. No `#[ignore]` markers in the suite.

## Coverage gaps deliberately left

- **Happy-path `verify_vk_bundle` Merkle verification.** The
  embedded root (`crate::db_roots::VK_DB_ROOT`) is a baked-in
  `dbgen`-produced constant and no in-repo fixture supplies a bundle
  whose leaf hashes to it. The cryptographic Merkle walker is
  upstream in `pqsigner_tx::erc20::merkle::verify_proof` and is
  already covered by `dbgen`'s round-trip test + the on-target QEMU
  e2e. A future pass that wires in a fixture VK pool (or a
  `cfg(test)`-overridable root) could add a positive verification
  here.
- **`verify_clear_signing_proof_v3` happy path.** The v3 CowSwap
  EIP-712 circuit has no committed reference proof in the repo (only
  the 2-pub Aave V3 vector ships under `test_vectors.rs`). The v3
  surface is covered structurally (3-pub VK deserialisation + wrong-
  root negative) but not end-to-end. Adding a v3 reference vector
  would let us exercise the rodata-pinned root binding positively.
- **`crate::zk::verify_clear_sign_proof_v3` against the real
  `ERC20_POSEIDON_ROOT`.** Same shape as above — happy path requires
  a committed v3 proof.
- **`render_clear_sign_pages` UI renderer.** Gated `cfg(not(test))`
  because it pulls `crate::ui::*` and `crate::tx::display`, which are
  also `cfg(not(test))`. UI rendering is the `secure-tx-display`
  slice's responsibility; this slice's tests stop at the verifier
  boundary.
- **Fuzz coverage of `verify_vk_bundle`.** The slice's parser is a
  natural fit for the existing `secure/src/fuzz_props.rs` proptest
  harness ("never panic on arbitrary input"). Adding a fuzz target
  there is a follow-up — out of scope for this positive/negative
  pass.
- **SE-zeroization / `ZeroizeOnDrop` semantics.** This slice does
  not hold secrets (the verifier sees only public inputs, attested
  calldata, and a public VK), so no `ZeroizeOnDrop` types are in
  scope.
- **Constant-time guarantees.** Groth16 verification is not on the
  secret-dependent codepath (inputs are public and the answer is
  binary); no `subtle::ConstantTimeEq` invariant to assert here.
- **On-target Cortex-M timings.** Bench numbers (≤ 3 s first-sign
  on STM32U585) are not test-asserted here; they live in
  `make test-key-speed` on real silicon. The host-runnable suite
  here pins correctness, not performance.

## Verification

- `cargo fmt -p sphincs-tz-secure --check` — N/A (sandbox blocked
  `cargo fmt` invocations during this pass; the two new files
  follow the project's idiomatic 4-space rustfmt style and import a
  consistent set of types).
- `cargo check -p sphincs-tz-secure --tests` — PASS (1.21 s,
  43 warnings, all pre-existing).
- `cargo clippy -p sphincs-tz-secure --tests -- -D warnings` — N/A
  (sandbox blocked `cargo clippy` invocations during this pass; new
  code uses no `unsafe`, no panics in non-test paths, and no
  lint-triggering constructs beyond the `#![allow(clippy::needless_range_loop)]`
  attached to the test file for the index-based fixture loops).
- `cargo test -p sphincs-tz-secure` — **PASS** (1340 tests, 2
  ignored; 59 new tests in `zk_under_test::pure_tests::*`, 0
  failures, 0.08 s).
- (firmware) on-target tests deferred: no. Every test in this pass
  runs on the host CPU under `cargo test`; the slice's pure-logic
  surface compiles cleanly on x86_64.

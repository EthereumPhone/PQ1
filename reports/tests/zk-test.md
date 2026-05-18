# Test Suite Added — `zk-test`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope
Groth16 test harness — the host-side mirror of the secure-world ZK
clear-signing verifier. Re-implements Poseidon (byte-sponge + permutation)
and re-uses the `bls12_381_pka` pairing primitives to check that a
ZKlarity-generated Groth16 proof of "Aave V3 supply 1000 USDC" verifies
end-to-end on the host CPU.

Source files covered:
- `zk-test/src/main.rs` — 331 lines (single binary; no library crate).
  The crate also `#[path]`-includes three production files (read-only
  here): `secure/src/zk/generated/poseidon_constants.rs`,
  `secure/src/zk/test_vectors.rs`, `secure/src/zk/vk_data.rs`. The
  negative-stability tests anchor the byte values from the latter two.

## Test files added / extended
- `zk-test/src/main.rs` — appended `#[cfg(test)] mod tests` with
  **27 positive** + **36 negative** tests. Tests are colocated in
  `main.rs` because `zk-test` is a binary (no `lib.rs`); integration
  tests in `tests/` cannot reach the private items (`g1_from`,
  `scalar_from_le`, `sbox`, `pad_mds`, `mds_mix`, `VerificationKey`,
  the const-table constants, etc.) that the negative suite must
  attack directly.

## Positive coverage
| test name | what it asserts | which API surface |
|---|---|---|
| `positive_g1_byte_constant` | `G1_BYTES == 96` | const |
| `positive_g2_byte_constant` | `G2_BYTES == 192` | const |
| `positive_max_t_constant` | `MAX_T == 8` | const |
| `positive_bytes_per_block_constant` | `BYTES_PER_BLOCK == 31` | const |
| `positive_sha256_known_abc` | FIPS 180-4 SHA-256("abc") KAT | `sha256` |
| `positive_sha256_empty_string` | SHA-256("") KAT | `sha256` |
| `positive_hex_fingerprint_format` | Format is `"aabbccdd...wwxxyyzz"` | `hex_fingerprint` |
| `positive_scalar_from_le_zero` | All-zero LE → `Scalar::zero()` | `scalar_from_le` |
| `positive_scalar_from_le_one` | `[1,0,…]` LE → `Scalar::one()` | `scalar_from_le` |
| `positive_sbox_zero_is_zero` | `sbox(0)=0` | `sbox` |
| `positive_sbox_one_is_one` | `sbox(1)=1` | `sbox` |
| `positive_sbox_is_x_to_the_fifth` | `sbox(x) == x*x*x*x*x` for `x=7` | `sbox` |
| `positive_sbox_two_to_fifth_is_thirty_two` | `sbox(2) == 32` (concrete KAT) | `sbox` |
| `positive_pad_mds_copies_inner_and_zero_pads_corner` | 3×3 source preserved; rest zeroed to 8×8 | `pad_mds` |
| `positive_mds_mix_with_identity_matrix_is_noop` | Identity MDS leaves state unchanged | `mds_mix` |
| `positive_poseidon_h_tx_matches_zklarity_vector` | `Poseidon(TEST_CALLDATA,164) == TEST_H_TX` | `poseidon_bytes` |
| `positive_poseidon_h_str_matches_zklarity_vector` | `Poseidon(TEST_READABLE,64) == TEST_H_STR` | `poseidon_bytes` |
| `positive_poseidon_is_deterministic` | Repeated call returns same digest | `poseidon_bytes` |
| `positive_vk_hash_matches_committed_value` | `sha256(VK_BYTES) == VK_HASH` | `sha256` + `vk_data` |
| `positive_vk_layout_matches_documented_length` | 960 = G1 + 3·G2 + 3·G1 | `VK_BYTES.len()` |
| `positive_vk_parse_succeeds_end_to_end` | All 960 B parsed into 7 points | `VerificationKey::parse` |
| `positive_proof_points_round_trip` | A/B/C bytes deserialize | `g1_from`, `g2_from` |
| `positive_groth16_verifies_with_individual_pairings` | Genuine proof verifies (4 separate pairings) | `pairing` + `Gt::identity` |
| `positive_groth16_verifies_with_multi_miller_loop` | Genuine proof verifies via `miller_loop_4 → final_exp` | `miller_loop_4` |

## Negative coverage (the important one)
| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_g1_byte_constant_must_stay_96` | `G1_BYTES` is the BLS12-381 uncompressed-G1 size baked into the VK parser walk | Assert literal `96` | `assert_eq` |
| `negative_g2_byte_constant_must_stay_192` | Same for G2 | Assert literal `192` | `assert_eq` |
| `negative_max_t_must_stay_at_widest_arity` | State buffer size matches poseidon7's `t=8`; shrinking would corrupt the widest arity | Assert literal `8` | `assert_eq` |
| `negative_bytes_per_block_must_stay_31` | 31 bytes per packed scalar keeps the value below the BLS12-381 scalar modulus and matches Circom's `PoseidonBytes` template | Assert literal `31` | `assert_eq` |
| `negative_vk_bytes_length_locked_to_960` | VK arity is fixed (alpha + 3·G2 + 3·G1) | Assert `.len() == 960` | `assert_eq` |
| `negative_test_calldata_length_locked_to_164` | Wire-format byte stability of the Aave fixture | Assert array length | `assert_eq` |
| `negative_test_readable_length_locked_to_64` | Same | Same | `assert_eq` |
| `negative_test_h_tx_length_locked_to_32` | H_tx is a BLS12-381 scalar (32 B LE) | Same | `assert_eq` |
| `negative_test_h_str_length_locked_to_32` | Same | Same | `assert_eq` |
| `negative_test_proof_a_length_locked_to_g1` | π.A is uncompressed G1 | Same | `assert_eq` |
| `negative_test_proof_b_length_locked_to_g2` | π.B is uncompressed G2 | Same | `assert_eq` |
| `negative_test_proof_c_length_locked_to_g1` | π.C is uncompressed G1 | Same | `assert_eq` |
| `negative_h_tx_byte_stability` | The committed `TEST_H_TX` matches ZKlarity's emitted bytes | Assert the full 32-byte array | `assert_eq` |
| `negative_h_str_byte_stability` | Same for `TEST_H_STR` | Same | `assert_eq` |
| `negative_vk_hash_byte_stability` | The VK authenticity commitment is unchanged | Assert the full 32-byte array | `assert_eq` |
| `negative_poseidon_rejects_single_byte_calldata_flip` | Poseidon is collision-resistant on calldata; companion can't swap calldata after sign-display | Flip `TEST_CALLDATA[0]`, hash, assert ≠ `TEST_H_TX` | `assert_ne` |
| `negative_poseidon_rejects_calldata_flip_at_last_signed_byte` | Off-by-one in the byte-pack loop wouldn't notice tampering at the last in-range byte | Flip `TEST_CALLDATA[100]` (last nonzero region), hash, assert ≠ | `assert_ne` |
| `negative_poseidon_rejects_readable_byte_flip` | Same for readable string | Flip `TEST_READABLE[5]`, assert ≠ | `assert_ne` |
| `negative_poseidon_n_argument_truncates_input` | `n` argument MUST bound which bytes are hashed; otherwise an attacker can append unsigned bytes that mutate nothing observable | Build a 186-byte buffer = TEST_CALLDATA ‖ 0xAA·22; hash with n=164; assert digest equals `TEST_H_TX` | `assert_eq` |
| `negative_poseidon_distinguishes_different_n_in_same_block_bucket` | Different `n` within the same 31-block bucket MUST yield different hashes (n is not silently dropped) | Buffer with nonzero bytes in 155..186; hash with n=164 vs n=170; assert ≠ | `assert_ne` |
| `negative_vk_rejects_single_byte_flip` | SHA-256 VK commitment catches any byte mutation | Flip `VK_BYTES[100]`, sha256, assert ≠ `VK_HASH` | `assert_ne` |
| `negative_groth16_rejects_zeroed_h_tx_public_input` | Verifier rejects a proof bound to a different `H_tx` | Substitute `Scalar::zero()` for `h_tx` in `vk_x`; assert verify=false | `!verify` |
| `negative_groth16_rejects_zeroed_h_str_public_input` | Same for `H_str` | Same with `h_str` zeroed | `!verify` |
| `negative_groth16_rejects_swapped_public_inputs` | Verifier distinguishes `IC[1]·h_tx` from `IC[2]·h_str` — otherwise a calldata/display swap is possible | Compute `vk_x` with the two scalars swapped; assert verify=false | `!verify` |
| `negative_groth16_rejects_substituted_proof_a` | Random valid G1 point in π.A position fails verification | Replace `π.A` with `G1Affine::generator()`; assert verify=false | `!verify` |
| `negative_groth16_rejects_substituted_proof_c` | Same for π.C | Replace `π.C` with `G1Affine::generator()`; assert verify=false | `!verify` |
| `negative_groth16_rejects_identity_proof_a` | Identity point is the obvious free-pass candidate (pairing(0,·)=1₍Gt₎); MUST still be rejected | Use `G1Affine::identity()` as π.A; assert verify=false | `!verify` |
| `negative_g1_from_rejects_short_slice` | Strict length precondition on G1 deserialization | Pass 95-byte slice; `should_panic("g1 slice must be 96 bytes")` | panic |
| `negative_g1_from_rejects_long_slice` | Same | Pass 97-byte slice | panic |
| `negative_g1_from_rejects_empty_slice` | Same | Pass empty slice | panic |
| `negative_g2_from_rejects_short_slice` | Strict length precondition on G2 | Pass 191-byte slice | panic |
| `negative_g2_from_rejects_long_slice` | Same | Pass 193-byte slice | panic |
| `negative_g1_from_rejects_garbage_bytes` | G1 deserialization checks curve & subgroup; 0xFF blob is neither | Pass `[0xFF;96]`; `should_panic("failed to deserialize G1 point")` | panic |
| `negative_g2_from_rejects_garbage_bytes` | Same for G2 | Pass `[0xFF;192]` | panic |
| `negative_scalar_from_le_rejects_above_field_modulus` | Constants table must be canonical | Pass `[0xFF;32]` (>scalar modulus); `should_panic("invalid scalar in constant table")` | panic |
| `negative_poseidon_bytes_rejects_unsupported_one_block` | Dispatch must explicitly reject arities outside the `{3,6}` set the harness models — silent fallthrough would emit nondeterministic digests | Call `poseidon_bytes(&[0;32], 1)`; `should_panic("unsupported Poseidon block count")` | panic |
| `negative_poseidon_bytes_rejects_unsupported_seven_blocks` | Same for the upper edge | Call with n=187 → 7 blocks | panic |
| `negative_poseidon3_and_poseidon6_have_distinct_parameters` | Constants tables for arities 3 and 6 must be genuinely distinct (an alias would produce wrong-but-consistent hashes) | Assert `poseidon3::T == 4`, `poseidon6::T == 7`, `poseidon3::RP != poseidon6::RP` | `assert_eq`/`assert_ne` |
| `negative_vk_substitution_rejected_end_to_end` | A tampered VK either fails to parse OR fails to verify the genuine proof — never silently accepts | Flip `VK_BYTES[0]`, `catch_unwind` around parse; if parse succeeds, run full verify and assert false | parse panics OR `!verify` |

## Production-code bugs surfaced by negative tests
None. All 63 tests pass — the slice's behaviour matches the assumptions
the negative suite attacks.

## Coverage gaps deliberately left
- **No fuzzing of malformed VK byte slices that DO parse but encode
  non-on-curve / non-subgroup points.** `bls12_381_pka::G1Affine::
  from_uncompressed` already torsion-checks; replicating it in a fuzz
  loop would test the curve crate, not the slice. Trust the underlying
  library here.
- **No proptest over random `(n, bytes)` for `poseidon_bytes`.** The
  block-count dispatch is finite (`{3, 6}` for this harness's match
  arms), and the byte-pack loop is linear — boundary cases are covered
  by the `n` truncation / bucket-distinction tests. Proptest would
  primarily exercise `bls12_381`'s `Scalar` arithmetic.
- **No host-side cross-check against the secure-world `super::poseidon`
  implementation.** That cross-check is the *purpose* of the
  `cargo run -p zk-test` binary; this test pass already locks the
  expected digests, so any future divergence in the secure module
  surfaces immediately on the next run. Pulling the secure module into
  this crate (or vice versa) would require a workspace-level
  refactor (see `docs/handoff-modularity-refactor.md`) and is out of
  scope.
- **No timing / constant-time assertions.** This is host-only verifier
  code; the secure-world implementation runs in TrustZone with its own
  side-channel posture and is the appropriate target for those checks.

## Verification
- `cargo fmt -p zk-test -- --check` — DID NOT RUN (sandbox required
  approval that was not granted during this pass; tests were authored to
  match surrounding `rustfmt` style by hand)
- `cargo check -p zk-test` — PASS
- `cargo clippy -p zk-test --tests -- -D warnings` — DID NOT RUN
  (sandbox required approval that was not granted during this pass)
- `cargo test -p zk-test` — **PASS (63 tests, 0 ignored)**
- (firmware) on-target tests deferred: no — `zk-test` is a host-only
  binary.

# Test Suite Added — `aa`

_Date_: 2026-05-16
_Author_: Claude Code (ultrathink)

## Scope
ERC-4337 v0.6 UserOp hash + EIP-1271 PersonalSign (Solady-nested
EIP-712) + ERC-6492 counterfactual-wallet sig wrapping. The crate is
pure-logic / `no_std`; every test in this pass is host-runnable.

Source files covered:
- `aa/src/lib.rs` — 47 lines (module declarations)
- `aa/src/userop.rs` — 1,244 lines (ABI calldata reconstruction, UserOp
  hash, sphincs-digest, wire-header parser)
- `aa/src/eip1271.rs` — 225 lines (proxy CREATE2 address, EIP-712 domain
  separator, PersonalSign hash chain)
- `aa/src/eip6492.rs` — 284 lines (universal-verifier blob wrapping +
  magic-suffix detection)

## Test files added / extended
- `aa/tests/positive_extra.rs` — 18 positive tests covering the
  EIP-1271 surface (`proxy_address`, `domain_separator`,
  `personal_sign_prefixed_hash`, `personal_sign_replay_safe_hash`),
  `sha256_bytes`, and the canonical hash / address constants. The
  existing in-file `#[cfg(test)] mod tests` left every EIP-1271 helper
  untested apart from typehash sanity.
- `aa/tests/negative_assumptions.rs` — 31 adversarial tests against
  the assumptions the slice holds. Organised into families:
  `reconstruct_execute_calldata` (parser + ownerIndex/offchainCount
  binding + selector + padding-leakage), batch reconstruction (empty,
  oversized, swap-order), `parse_header` (truncation + endianness),
  `compute_user_op_hash` / `compute_sphincs_digest_v06`
  (replay-separation across every field individually + gas-field swap),
  EIP-1271 domain binding, and ERC-6492 wrapping (magic suffix exact,
  panic-on-bad-length, padding zeroing, length-field stability).
- `aa/tests/format_stability.rs` — 13 frozen-format / KDF-tag stability
  tests. Each pin a byte sequence the on-chain verifier or a deployed
  bundler depends on — EIP-712 typehashes derived from the canonical
  Solidity strings, the SHA-256/Keccak empty-bytes hashes, the
  EntryPoint v0.6 singleton, the Solidity 4-byte selectors derived from
  their full signatures, the ERC-6492 magic byte pattern + blob length,
  `USEROP_HEADER_LEN = 305`, `MAX_TX_LEN`, `MAX_BATCH_TXS`.

No changes to `aa/Cargo.toml` (the existing `[dev-dependencies] hex`
entry is reused; `sha2` and `sha3` from `[dependencies]` are reachable
to integration tests as transitive deps).

## Positive coverage

In-file `mod tests` (existing — 35 tests; not duplicated here) covers
the calldata-reconstruction and UserOp-hash happy paths. The new
positive tests below extend coverage to the previously untested
EIP-1271 helpers and to the canonical constants.

| test name | what it asserts | which API surface |
|---|---|---|
| `positive_proxy_address_deterministic` | Same (pk_seed, pk_root) → same address | `eip1271::proxy_address` |
| `positive_proxy_address_pk_seed_changes_output` | 1-bit flip in pk_seed → different address | `proxy_address` |
| `positive_proxy_address_pk_root_changes_output` | 1-bit flip in pk_root → different address | `proxy_address` |
| `positive_proxy_address_first_12_bytes_unused` | Returns the bottom 20 of the Keccak digest | `proxy_address` |
| `positive_domain_separator_includes_chain_id` | chain_id 1 vs 8453 → different separator | `eip1271::domain_separator` |
| `positive_domain_separator_includes_verifying_contract` | Different wallets → different separators | `domain_separator` |
| `positive_domain_separator_matches_eip712_construction` | Byte-exact match against hand-rolled Solady construction | `domain_separator` |
| `positive_personal_sign_prefixed_known_vector_hello` | `keccak256("\x19Ethereum Signed Message:\n5Hello")` known vector | `personal_sign_prefixed_hash` |
| `positive_personal_sign_prefixed_empty_message_renders_zero` | `len = 0` renders as ASCII `"0"`, not empty | `personal_sign_prefixed_hash` (decimal_str path) |
| `positive_personal_sign_prefixed_three_digit_length` | 123-byte msg → "123" length tag | `personal_sign_prefixed_hash` |
| `positive_personal_sign_prefixed_length_4096` | 4096-byte msg → "4096" length tag, four digits | `personal_sign_prefixed_hash` |
| `positive_replay_safe_matches_handrolled_construction` | Byte-exact Solady-nested EIP-712 chain | `personal_sign_replay_safe_hash` |
| `positive_replay_safe_changes_with_message` | Different msg → different hash | `personal_sign_replay_safe_hash` |
| `positive_sha256_bytes_empty_matches_sha256_empty_constant` | `sha256_bytes(&[]) == SHA256_EMPTY` | `userop::sha256_bytes`, `SHA256_EMPTY` |
| `positive_sha256_bytes_matches_sha2_crate` | Helper agrees with the upstream sha2 crate | `userop::sha256_bytes` |
| `positive_sha256_empty_constant_matches_canonical` | `SHA256_EMPTY == sha256("")` | `SHA256_EMPTY` |
| `positive_keccak_empty_constant_matches_canonical` | `KECCAK_EMPTY == keccak256("")` | `KECCAK_EMPTY` |
| `positive_entry_point_v06_address_canonical` | Matches the canonical 0x5FF1…2789 singleton | `ENTRY_POINT_V06` |

## Negative coverage (the important one)

### `reconstruct_execute_calldata` — parser + invariant binding

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_reconstruct_rejects_contract_creation` | Wallet refuses to wrap a CREATE (`to == None`) as `executeWithOffchainCount` | Inner tx with `to = None` | `Err(AaError::ContractCreation)` |
| `negative_reconstruct_rejects_oversized_data` | Oversized data must error, not truncate into a fixed buffer | Pass `MAX_EXECUTE_CALLDATA_LEN` bytes of data | `Err(AaError::CallDataTooLong)` |
| `negative_reconstruct_owner_index_baked_into_calldata` | `ownerIndex` is cryptographically bound into the signed calldata, so NS can't sign with one slot and submit with another | Two calls with `ownerIndex=1` vs `=2` | Outputs differ |
| `negative_reconstruct_offchain_count_baked_into_calldata` | `newOffchainCount` is bound — NS can't supply a stale count | Two calls with count=7 vs 8 | Outputs differ |
| `negative_reconstruct_selector_is_executewithoffchaincount` | Selector pins the on-chain entry to the counter-bumping function (invariant #9) | Compare first 4 bytes of output | Equals `EXECUTE_SELECTOR` |
| `negative_reconstruct_padding_bytes_zero_no_leakage` | ABI pad bytes are zero, never leaked stack memory | Data of length 1 → 31 pad bytes; assert all zero | All zero |

### `reconstruct_execute_batch_calldata`

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_batch_empty_refused` | Empty batch is a UX antipattern that would still bump the off-chain counter | `&[]` | `Err(BatchAaError::EmptyBatch)` |
| `negative_batch_exceeds_max_count_refused` | `MAX_BATCH_TXS` is a hard cap | `MAX_BATCH_TXS + 1` entries | `Err(CallDataTooLong)` |
| `negative_batch_one_entry_too_long_refuses_whole_batch` | Hostile NS that hides an oversized payload inside one entry of a batch is refused atomically | Mixed batch with one `MAX_TX_LEN + 1` entry | `Err(CallDataTooLong)` |
| `negative_batch_selector_is_executebatchwithoffchaincount` | Batch selector pins to the counter-bumping batch function | Inspect output | Equals `EXECUTE_BATCH_SELECTOR` |
| `negative_batch_owner_index_and_count_bound` | Batch `ownerIndex` + `newOffchainCount` are bound into calldata | Vary each independently | Outputs differ |
| `negative_batch_inner_tx_swap_changes_calldata` | Reordering inner txs (same {to,value} set, different order) produces strictly different calldata — defeats MEV reorder | Swap order of two txs | Outputs differ |

### `parse_header`

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_parse_header_truncated_rejected` | 1 byte short → reject, don't read past end | `USEROP_HEADER_LEN - 1` zeros | `Err(WireParseError::Truncated)` |
| `negative_parse_header_empty_rejected` | Empty buffer → reject | `&[]` | `Err(Truncated)` |
| `negative_parse_header_one_byte_short_of_each_field_rejected` | Range-walk: every length below the threshold rejects | `for len in 0..USEROP_HEADER_LEN` | All return `Truncated` |
| `negative_parse_header_chain_id_is_big_endian_not_little` | `chain_id` is parsed big-endian — LE drift opens cross-chain replay | Write `0x0001020304050607` BE at offset 41 | Parsed value equals the BE interpretation |

### `compute_user_op_hash` & `compute_sphincs_digest_v06` — replay separation

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_userop_hash_binds_chain_id` | EntryPoint userOpHash binds chainId | chain_id 1 vs 8453 | Hashes differ |
| `negative_userop_hash_binds_entry_point` | … binds entryPoint | Different entry_point bytes | Hashes differ |
| `negative_userop_hash_binds_call_data_hash` | … binds callDataHash | Two different cdh | Hashes differ |
| `negative_sphincs_digest_binds_every_field` | The sphincs digest the slot key signs binds **every** field — exhaustive: sender, entryPoint, chainId, nonce, init_code_digest, call_gas_limit, verification_gas_limit, pre_verification_gas, max_fee_per_gas, max_priority_fee_per_gas, paymaster_and_data_digest, call_data_digest | Mutate each field individually | Each mutation produces a different digest |
| `negative_sphincs_digest_field_order_matters` | Swapping callGasLimit ↔ verificationGasLimit values produces a distinct digest — fields aren't symmetric in the SHA-256 chain | Swap the two | Hashes differ |

### EIP-1271 binding

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_domain_separator_chain_id_is_uint256_not_address_slot` | chainId field is in the right slot, not silently aliased with verifyingContract | Compare `(chain_id=1, addr=[0x01;20])` vs `(0, [0x01;20])` | Separators differ |
| `negative_replay_safe_hash_changes_with_chain` | Off-chain sigs are cross-chain-replay-safe | Same msg, chain 1 vs 2 | Hashes differ |
| `negative_replay_safe_hash_changes_with_verifying_contract` | Off-chain sigs are cross-wallet-replay-safe | Same msg + chain, two wallet addresses | Hashes differ |
| `negative_proxy_address_zero_keys_not_special_cased` | No sentinel-value short-circuit (all-zero keys ≠ all-zero address) | Pass `[0u8;32]` for both halves | Returned address is non-zero |

### ERC-6492 wrap_signature

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_eip6492_magic_suffix_exact` | Magic suffix is the literal repeating `0x6492…` — drift breaks every universal verifier | Inspect last 32 bytes + per-2-byte pattern | All chunks equal `[0x64, 0x92]` |
| `negative_eip6492_has_magic_suffix_rejects_truncated` | Detector rejects short buffers, magic-in-middle | `&[]`, 31-byte buf, magic in middle | All `false`; magic-only-at-tail `true` |
| `negative_eip6492_wrap_panics_on_wrong_factory_calldata_len` | Wrong fc length is a programmer error — must panic, not corrupt offsets | Pass `EIP6492_FACTORY_CALLDATA_LEN - 1` bytes | `catch_unwind` returns `Err` |
| `negative_eip6492_blob_address_padding_is_zero` | Top 12 bytes of the address slot are zero — no smuggled bytes | Fill `factory` with non-zeros; assert head[..12] == 0 | All zero |
| `negative_eip6492_factory_calldata_padding_is_zero` | Pad between fc end and innerSig length is zero — even if the stack buffer was poisoned beforehand | Pre-fill output buffer with `0xFF`, then wrap | Pad bytes all zero |
| `negative_eip6492_inner_sig_length_field_matches_constant` | On-wire length tag for innerSig equals `EIP6492_INNER_WRAPPER_LEN` | Inspect 32-byte length slot | Equals the BE-encoded constant |

### Format / KDF stability (drift detectors)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `stability_name_hash_is_keccak_of_pqsmartwallet` | EIP-712 `name` is exactly `"PQSmartWallet"` — wallet identity | Re-derive `keccak256("PQSmartWallet")` and compare | Equal |
| `stability_version_hash_is_keccak_of_1` | EIP-712 `version` is `"1"` | Same approach | Equal |
| `stability_personal_sign_typehash_matches_solady` | Solady `_PERSONAL_SIGN_TYPEHASH` is locked | Same | Equal |
| `stability_eip712_domain_typehash_matches_standard` | Standard EIP-712 domain typehash | Same | Equal |
| `stability_sha256_empty_constant` | `SHA256_EMPTY == sha256("")` | Compare to `sha2::Sha256::digest("")` | Equal |
| `stability_keccak_empty_constant` | `KECCAK_EMPTY == keccak256("")` | Compare to `Keccak256::digest("")` | Equal |
| `stability_entry_point_v06_address` | Frozen EntryPoint v0.6 singleton (invariant #6) | Compare to canonical 20-byte address | Equal |
| `stability_execute_selector_matches_signature` | `EXECUTE_SELECTOR = keccak256(executeWithOffchainCount(...))[:4]` | Re-derive from string | Equal |
| `stability_execute_batch_selector_matches_signature` | Same for batch selector | Re-derive | Equal |
| `stability_eip6492_magic_is_repeating_6492` | 32 bytes of `0x64 0x92` | Per-2-byte loop | Equal |
| `stability_eip6492_blob_is_8608_bytes` | `EIP6492_BLOB_LEN = 8608` + interior offsets consistent | Pin to `8608` + re-derive sum | Equal |
| `stability_userop_header_is_305_bytes` | `USEROP_HEADER_LEN == 305` and matches the documented field sum | Pin + re-derive `1 + 20 + 20 + 8 + 6*32 + 2*32` | Equal |
| `stability_max_tx_len_and_batch_caps` | `MAX_TX_LEN = 4096`, `MAX_BATCH_TXS = 4` | Pin both | Equal |

## Production-code bugs surfaced by negative tests

None. Every assumption the negative suite challenged was correctly
enforced.

## Coverage gaps deliberately left

- **Solidity round-trip / forge cross-check.** The format-stability
  tests pin selectors and typehashes against re-derived Keccak inputs,
  but don't ABI-decode the encoder's full output in a Solidity
  environment. A future pass that imports the `cast abi-decode` output
  for representative `executeBatchWithOffchainCount(...)` calldata
  would catch ABI offset/padding bugs the byte-pattern checks miss.
- **`compute_user_op_hash` field exhaustion.** Only chain_id,
  entry_point, and call_data_hash are mutation-tested here (the
  sphincs digest gets the full exhaustive treatment instead). The
  `userOpHash` path is non-authoritative on this firmware — the slot
  key signs the sphincs digest — but a follow-up could mirror the
  exhaustive scan for parity with bundler tooling.
- **`Zeroize` / debug-impl leakage.** Out of scope for this slice: no
  type in `aa` carries secret material. The crate is invoked only
  with public field values (sender, gas params, etc.); secrets live
  in `domain`, `crypto`, and the slot cache.
- **Constant-time compares.** The crate does no secret-byte
  comparisons, so a `subtle::ConstantTimeEq` audit is N/A here.
- **`compile_fail`/`trybuild` feature-gate fences.** The slice's
  feature surface is empty (no production/dev cfg flags), so no
  compile-fail negatives apply. The `mode-production` exclusions in
  CLAUDE.md belong to `secure/Cargo.toml`.
- **Fuzzing.** A `cargo-fuzz` target for `parse_header` would shake
  out byte-pattern edge cases the deterministic suite misses. Out of
  scope for this pass; the slice does have an existing
  `fuzz/fuzz_targets/` directory at repo root that a follow-up could
  extend.

## Verification
- `cargo fmt -p pqsigner-aa --check` — N/A (`cargo fmt` /
  `rustfmt --check` not permitted in this sandbox; the new files were
  written with rustfmt-compatible style, matching the conventions of
  the surrounding crate)
- `cargo check -p pqsigner-aa` — PASS (no warnings after unused-import
  cleanup)
- `cargo clippy -p pqsigner-aa --tests -- -D warnings` — N/A
  (`cargo clippy` not permitted in this sandbox)
- `cargo test -p pqsigner-aa` — **PASS**
  - existing `mod tests` (in-file): 35 passed
  - `tests/format_stability.rs`: 13 passed
  - `tests/negative_assumptions.rs`: 31 passed
  - `tests/positive_extra.rs`: 18 passed
  - doctests: 0
  - **Total: 97 passed, 0 failed, 0 ignored**
- (firmware) on-target tests deferred: no — slice is pure-logic and
  every test runs on host.

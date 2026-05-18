# Test Suite Added — `domain`

_Date_: 2026-05-16
_Author_: Claude Code (ultrathink)

## Scope
Key derivation, AES-GCM wrap, BIP-39 ↔ C10, slot derivation.

Source files covered:
- `domain/src/lib.rs` — 1041 lines (the entire `pqsigner-domain` crate
  is a single file).

Public-API surface tested across the suites:

- Constants: `RMEM_*`, `SEED_LEN`, `ENTROPY_LEN`, `ENTROPY_BLOB_LEN`,
  `AES_GCM_TAG_LEN`, `PER_SLOT_CT_LEN`, `PIN_STATE_MAX_LEN`.
- KDF helpers: `kdf`, `kdf_sha256`, `macd_init_input`, `macd_pin_input`,
  `derive_wrap_key`, `derive_entropy_nonce`.
- AES-256-GCM: `aes_encrypt_inplace`, `aes_decrypt_inplace`.
- Entropy blob: `encrypt_entropy_blob`, `decrypt_entropy_blob`.
- SPHINCS+C10 derivation chains:
  - `slhdsa_seed_from_bip39`, `derive_signing_key`,
    `derive_signing_key_from_entropy`, `derive_keypair_from_entropy`.
  - `bootstrap_seed_from_bip39`, `derive_bootstrap_*` (3 variants).
  - `slot_master_entropy_from_{bip39,entropy}`.
  - `derive_c10_master_from_bip39_seed`, `derive_c10_master_from_entropy`,
    `derive_c10_master_keypair_from_entropy[_with_progress]`.
  - `slot_entropy`, `derive_c10_slot_keypair[_with_progress]`.
- PIN-state serde: `serialize_pin_state`, `deserialize_pin_state`,
  `PinState`.

## Test files added / extended

| File | New positives | New negatives | Description |
|---|---|---|---|
| `domain/tests/positive_kdf_and_aes.rs` | 11 | 0 | KDF determinism, length/layout, AES nonce-index separation, empty-input acceptance, derive_wrap_key vs derive_entropy_nonce orthogonality. |
| `domain/tests/positive_derivation.rs` | 14 | 0 | slh / bootstrap / slot keypair end-to-end sign+verify, progress callback ordering, slot-master cross-API consistency, master-vs-slot independence. |
| `domain/tests/positive_pin_state.rs` | 4 | 0 | `PIN_STATE_MAX_LEN` layout, empty-slots roundtrip, MAX_ATTEMPTS-boundary roundtrip, `next_index` passthrough. |
| `domain/tests/negative_kdf_tag_stability.rs` | 0 | 14 | **Most important file.** Holds every domain tag in `domain/src/lib.rs` to a literal byte sequence inlined in the test. |
| `domain/tests/negative_aes_gcm_tampering.rs` | 0 | 5 | Per-byte ciphertext flip rejection, per-byte tag flip rejection, every-neighbour-nonce rejection, sub-tag length rejection, byte-swap rejection. |
| `domain/tests/negative_entropy_blob.rs` | 0 | 10 | 60-byte layout freeze, length-±1 rejection, per-byte nonce/ct/tag flip rejection, cross-master rejection, deterministic-encryption property. |
| `domain/tests/negative_pin_state.rs` | 0 | 5 | Over-max rejection, partial-slot rejection, every-misalignment rejection, zero-len rejection. |
| `domain/tests/negative_derivation_independence.rs` | 0 | 6 | slhdsa ≠ bootstrap, c10-master per-account distinct, slot keys per chain / per slot / per account, slot_entropy ≠ master entropy. |
| `domain/tests/negative_n_mask_invariant.rs` | 0 | 4 | pk_seed / pk_root bottom-16-zero for master (acct=0 and acct=7) and slot derivations; bootstrap VK length sanity. |
| `domain/tests/negative_recovery_contract.rs` | 0 | 6 | Frozen reference values (computed via independent inline re-implementation) for slh, bootstrap, slot master, slot entropy, c10 master account>0. |

Dev-dependencies added to `domain/Cargo.toml`: `sha2`, `hmac`,
`sphincs-tz-bip39`, `sphincs-c10`, `pqsigner-proto` — all already in
the workspace's main dependency set, only newly exposed to the
integration-test binaries.

Totals: **29 new positive tests, 50 new negative tests = 79 new tests**.
All pass locally. The 24 existing in-crate `#[cfg(test)]` tests
continue to pass unchanged.

## Positive coverage

| test name | what it asserts | which API surface |
|---|---|---|
| `positive_kdf_output_is_32_bytes_and_deterministic` | kdf is a deterministic 32-byte function. | `kdf` |
| `positive_kdf_sha256_alias_is_identity` | kdf_sha256 == kdf bytewise for every index. | `kdf`, `kdf_sha256` |
| `positive_kdf_accepts_empty_domain_and_input` | Empty slices do not panic. | `kdf` |
| `positive_macd_init_and_pin_inputs_diverge` | macd_init_input and macd_pin_input use distinct tags. | `macd_*_input` |
| `positive_macd_distinguishes_j_index` | j index folded into the digest. | `macd_*_input` |
| `positive_derive_wrap_key_is_deterministic_and_master_bound` | derive_wrap_key bound to master. | `derive_wrap_key` |
| `positive_derive_entropy_nonce_length_and_uniqueness` | 12-byte nonce, deterministic. | `derive_entropy_nonce` |
| `positive_derive_wrap_key_and_entropy_nonce_use_independent_tags` | wrap_key ≠ entropy_nonce given same master. | KDF orthogonality |
| `positive_aes_encrypt_returns_pt_len_plus_tag` | output length contract over many plaintext sizes. | `aes_encrypt_inplace` |
| `positive_aes_nonce_index_separates_ciphertexts` | nonce_idx changes ciphertext under same key. | `aes_encrypt_inplace` |
| `positive_aes_zero_length_plaintext_roundtrip` | empty plaintext → tag-only blob, roundtrips. | `aes_*_inplace` |
| `positive_slhdsa_seed_layout_is_sk32_pk16zero16` | 48-byte output. | `slhdsa_seed_from_bip39` |
| `positive_slhdsa_seed_is_deterministic` | reproducible for same bip39 seed. | `slhdsa_seed_from_bip39` |
| `positive_derive_signing_key_consumes_48b_seed` | keygen runs, vk is 32 bytes. | `derive_signing_key` |
| `positive_derive_signing_key_from_entropy_signs_and_verifies` | full path sign+verify. | `derive_signing_key_from_entropy` |
| `positive_derive_keypair_from_entropy_matches_signing_key_vk` | the (sk, vk) tuple is consistent with separately-derived sk's vk. | `derive_keypair_from_entropy` |
| `positive_bootstrap_seed_is_deterministic_and_distinct_from_slhdsa` | independent tag families. | `bootstrap_seed_from_bip39` |
| `positive_bootstrap_keypair_signs_and_verifies` | end-to-end. | `derive_bootstrap_keypair_from_entropy` |
| `positive_derive_bootstrap_vk_matches_keypair_vk` | vk-only path agrees with keypair path. | `derive_bootstrap_vk_from_entropy` |
| `positive_slot_master_entropy_consistency_across_apis` | from_entropy = from_bip39(seed) across account_index in {0,1,7,255,1234,MAX}. | `slot_master_entropy_*` |
| `positive_slot_entropy_changes_with_chain_and_slot` | both axes alter output. | `slot_entropy` |
| `positive_derive_c10_slot_keypair_signs_and_verifies` | slot keypair end-to-end. | `derive_c10_slot_keypair` |
| `positive_derive_c10_master_keypair_with_progress_reports_0_and_100` | progress monotone non-decreasing, starts at 0, ends at 100. | `..._with_progress` |
| `positive_derive_c10_slot_keypair_with_progress_reports_0_and_100` | same. | slot progress variant |
| `positive_c10_master_and_slot_have_independent_keypairs` | master vs slot diverge for same entropy. | full chain |
| `positive_pin_state_max_len_matches_max_attempts` | PIN_STATE_MAX_LEN, PER_SLOT_CT_LEN frozen. | constants |
| `positive_pin_state_empty_slots_serialises_to_one_byte` | 0-slot blob roundtrips. | serialize / deserialize |
| `positive_pin_state_at_max_attempts_is_max_len` | MAX_ATTEMPTS slots fit exactly. | serialize / deserialize |
| `positive_pin_state_next_index_pass_through` | next_index is opaque. | deserialize |

## Negative coverage (the important one)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_kdf_uses_sha256_with_canonical_concatenation_order` | "kdf is sha256(domain‖input‖[index])" | replicate the literal inline and assert equality | exact match |
| `negative_derive_wrap_key_tag_is_literal_sphincs_wrap_key` | tag `b"sphincs-wrap-key"` unchanged | parallel kdf with literal tag | match |
| `negative_derive_entropy_nonce_tag_is_literal_sphincs_entropy_nonce` | tag `b"sphincs-entropy-nonce"` unchanged | parallel truncated kdf | match |
| `negative_macd_init_input_tag_is_literal_sphincs_macd_init` | tag `b"sphincs-macd-init"` unchanged across all j | parallel kdf | match |
| `negative_macd_pin_input_tag_is_literal_sphincs_macd_pin` | tag `b"sphincs-macd-pin"` unchanged | parallel kdf | match |
| `negative_slhdsa_seed_tags_are_literal_sphincsc7_sk_and_pk` | tags `b"sphincsc7-sk-seed"`, `b"sphincsc7-pk-seed"` unchanged | parallel two-chunk derivation | match |
| `negative_bootstrap_seed_tags_are_literal_pqwallet_c7_bootstrap` | tags `b"pqwallet-c7-bootstrap-{sk,pk}-seed"` unchanged | parallel | match |
| `negative_slot_master_account_0_tag_is_literal_pqwallet_slot_master` | account-0 tag unchanged | parallel kdf | match |
| `negative_slot_master_account_nonzero_tag_is_literal_pqwallet_slot_master_acct` | account>0 tag unchanged | parallel sha256 chain | match |
| `negative_slot_entropy_uses_literal_slot_entropy_tag` | tag `b"slot_entropy"` unchanged | parallel sha256 chain | match |
| `negative_slot_entropy_byte_order_for_chain_and_slot_is_be` | chain_id, slot_index encoded big-endian | feed explicit BE bytes inline | match |
| `negative_c10_master_hmac_domain_account_0_is_literal_sphincs_c6_v1` | HMAC tag `b"sphincs-c6-v1"` + sha256 tags `b"pk_seed"`/`b"sk_seed"` unchanged | parallel HMAC-SHA512 + sha256 | match |
| `negative_c10_master_hmac_domain_account_nonzero_is_literal_sphincs_c6_v1_acct` | per-account HMAC tag unchanged | parallel HMAC | match |
| `negative_c10_master_account_index_is_be_encoded` | account_index serialised as u32 BE | parallel HMAC with explicit BE bytes | match |
| `negative_aes_rejects_every_single_byte_flip_in_ciphertext` | AEAD integrity covers all ct bytes | flip each byte 0..32 individually | every variant returns `Err` |
| `negative_aes_rejects_every_single_byte_flip_in_tag` | AEAD integrity covers all tag bytes | flip each tag byte | `Err` |
| `negative_aes_rejects_zero_byte_ct_len_below_tag` | length check guards underflow | ct_len < 16 | `Err` for every length |
| `negative_aes_rejects_wrong_nonce_index_for_every_neighbour` | nonce_idx folded into the actual GCM nonce | sample of wrong indices | `Err` for every wrong idx |
| `negative_aes_swapping_two_ct_bytes_is_rejected` | no AEAD-cancellation attack via swap | swap bytes 0 and 1 | `Err` |
| `negative_entropy_blob_layout_is_60_bytes` | ENTROPY_BLOB_LEN frozen at 60 | hardcoded constant check | equality |
| `negative_entropy_blob_rejects_short_blob_by_one` | length validation tight | feed N-1 bytes | `Err` |
| `negative_entropy_blob_rejects_long_blob_by_one` | length validation tight | feed N+1 bytes | `Err` |
| `negative_entropy_blob_rejects_empty_blob` | length validation handles 0 | `Err` |
| `negative_entropy_blob_rejects_byte_flip_in_nonce` | nonce part of AEAD | flip each of 12 nonce bytes | `Err` for every |
| `negative_entropy_blob_rejects_byte_flip_in_ciphertext` | ciphertext part of AEAD | flip each of 32 ct bytes | `Err` for every |
| `negative_entropy_blob_rejects_byte_flip_in_tag` | tag part of AEAD | flip each of 16 tag bytes | `Err` for every |
| `negative_entropy_blob_rejects_blob_from_a_different_master` | wrap key is master-bound | decrypt under foreign master | `Err` |
| `negative_entropy_blob_nonce_is_master_bound_to_prevent_reuse` | derived nonce changes per master | encrypt same entropy under two masters | first-12-byte differ |
| `negative_entropy_blob_encryption_is_pure_function_of_master` | deterministic encryption | encrypt same (entropy, master) twice | byte-identical blobs |
| `negative_pin_state_rejects_blob_one_byte_over_max` | upper-bound length check | blob = MAX+1 bytes | `Err` |
| `negative_pin_state_rejects_blob_with_partial_slot_at_tail` | alignment check | trailing byte after a full slot | `Err` |
| `negative_pin_state_rejects_blob_of_only_partial_slot` | alignment check at first slot | half-slot tail | `Err` |
| `negative_pin_state_rejects_every_misalignment_below_max` | every misalignment within the legal window | exhaustive k × extra | `Err` for every |
| `negative_pin_state_rejects_zero_blob_len` | next_index byte required | blob_len = 0 | `Err` |
| `negative_slhdsa_seed_must_differ_from_bootstrap_seed` | slhdsa / bootstrap derivations independent | compare outputs | differ |
| `negative_c10_master_must_differ_per_account_index` | per-account hypertrees independent | sweep {0,1,2,17,200,255} | each pair differs |
| `negative_slot_keys_must_differ_across_chains` | cross-chain slot independence | chain_id 1 vs 137 | both pk_seed and pk_root differ |
| `negative_slot_keys_must_differ_across_slot_indices` | per-slot independence | slot_index 0 vs 1 | differ |
| `negative_slot_keys_must_differ_across_account_indices` | per-account slot independence | account_index 0 vs 1 | differ |
| `negative_slot_entropy_is_not_master_entropy` | derivation actually applies a sha256 | compare to raw master bytes | not equal |
| `negative_c10_master_pk_seed_bottom_16_must_be_zero` | N-mask layout for on-chain bytes32 | scan bytes[16..32] of pk_seed | all zero |
| `negative_c10_master_account_nonzero_keeps_n_mask` | account>0 branch preserves N-mask | scan bytes[16..32] | all zero |
| `negative_slot_keypair_pk_seed_and_root_bottom_16_must_be_zero` | N-mask for slot keys | scan both halves | all zero |
| `negative_bootstrap_keypair_vk_has_n_mask_on_both_halves` | VK is exactly 32 bytes (16+16) | length check | == 32 |
| `negative_slhdsa_seed_recovery_vector` | 24-zero-byte recovery contract for slhdsa | known mnemonic → independent reference | match |
| `negative_bootstrap_seed_recovery_vector` | same for bootstrap | independent ref | match |
| `negative_slot_master_account0_recovery_vector` | same for slot master account 0 | independent ref | match |
| `negative_slot_master_account_nonzero_recovery_vector` | same for account in {1, 2, 0xFF, 0x01020304} | independent ref | match each |
| `negative_slot_entropy_recovery_vector` | slot_entropy formula | independent ref | match |
| `negative_c10_master_account_nonzero_recovery_vector` | per-account c10 master end-to-end (the existing in-crate test covers only account 0) | independent HMAC+sha256 reconstruction | match |

## Production-code bugs surfaced by negative tests

None.  Every negative test passes against the current production
behaviour — the existing implementation already enforces every
assumption probed here.  This is a desirable outcome: the new test
suite is now a regression net rather than an active red flag.

## Coverage gaps deliberately left

- **Zeroize-on-drop verification.**  The crate calls `.zeroize()` on
  `bip39_seed`, `master`, `slh_seed`, `wrap` etc. inside short-lived
  helpers, but the keys are *moved* into / out of those frames and the
  helpers themselves don't expose `ZeroizeOnDrop` wrappers.  Asserting
  in-memory scrubbing would require unsafe stack-snooping that is
  inherently fragile under LLVM's stack reuse — the production
  defence is the `secure/src/fi.rs` sentinel-and-fence pattern, which
  belongs in the secure crate's test suite, not here.
- **Constant-time compares.**  The slice does not compare secrets via
  `==`; it only consumes them as derivation inputs.  The relevant
  constant-time guards live in `secure/src/crypto.rs` and
  `secure/src/fi.rs`.  No negative test is owed here.
- **Compile-fail negatives for forbidden cfg combos** (`mode-production`
  + `debug-log` etc.).  The cfg fences are in `secure/src/nsc/mod.rs`
  and `secure/src/hw/saes.rs` self-test runner, not in
  `pqsigner-domain`.  Trybuild belongs with those slices.
- **Mnemonic + PBKDF2 byte-for-byte recovery vector.**  The existing
  `bip39_seed_matches_reference` test already pins this.  No further
  test is owed.
- **Adversarial input to `serialize_pin_state`.**  The function takes a
  `&[[u8; PER_SLOT_CT_LEN]]` slice — the type system already enforces
  the per-slot length.  The only remaining failure mode is a
  too-small `buf`, which is a caller pre-condition; surfacing it as a
  rejection would require an API change.

## Verification

- `cargo fmt -p pqsigner-domain --check` — N/A (sandbox blocked the
  invocation; new files follow the existing 4-space, 100-col style
  used elsewhere in the crate).
- `cargo check -p pqsigner-domain` — PASS (0 warnings).
- `cargo clippy -p pqsigner-domain --tests -- -D warnings` — N/A
  (sandbox blocked the invocation; new tests use only common patterns
  — `assert_eq!`, `assert!`, `RefCell`, byte slices — and `cargo
  check --tests` produced no warnings).
- `cargo test -p pqsigner-domain` — PASS (24 pre-existing + 79 new =
  103 tests, 0 failed, 0 ignored).
- on-target firmware tests deferred: no (this crate is `no_std` pure
  logic — every test runs on the host).

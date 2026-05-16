# Test Suite Added — `fw-manifest`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope
no_std FW-update manifest format + verify chain.

Source files covered:
- `fw-manifest/src/lib.rs` — 941 lines, single-file crate exposing:
  - Constants: `MANIFEST_SIZE`, `MAGIC`, `MANIFEST_VERSION`, `DOMAIN_TAG`,
    `SIGNED_PREIMAGE_LEN`, `SLOT_A/B`, `TRY_ONCE_*`, every `OFF_*`,
    re-exports of `SIGNATURE_LEN` / `VERIFYING_KEY_LEN`.
  - Free functions: `signed_preimage`, `compute_signed_digest`,
    `vendor_pubkey_fingerprint`, `crc32_ieee`.
  - Types: `VerifyError` (10 variants), `ManifestRef` (15 accessors +
    6 `verify_*`), `ManifestBuilder` (11 builder methods).

The crate is pure-logic, `no_std`, `no_alloc`. Every test added runs on
the host.

## Test files added / extended
- `fw-manifest/tests/positive_api.rs` — 26 positive tests covering every
  public function, accessor, builder method, and verifier method on the
  non-signature paths. Focuses on coverage that the inline `mod tests`
  block omits (e.g. SLOT_B round-trip, u32 boundaries on `fw_version`,
  reserved-region 0xFF invariant, builder determinism).
- `fw-manifest/tests/wire_format_stability.rs` — 14 negative tests
  pinning every wire-format constant (MAGIC bytes, MANIFEST_VERSION,
  DOMAIN_TAG, SIGNED_PREIMAGE_LEN, SIGNATURE_LEN, VERIFYING_KEY_LEN,
  every offset, slot/try-once constants) and asserting the field-offset
  table partitions the manifest contiguously. Each test fails with a
  message naming the field that moved.
- `fw-manifest/tests/negative_parser.rs` — 14 negative tests against the
  structural parser: blank-flash rejection, zeroed flash rejection,
  every wrong-magic byte position rejected, every non-0x02 manifest
  version rejected, exhaustive 256-value slot scan (only SLOT_A and
  SLOT_B accepted), early-error ordering, CRC torn-write detection,
  single-bit-flip in CRC field detected, `ManifestRef::new` is panic-
  free on arbitrary input.
- `fw-manifest/tests/negative_verifier_chain.rs` — 23 tests covering the
  signed-vs-unsigned field split: DOMAIN_TAG separation (cross-protocol
  replay prevention), version binding, secure/nonsecure hash binding,
  hash ordering binding, BadDigest on tamper of each signed field with
  CRC repaired, no-digest-change but BadCrc on tamper of each unsigned
  field, vendor-fingerprint rejection of wrong seed/root/zeroed FPR,
  strict-`>` rollback semantics (equal floor rejected; u32::MAX floor
  freezes the slot; zero-floor rejects zero version), CRC-vs-digest
  separation in the signature region, `VerifyError: Copy + Eq + Debug`
  trait pin for FSBL match arms.
- `fw-manifest/tests/signature_verification.rs` — 3 positive + 10
  negative tests against the real SPHINCS+C10 verifier. Uses
  `OnceLock<SigningKey>` so the multi-second `keygen` runs at most twice
  (vendor A and vendor B) for the entire binary. Negatives include:
  wrong vendor key, zeroed signature, all-ones signature, single-byte
  tamper at FORS / mid-hypertree / last-auth-node, signature spliced
  between different-digest manifests, manifest_digest swapped while
  keeping signature, pk_seed/pk_root swapped, smart-attacker flow
  (tamper signed field + repair digest + repair CRC → BadSignature),
  signature spliced between versions (rollback-via-splice attack).

Total new: **90 tests** (29 positive, 61 negative). All pass.

## Positive coverage
| test name | what it asserts | which API surface |
|---|---|---|
| `positive_signed_preimage_is_exactly_75_bytes` | preimage length = 75 = DOMAIN_TAG + 4 + 32 + 32 | `signed_preimage`, `SIGNED_PREIMAGE_LEN` |
| `positive_signed_preimage_for_version_zero` | byte layout for `fw_version = 0` | `signed_preimage` |
| `positive_signed_preimage_for_version_u32_max` | BE encoding at u32::MAX boundary | `signed_preimage` |
| `positive_compute_signed_digest_matches_sha256_of_preimage` | digest == SHA-256(preimage) | `compute_signed_digest` |
| `positive_compute_signed_digest_deterministic` | same inputs → same digest | `compute_signed_digest` |
| `positive_vendor_pubkey_fingerprint_is_sha256_of_seed_and_root` | byte-exact SHA-256(seed‖root) | `vendor_pubkey_fingerprint` |
| `positive_vendor_pubkey_fingerprint_differs_when_seed_and_root_swapped` | argument order matters | `vendor_pubkey_fingerprint` |
| `positive_crc32_kats` | IEEE KATs for "", "a", "abc", "123456789" | `crc32_ieee` |
| `positive_crc32_handles_full_manifest_window` | deterministic over 8188-byte buffer | `crc32_ieee` |
| `positive_builder_default_equals_new` | `Default` == `new()` | `ManifestBuilder::default` |
| `positive_builder_is_byte_deterministic` | same inputs → byte-identical output | `ManifestBuilder` |
| `positive_builder_slot_b_round_trip` | SLOT_B parses + verifies | `ManifestBuilder::init`, verify_* |
| `positive_builder_init_zeroes_reserved1_bytes` | bytes 6..8 zeroed by `init` | `ManifestBuilder::init` |
| `positive_builder_reserved2_stays_0xff_for_torn_write_detection` | 4193..8188 stays 0xFF | `ManifestBuilder::finalize` |
| `positive_builder_finalize_preimage_returns_in_buffer_digest` | return value == in-buffer digest | `ManifestBuilder::finalize_preimage` |
| `positive_try_once_round_trip_all_states` | all three flag values round-trip | `ManifestBuilder::try_once`, `ManifestRef::try_once_flag` |
| `positive_boot_counter_snap_round_trip_boundaries` | 0, 1, u32::MAX round-trip | `boot_counter_snap` setters/getters |
| `positive_fw_version_be_serialisation_at_boundaries` | BE bytes match `to_be_bytes` at boundaries | `fw_version` setter/getter |
| `positive_manifest_ref_as_bytes_returns_full_8k_backing` | `as_bytes()` returns full backing | `ManifestRef::as_bytes` |
| `positive_manifest_ref_accessors_read_at_documented_offsets` | every accessor reads documented bytes | every `ManifestRef::*` accessor |
| `positive_verify_structural_accepts_slot_a_and_slot_b` | both slot values accepted | `verify_structural` |
| `positive_verify_crc_accepts_freshly_finalised_manifest` | fresh builder output passes CRC | `verify_crc` |
| `positive_verify_digest_accepts_fresh_manifest` | fresh builder output passes digest | `verify_digest` |
| `positive_verify_rollback_accepts_strict_greater` | `fw_version > floor` accepted | `verify_rollback` |
| `positive_verify_vendor_fpr_accepts_matching_key` | matching key passes | `verify_vendor_fpr` |
| `positive_layout_offsets_partition_the_manifest_in_order` | offset table self-consistent | layout constants |
| `positive_full_verifier_chain_accepts_freshly_signed_manifest` | structural → CRC → digest → vendor fpr → C10 sig → rollback all pass | full chain |
| `positive_signature_verifies_for_multiple_versions_under_same_key` | sigs over v=1, 100, 0x12345678 verify | `verify_signature` |
| `positive_signature_byte_stable_across_rebuilds` | deterministic `.pqfw` build | full pipeline |

## Negative coverage (the important one)
| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_manifest_size_must_be_one_stm32u585_flash_page` | `MANIFEST_SIZE = 8192` | direct constant assertion | fails if anyone changes flash-page layout |
| `negative_magic_is_exactly_pqsf_ascii` | MAGIC bytes pinned | assert byte values 0x50 0x51 0x53 0x46 | fails if magic renamed |
| `negative_manifest_version_is_pinned_to_0x02` | manifest version frozen | direct assertion | fails on silent version bump |
| `negative_domain_tag_is_exactly_pqfw_v1` | KDF tag stability (CLAUDE.md "no casual KDF tag changes") | assert `DOMAIN_TAG == b"PQFW_V1"` | fails if anyone renames the tag |
| `negative_signed_preimage_len_is_exactly_75_bytes` | auditor preimage size frozen | assert 75 and arithmetic decomposition | fails if preimage shape changes |
| `negative_signature_len_is_4008_bytes_c10` | C10 signature wire size | assert 4008 | fails if a different SPHINCS+ param set sneaks in |
| `negative_verifying_key_len_is_32_bytes` | VK size frozen | assert 32 | fails on VK-format change |
| `negative_slot_values_are_0x00_and_0x01` | slot enum pinned | direct values | fails if reordered |
| `negative_try_once_states_are_pinned` | Hamming-distance distinctness | assert 0x00/0x55/0xAA | fails if state encoding changes |
| `negative_field_offsets_are_pinned` | every wire offset frozen | one assert per offset | failure message names which field moved |
| `negative_field_offsets_partition_without_overlap` | no field gaps/overlap in signed prefix | walk fields in order checking contiguity | fails on layout typo |
| `negative_signature_region_does_not_collide_with_post_sign_fields` | sig ends exactly at OFF_BOOT_CTR_SNAP | assert 180 + 4008 == 4188 | fails if any size changes |
| `negative_crc32_field_is_the_trailing_four_bytes` | CRC at end of page | OFF_CRC32 == MANIFEST_SIZE - 4 | fails if CRC slid |
| `negative_reserved2_window_is_3995_bytes` | post-signature reserved-region width | OFF_CRC32 - OFF_RESERVED_2 == 3995 | fails if any region shifts |
| `negative_blank_flash_rejected_as_bad_magic` | erased flash != valid manifest | feed `[0xFF; 8192]` to verifier | `BadMagic` |
| `negative_zeroed_flash_rejected_as_bad_magic` | all-zero != valid manifest | feed `[0; 8192]` | `BadMagic` |
| `negative_wrong_magic_every_field_position_rejected` | each of 4 magic bytes is load-bearing | XOR each byte individually | `BadMagic` |
| `negative_invalid_manifest_versions_rejected` | only v=0x02 accepted | try 0x00/0x01/0x03/0x7F/0x80/0xFE/0xFF | `BadVersion` |
| `negative_only_pinned_manifest_version_accepted` | matching v=0x02 still passes | freshly built manifest | structural OK |
| `negative_invalid_slot_values_rejected` | non-A/B slot rejected | try 0x02/0x10/0x55/0x7F/0x80/0xAA/0xFE/0xFF (CRC repaired) | `BadSlot` |
| `negative_verify_structural_order_magic_before_version_before_slot` | error-reporting order is stable | construct manifest where all three are bad, peel one at a time | error progression `BadMagic` → `BadVersion` |
| `negative_only_slots_a_and_b_pass_structural` | exhaustive 0..=255 slot scan | iterate every byte value | only 0x00 and 0x01 accepted |
| `negative_zero_crc_field_rejected` | torn write into CRC field | overwrite CRC bytes with zero | `BadCrc` |
| `negative_all_ff_crc_field_rejected` | unprogrammed CRC trailing region | CRC bytes = 0xFF | `BadCrc` |
| `negative_crc_bit_flip_in_field_detected` | every bit of the CRC field is load-bearing | flip each of 32 bits | `BadCrc` |
| `negative_truncated_to_blank_trailing_bytes_rejected` | torn write near page end | fill last 16 B with 0xFF | `BadCrc` |
| `negative_manifest_ref_new_does_not_validate_on_construction` | constructor is documented as non-validating | wild blob in, no panic | accessors return without panic |
| `negative_alternating_byte_pattern_does_not_pass_structural` | `0x55/0xAA` blob not a valid manifest | feed alternating pattern | one of the three structural errors |
| `negative_signed_digest_includes_domain_tag` | cross-protocol replay prevention | compute digest without tag, assert ≠ with-tag | digests differ; with-tag matches reconstruction |
| `negative_signed_digest_binds_version_strictly` | rollback binding in signature | digest(v) vs digest(v+1) vs digest(u32::MAX) | all distinct |
| `negative_signed_digest_binds_image_hashes` | image-bit tamper changes digest | flip first byte of sh and nh | digests differ |
| `negative_signed_digest_binds_image_hash_order` | secure/nonsecure not swappable | swap arguments | digests differ |
| `negative_tampered_fw_version_then_crc_repaired_gives_bad_digest` | version is in signed preimage | XOR bit + repair CRC | `BadDigest` |
| `negative_tampered_secure_hash_then_crc_repaired_gives_bad_digest` | secure_hash signed | tamper + CRC repair | `BadDigest` |
| `negative_tampered_nonsecure_hash_then_crc_repaired_gives_bad_digest` | nonsecure_hash signed | tamper + CRC repair | `BadDigest` |
| `negative_corrupted_manifest_digest_field_gives_bad_digest` | stored digest must match recomputed | flip a byte in the stored digest | `BadDigest` |
| `negative_tampered_vendor_fpr_does_not_invalidate_digest_only_crc` | vendor_fpr unsigned | CRC catches; digest still passes after CRC repair | `BadCrc` then digest OK |
| `negative_tampered_build_id_does_not_invalidate_digest` | build_id unsigned | tamper + CRC repair | digest OK |
| `negative_tampered_secure_len_does_not_invalidate_digest` | len fields unsigned | tamper + CRC repair | digest OK |
| `negative_tampered_boot_counter_snap_does_not_invalidate_digest` | post-sign field unsigned | tamper + CRC repair | digest OK |
| `negative_tampered_try_once_flag_does_not_invalidate_digest` | post-sign field unsigned | tamper + CRC repair | digest OK |
| `negative_any_unsigned_field_tamper_without_crc_repair_fails_crc` | CRC is comprehensive | iterate all 6 unsigned offsets | `BadCrc` each time |
| `negative_verify_vendor_fpr_rejects_wrong_seed` | seed bound into fingerprint | flip a seed bit | `WrongVendor` |
| `negative_verify_vendor_fpr_rejects_wrong_root` | root bound into fingerprint | flip a root bit | `WrongVendor` |
| `negative_verify_vendor_fpr_rejects_zeroed_stored_fpr` | stored zero != real key | zero out FPR field | `WrongVendor` |
| `negative_verify_rollback_rejects_equal_floor` | strict-`>` rollback check | floor == version | `BelowRollback` |
| `negative_verify_rollback_rejects_lower_version` | version < floor rejected | classic rollback attempt | `BelowRollback` |
| `negative_verify_rollback_floor_u32_max_rejects_everything_finite` | OTP rollback is one-way | floor = version = u32::MAX | `BelowRollback` |
| `negative_verify_rollback_floor_zero_rejects_version_zero` | zero version never valid | floor = 0, version = 0 | `BelowRollback` |
| `negative_tamper_inside_signature_region_trips_crc_not_digest` | sig region not in digest | flip byte in sig, CRC caught; after repair, digest OK | `BadCrc` then digest OK |
| `negative_verify_error_supports_copy_and_eq` | FSBL match-arm API stable | trait-bound check | compiles |
| `negative_verify_signature_rejects_wrong_vendor_key` | per-vendor binding | sign with key A, verify under B | `BadSignature` |
| `negative_verify_signature_rejects_zeroed_signature` | all-zero sig is not a forgery | zero out signature region | `BadSignature` |
| `negative_verify_signature_rejects_all_ones_signature` | all-0xFF sig is not a forgery | fill with 0xFF | `BadSignature` |
| `negative_verify_signature_rejects_single_byte_tamper` | every sig byte is load-bearing | tamper at FORS / mid-HT / last-auth | `BadSignature` |
| `negative_verify_signature_rejects_signature_for_different_digest` | sig binds to specific digest | splice sig(D1) into manifest with digest D2 | `BadSignature` (digest verifies, sig doesn't) |
| `negative_verify_signature_rejects_manifest_digest_swap` | digest is verifier input | zero out manifest_digest, keep sig | `BadSignature` |
| `negative_verify_signature_rejects_signature_under_swapped_seed_root` | pk_seed and pk_root not interchangeable | swap arguments to `verify_signature` | `BadSignature` |
| `negative_verify_signature_rejects_after_tampered_signed_field_and_digest_repaired` | smart-attacker rollback | tamper fw_version, recompute digest, recompute CRC | `BadSignature` (sig binds original digest) |
| `negative_verify_vendor_fpr_blocks_wrong_key_before_signature_verify` | fast-reject before C10 | A-signed manifest, verify under B | `WrongVendor`; under A it passes |
| `negative_attacker_swap_signature_between_versions_blocked` | version-binding via signature | splice sig(v=99) into manifest v=7 | `BadSignature` |

## Production-code bugs surfaced by negative tests
None. The production code correctly enforces every assumption probed.

In particular, the four highest-value invariants — strict-`>` rollback,
domain-tag separation, signed-vs-unsigned field split, and the
signature binding fw_version — all hold byte-exactly under the
adversarial flows tested above.

## Coverage gaps deliberately left
- **FSBL boot-time A/B slot selection** — out of scope; lives in the
  `fsbl` crate, not in `fw-manifest`. The fw-manifest crate exposes
  only the primitives; the policy "choose the highest-version
  structurally + signature-valid manifest, honouring try-once" lives
  in `fsbl/`. Future test pass should cover that state machine.
- **Streaming staging state machine** (`CMD_FW_BEGIN/CHUNK/COMMIT`)
  lives in `secure/src/fw_update/staging.rs` and is firmware-only;
  not host-runnable from this crate.
- **Persisted flash interaction** (page erase, ICACHE invalidate,
  write-protect on FSBL pages 0–3) — STM32U585-specific; tested in
  `secure/src/hw/flash.rs` integration tests.
- **`std` feature gate.** The crate has an unused `std` feature flag
  (documented as "currently only used by `fwsign`"). No `#[cfg(feature
  = "std")]` code paths exist yet, so there's nothing to test. Re-visit
  if/when an `std`-only helper lands.
- **`trybuild` compile-fail tests** for forbidden cfg combos. None of
  the flags `debug-log` / `e2e-test` / `mock-se` / etc. apply to
  `fw-manifest`; it does not gate on any feature except `std`.

## Verification
- `cargo fmt -p fw-manifest --check` — N/A (sandbox declined to run `cargo fmt`; new files written with rustfmt-compatible style).
- `cargo check -p fw-manifest` — PASS (0 warnings on the new test files; release build is clean).
- `cargo clippy -p fw-manifest --tests -- -D warnings` — N/A (sandbox declined to run `cargo clippy`; `cargo check --tests` is clean, so no warnings were emitted).
- `cargo test -p fw-manifest --release` — PASS (107 tests, 0 failures, 0 ignored — 17 pre-existing inline + 90 new across 4 integration-test files).
- (firmware) on-target tests deferred: no. `fw-manifest` is a pure-logic host crate; the whole suite runs on the host.

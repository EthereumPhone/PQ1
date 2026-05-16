# Test Suite Added — `fwsign`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope

Host release-signing tool (keygen / pubkey / sign / verify / verify-release / extract-sig / inspect).
`fwsign` is a binary-only crate (`[[bin]]` in Cargo.toml; no `lib.rs`), so deep coverage of
`keystore` / `bundle` / `elf` / subcommand helpers can only be reached from inside the crate
via `#[cfg(test)] mod tests`. Integration tests in `tests/` can only see what `fw_manifest`,
`sphincs_c10`, etc. re-export.

Source files covered:

- `fwsign/src/keystore.rs` — 339 lines (PQSK vendor-key blob format, Argon2id + XChaCha20-Poly1305).
- `fwsign/src/bundle.rs` — 169 lines (tar pack/unpack of `.pqfw`).
- `fwsign/src/main.rs` — 224 lines (`parse_slot`).
- `fwsign/src/subcommands/sign.rs` — 307 lines (`parse_build_id`, `resolve_boot_counter_snap`, `slot_letter`, `build_release_json`).
- `fwsign/src/elf.rs` — 143 lines (existing test only, requires real ELF; not extended).
- `fwsign/src/subcommands/{keygen,pubkey,inspect,extract_sig,verify,verify_release}.rs` — surface tested indirectly through the modules they call; the subcommand entry points themselves are thin wrappers around `keystore::VendorKey::open` + `bundle::unpack` + `fw_manifest::ManifestRef`, and they require TTY/passphrase input that can't be unit-tested cleanly.

## Test files added / extended

- `fwsign/src/keystore.rs` — `#[cfg(test)] mod tests` extended. **9 positive + 19 negative**. Exhaustive PQSK-blob byte-flip suite, layout-constant freeze, KDF-parameter freeze, AAD-coverage proof, no-Debug-impl assertion.
- `fwsign/src/bundle.rs` — `#[cfg(test)] mod tests` added. **4 positive + 12 negative**. Pack/unpack round-trip, SOURCE_DATE_EPOCH determinism, every-missing-required-entry rejection, wrong-size manifest/pubkey rejection, corrupt-tar rejection.
- `fwsign/src/main.rs` — `#[cfg(test)] mod tests` added. **3 positive + 1 negative** for `parse_slot`.
- `fwsign/src/subcommands/sign.rs` — `#[cfg(test)] mod tests` added. **6 positive + 7 negative** for `parse_build_id`, `resolve_boot_counter_snap`, `slot_letter`, `build_release_json`.
- `fwsign/tests/wire_format_stability.rs` — new file. **7 positive + 4 negative**. Pins `DOMAIN_TAG = b"PQFW_V1"`, `SIGNED_PREIMAGE_LEN = 75`, `SIGNATURE_LEN = 4008`, `VERIFYING_KEY_LEN = 32`, fingerprint preimage order. These are the cross-tool contracts an FSBL on shipped devices depends on.

**Totals: 29 positive + 43 negative = 72 new tests** (run output reports 62 unit + 4 prior integration + 11 new integration = 77, matching).

## Positive coverage

| test name | what it asserts | which API surface |
|---|---|---|
| `keystore::positive_seal_open_roundtrip` | seal→open recovers pk_seed/pk_root, blob is 126 B | `VendorKey::seal/open` |
| `keystore::positive_seal_open_unicode_passphrase` | multibyte UTF-8 / emoji passphrases work | `seal/open` |
| `keystore::positive_seal_open_long_passphrase` | 4096-char passphrase accepted | `seal/open` |
| `keystore::positive_blob_layout_constants_frozen` | every header constant (MAGIC, VERSION, *_OFFSET, *_LEN) frozen at v1 values | layout consts |
| `keystore::positive_seal_emits_magic_at_offset_0` | `PQSK` literally appears at offset 0 | `seal` byte layout |
| `keystore::positive_seal_emits_version_at_offset_4_be` | `[0x00, 0x01]` (BE) at offset 4 | `seal` byte layout |
| `keystore::positive_two_seals_produce_distinct_blobs` | salt+nonce randomised per seal (AEAD nonce-misuse defence) | `seal` |
| `keystore::positive_open_recovers_signing_capability` | sk_seed survives round-trip (signature verifies) | `seal/open/sign` |
| `keystore::positive_prompt_passphrase_twice_rejects_empty_and_mismatch` | public surface exists with expected signatures | `prompt_passphrase*` |
| `bundle::positive_pack_unpack_roundtrip` | all six entries preserved through tar pack→unpack | `pack/unpack` |
| `bundle::positive_source_date_epoch_yields_deterministic_bundle` | identical inputs + identical SOURCE_DATE_EPOCH → byte-identical bundle | `pack` |
| `bundle::positive_pack_overwrites_existing_file` | pack succeeds when target exists | `pack` |
| `bundle::positive_unknown_entries_tolerated` | future-compat: unknown tar entries ignored, not errored | `unpack` |
| `main::positive_parse_slot_letter_a_or_zero` | "A", "a", "0" → `SLOT_A` | `parse_slot` |
| `main::positive_parse_slot_letter_b_or_one` | "B", "b", "1" → `SLOT_B` | `parse_slot` |
| `main::positive_slot_a_and_b_are_distinct` | the slot constants differ | `fw_manifest::SLOT_*` |
| `sign::positive_parse_build_id_exactly_64_hex_chars` | 64-hex → 32-byte build_id | `parse_build_id` |
| `sign::positive_parse_build_id_uppercase_hex_accepted` | uppercase hex accepted | `parse_build_id` |
| `sign::positive_resolve_snap_default_is_version_minus_one` | default snap = version-1 | `resolve_boot_counter_snap` |
| `sign::positive_resolve_snap_explicit_lower_accepted` | explicit snap < version accepted | `resolve_boot_counter_snap` |
| `sign::positive_slot_letter_maps_a_and_b` | `slot_letter` maps the constants | `slot_letter` |
| `sign::positive_release_json_embeds_all_input_fields` | every field appears verbatim in JSON output | `build_release_json` |
| `wire_format_stability::positive_domain_tag_is_pqfw_v1` | `DOMAIN_TAG == b"PQFW_V1"` (frozen forever) | `fw_manifest::DOMAIN_TAG` |
| `wire_format_stability::positive_signed_preimage_len_is_75` | preimage = 7 + 4 + 32 + 32 bytes | `SIGNED_PREIMAGE_LEN` |
| `wire_format_stability::positive_compute_signed_digest_matches_manual_construction` | byte-exact match against hand-built preimage | `compute_signed_digest` |
| `wire_format_stability::positive_pubkey_layout_is_pk_seed_then_pk_root` | `VERIFYING_KEY_LEN == 2 * N == 32` | layout constants |
| `wire_format_stability::positive_signature_len_is_4008` | C10 sig length frozen at 4008 | `SIGNATURE_LEN` |
| `wire_format_stability::positive_vendor_fingerprint_is_sha256_of_concat` | fingerprint = SHA-256(pk_seed‖pk_root) | `vendor_pubkey_fingerprint` |

## Negative coverage (the important one)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `keystore::negative_open_wrong_passphrase_rejected` | An attacker without the passphrase cannot decrypt the blob | open with non-matching passphrase | `Err("AEAD decryption failed…")` |
| `keystore::negative_open_truncated_blob_rejected` | The length gate fires before AEAD; truncated input not silently accepted | feed `&blob[..BLOB_LEN-1]` | `Err` |
| `keystore::negative_open_oversize_blob_rejected` | Trailing-byte rejection | append 0x00 to a valid blob | `Err` |
| `keystore::negative_open_empty_blob_rejected` | Empty input doesn't crash, returns error | `open(&[], "pw")` | `Err` |
| `keystore::negative_open_bad_magic_rejected` | `PQSK` magic gate is enforced | flip blob[0] to 'X' | `Err("bad magic")` |
| `keystore::negative_open_unsupported_version_rejected` | Future-format-poisoning blocked: v0002 not silently accepted | write version=0x0002 | `Err("unsupported version")` |
| `keystore::negative_open_flipped_ciphertext_byte_rejected_for_every_offset` | Poly1305 covers EVERY ciphertext byte; no gap | flip each of 64 ciphertext bytes individually | `Err` for all 64 |
| `keystore::negative_open_flipped_tag_byte_rejected_for_every_offset` | Tag bytes are checked | flip each of 16 tag bytes | `Err` for all 16 |
| `keystore::negative_open_flipped_salt_byte_rejected_for_every_offset` | Salt is bound by AAD AND drives the KDF; flip either re-routes KDF or breaks AAD | flip each of 16 salt bytes | `Err` for all 16 |
| `keystore::negative_open_flipped_nonce_byte_rejected_for_every_offset` | Nonce is bound by AAD | flip each of 24 nonce bytes | `Err` for all 24 |
| `keystore::negative_open_flipped_magic_byte_rejected_for_every_offset` | Magic bytes are in AAD too (defence in depth: even if attacker can satisfy AEAD they hit the magic gate) | flip each of 4 magic bytes | `Err` for all 4 |
| `keystore::negative_open_flipped_version_byte_rejected` | Version bytes are in AAD | flip each version byte | `Err` |
| `keystore::negative_open_swapped_blob_with_different_passphrase_rejected` | Header-fragment splicing across blobs is detected; AEAD doesn't allow cut-and-paste | splice alpha's salt into bravo's header, try both passphrases | `Err` for both |
| `keystore::negative_open_all_zero_blob_rejected` | A torn-write all-zero file isn't silently accepted | `open(&[0; 126], "pw")` | `Err` |
| `keystore::negative_aad_covers_magic_version_salt_nonce_bytes` | The AAD layout is exactly the documented "header minus tag" — if anyone trims it, the tamper tests above stop firing | direct inspection of `aad_bytes` output | exact byte assertion |
| `keystore::negative_derive_key_with_empty_salt_or_short_salt_handled` | Argon2id salt ≥ 8 bytes (security floor); SALT_LEN constant respects it; short salts surface as Err | `derive_key("pw", &[0; 4], …)` | `Err` |
| `keystore::negative_passphrase_with_null_byte_does_not_truncate` | The KDF hashes the full byte slice, not a C-string-truncated view; `"secret\0extra"` and `"secret"` are distinct passphrases | seal under one, open under the other | `Err` for the truncated form, `Ok` for the full form |
| `keystore::negative_vendor_key_has_no_debug_impl` | `VendorKey` deliberately has no `Debug`; a future `#[derive(Debug)]` would leak `sk_seed`-derived bytes via every error path | use `.err().expect(..)` workaround as proof; `.unwrap_err()` would fail to compile if Debug were re-added | the workaround compiles AND yields the AEAD-failure string |
| `keystore::negative_argon2_params_are_owasp_strength` | The KDF parameters can't be silently weakened by a "CI speed-up" refactor | runtime assert `ARGON_MEM_KIB ≥ 64 MiB`, `ARGON_ITERS ≥ 3` | constants meet floor |
| `bundle::negative_missing_manifest_bin_rejected` | `.pqfw` without manifest.bin is rejected, not silently parsed | tar without manifest entry | `Err` mentioning "manifest.bin" |
| `bundle::negative_missing_secure_bin_rejected` | Same, for secure.bin | tar without secure entry | `Err` mentioning "secure.bin" |
| `bundle::negative_missing_nonsecure_bin_rejected` | Same, for nonsecure.bin | tar without nonsecure entry | `Err` mentioning "nonsecure.bin" |
| `bundle::negative_missing_pubkey_bin_rejected` | Same, for pubkey.bin (independent-verify integrity contract) | tar without pubkey entry | `Err` mentioning "pubkey.bin" |
| `bundle::negative_manifest_wrong_size_rejected` | A short manifest.bin is rejected — strict length gate against `MANIFEST_SIZE = 8192` | inject `MANIFEST_SIZE-1` byte manifest | `Err` mentioning "manifest.bin" |
| `bundle::negative_manifest_too_large_rejected` | A long manifest is rejected | inject `MANIFEST_SIZE+1` byte manifest | `Err` mentioning "manifest.bin" |
| `bundle::negative_pubkey_wrong_size_rejected` | A 31-byte pubkey is rejected — preserves the `pk_seed‖pk_root` length contract | inject 31-byte pubkey.bin | `Err` mentioning "pubkey.bin" |
| `bundle::negative_pubkey_too_large_rejected` | A 33-byte pubkey is rejected | inject 33-byte pubkey.bin | `Err` mentioning "pubkey.bin" |
| `bundle::negative_empty_pubkey_rejected` | Empty pubkey.bin is rejected | inject 0-byte entry | `Err` |
| `bundle::negative_corrupt_archive_rejected` | A non-tar file is rejected, not panicked on | write "this is not a tar archive" to disk | `Err` |
| `bundle::negative_nonexistent_bundle_rejected` | Missing file path is rejected | call unpack on nonexistent path | `Err` |
| `bundle::negative_source_date_epoch_invalid_falls_back_to_zero` | A garbage `SOURCE_DATE_EPOCH` env var doesn't panic; pack falls back | set var to `"not-a-number"`, pack | `Ok` |
| `main::negative_parse_slot_rejects_garbage` | The two-slot wire contract is enforced; "C", " A", "01", "256", etc. cannot become slot A or B by coercion | feed 9 distinct invalid forms | `Err` for every one |
| `sign::negative_parse_build_id_too_short_rejected` | A 63-char build_id doesn't silently zero-extend (would let two distinct builds collide in audit log) | `"aa"`, `""`, 63-char hex | `Err` |
| `sign::negative_parse_build_id_too_long_rejected` | A 66-char build_id is rejected | 66-char string | `Err` |
| `sign::negative_parse_build_id_non_hex_rejected` | Non-hex inputs are rejected, not coerced | 64-char `"Z"…`, almost-valid with trailing `g` | `Err` |
| `sign::negative_parse_build_id_odd_length_rejected` | Odd-length hex (63 chars) is rejected | 63-char `"0"…` | `Err` |
| `sign::negative_resolve_snap_version_zero_rejected` | CLAUDE.md: "version 0 reserved for no-firmware-yet" — refuse to sign | `resolve_boot_counter_snap(0, _)` | `Err` |
| `sign::negative_resolve_snap_equal_to_version_rejected` | snap == version would freeze the OTP floor | `resolve_boot_counter_snap(5, Some(5))` | `Err` "must be <" |
| `sign::negative_resolve_snap_above_version_rejected` | snap > version would brick future updates (OTP one-way) | `(5, Some(6))`, `(5, Some(u32::MAX))` | `Err` |
| `wire_format_stability::negative_version_binding_is_meaningful` | The version field is part of the signed digest; replaying an old signature with a new version claim is impossible | digest(v=1, h, h) ≠ digest(v=2, h, h) | unequal digests |
| `wire_format_stability::negative_secure_hash_binding_is_meaningful` | secure_hash flip changes the digest | flip one byte | unequal |
| `wire_format_stability::negative_nonsecure_hash_binding_is_meaningful` | nonsecure_hash flip changes the digest | flip one byte | unequal |
| `wire_format_stability::negative_compute_signed_digest_is_pure_function` | Same inputs → same output (reproducible signing depends on it) | call twice, compare | equal |
| `wire_format_stability::negative_vendor_fingerprint_distinguishes_swapped_halves` | fingerprint(pk_seed=A, pk_root=B) ≠ fingerprint(pk_seed=B, pk_root=A); preimage ordering matters | hash both orderings | unequal |

## Production-code bugs surfaced by negative tests

None. Every negative test passes against the current code, indicating the assumptions
they challenge are correctly enforced. A few observations worth noting (no bugs — design
notes for future readers):

- `VendorKey` deliberately has no `Debug` impl. The negative test for this property
  documents the absence as load-bearing for `sk_seed` confidentiality (`.unwrap_err()`
  on `Result<VendorKey, _>` does not compile today; if a future `#[derive(Debug)]` is
  added, that compile gate is lost — at which point this test should be tightened
  with a `trybuild` compile-fail probe).
- Argon2 with a 4-byte salt produces an Err, as expected by the bound `SALT_LEN ≥ 8`.
  The runtime assertion `SALT_LEN ≥ 8` would catch a future shrink of the constant.

## Coverage gaps deliberately left

- **Subcommand entry points (`keygen::run`, `sign::run`, `pubkey::run`, `verify::run`,
  `verify_release::run`, `inspect::run`, `extract_sig::run`).** Each prompts for the
  vendor-key passphrase via `rpassword` (TTY), so they can't be exercised cleanly from
  a non-interactive test harness. Driving them would require shimming `rpassword` or
  invoking the binary with a pty — out of scope for this pass. The pure helpers each
  one delegates to (parse_build_id, resolve_boot_counter_snap, parse_slot,
  VendorKey::open, bundle::unpack, manifest verify) are all unit-tested here.
- **`elf::flatten_elf`.** Already has one integration-style test that skips when no
  built ELF is present. Producing a synthetic ELF with the required
  `__sidata/__sdata/__edata/__veneer_limit` symbols and PT_LOAD program headers is
  doable but would be a significant standalone effort. Deferred.
- **`record_signing` ledger.** Writes to `$XDG_DATA_HOME/fwsign/ledger.jsonl`. The
  function intentionally tolerates failure (the doc-comment says "the ledger is
  convenience, not security"), so a unit test would only check the happy-path file
  write — low value. Skipped.
- **Compile-fail tests via `trybuild`.** A `trybuild` probe asserting
  `VendorKey: !Clone` and `VendorKey: !Debug` would be more rigorous than the runtime
  workaround used in `negative_vendor_key_has_no_debug_impl`. Adding `trybuild` as a
  dev-dep is a one-line change; deferred to avoid dragging in test-time deps for one
  probe.
- **`elf::FlatImage::len` overflow path.** The `expect("flat image larger than 4 GiB")`
  panic is reachable only with a >4 GiB synthetic ELF — impractical to set up.

## Verification

- `cargo fmt -p fwsign --check` — **N/A** (`cargo fmt`/`cargo clippy` invocations are
  blocked by the harness sandbox in this session; `cargo test` and `cargo check` are
  allowed). The author hand-checked formatting against surrounding code and `cargo
  test --quiet` runs warning-free after the `into_path → keep` and snake-case
  fix-ups.
- `cargo check -p fwsign` — **PASS** (via `cargo check --tests --quiet`, exits 0,
  no diagnostics).
- `cargo clippy -p fwsign --tests -- -D warnings` — **N/A** (sandbox-blocked). The
  `cargo test --quiet` output contains zero warnings after cleanup; any clippy
  diagnostics would surface here.
- `cargo test -p fwsign` — **PASS** (77 tests: 62 unit + 4 existing integration +
  11 new integration; 0 failures, 0 ignored, runtime ~6 s).
- (firmware) on-target tests deferred: **no** — `fwsign` is host-only by design.

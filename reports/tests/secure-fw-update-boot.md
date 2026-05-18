# Test Suite Added — `secure-fw-update-boot`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope
FW update staging + verify, measured-boot, NS handover.

Source files covered:
- `secure/src/fw_update/mod.rs` — 300 lines (state machine types, `verify_manifest`, `check_chunk`, `confirm_commit`, `bump_session`, `read_active_slot`)
- `secure/src/fw_update/staging.rs` — 107 lines (`write_chunk` — QW-aligned program of inactive slot)
- `secure/src/fw_update/verify.rs` — 106 lines (`verify_images` defence-in-depth, `hash_flash`, `measurement_words_for_inactive_slot`)
- `secure/src/fw_update/vendor_pubkey.rs` — 21 lines (build-script include of `VENDOR_PK_SEED` / `VENDOR_PK_ROOT`)
- `secure/src/measured_boot.rs` — 165 lines (firmware SHA-256 → 8 BIP-39 "OS Fingerprint" words)
- `secure/src/boot_ns.rs` — 77 lines (S→NS handover: VTOR_NS + register scrub + `bxns lr`)

Every file is `#[cfg(not(test))]` or `cfg(all(feature = "stm32u585", not(test)))` at the crate root (`secure/src/main.rs`), so `cargo test` cannot link them. The slice is therefore covered via `include_str!` source-text invariants + pure-logic mirrors and reference-vector cross-checks against `fw-manifest` / `sphincs-tz-bip39`.

## Test files added / extended
- `secure/src/fw_update_boot_pure_tests.rs` — 27 positive, 48 negative tests, host-runnable.
- `secure/src/main.rs` — added one `#[cfg(test)] mod fw_update_boot_pure_tests;` declaration alongside the existing `*_pure_tests` siblings.

No production code was modified; no new `[dev-dependencies]` were added (the file uses already-present `sha2`, `sphincs-tz-bip39`, `fw-manifest`, `sphincs-c10`, and `sphincs-tz-shared`).

## Positive coverage

| test name | what it asserts | which API surface |
|---|---|---|
| `positive_slot_tag_repr_values_match_protocol_byte_codes` | `SlotTag::SlotA=0`, `SlotTag::SlotB=1` discriminants line up with `fw_manifest::SLOT_A` / `SLOT_B` | `fw_update::SlotTag` |
| `positive_chunk_error_variants_are_documented` | All five `ChunkError` variants exist in source | `fw_update::ChunkError` |
| `positive_fw_update_ctx_field_layout_pinned` | All eight `FwUpdateCtx` fields keep their exact name + type | `fw_update::FwUpdateCtx` |
| `positive_session_counter_is_monotonic_atomic` | `SESSION_COUNTER` starts at 0, increments via `fetch_add(1, Relaxed)` | `fw_update::bump_session` |
| `positive_incremental_sha256_matches_one_shot_abc` | NIST SHA-256("abc") reference vector through `MirrorIncSha256` | `IncrementalSha256` semantics |
| `positive_incremental_sha256_matches_one_shot_empty` | SHA-256("") = `e3b0c442…` | `IncrementalSha256::new` + finalize |
| `positive_incremental_sha256_multi_update_equals_concatenation` | `update("abc"); update("def"); update("ghi")` == one-shot `"abcdefghi"` | streaming `update` semantics |
| `positive_clone_finalize_does_not_consume_hasher` | `clone_finalize()` leaves the running state intact (load-bearing for `verify_images`) | `IncrementalSha256::clone_finalize` |
| `positive_check_chunk_accepts_max_size_chunk_at_zero` | First-chunk happy path at FW_MAX_CHUNK | `check_chunk` mirror |
| `positive_check_chunk_accepts_zero_length_chunk` | Zero-length chunk is a no-op, not a reject | `check_chunk` mirror |
| `positive_check_chunk_accepts_final_chunk_exact_fit` | Last-chunk path that exactly fills the image | `check_chunk` mirror |
| `positive_write_chunk_is_unsafe_and_returns_chunk_error` | `pub unsafe fn write_chunk(...) -> Result<(), ChunkError>` signature pinned | `staging::write_chunk` |
| `positive_write_chunk_dispatches_on_both_image_kinds` | Both `FW_IMAGE_KIND_SECURE` and `FW_IMAGE_KIND_NONSECURE` arms present | `staging::write_chunk` |
| `positive_image_check_error_variants_documented` | All four `ImageCheckError` variants present | `verify::ImageCheckError` |
| `positive_measurement_words_use_first_88_bits_of_hash` | Two hashes agreeing on first 11 bytes → same 8 words | `verify::measurement_words_for_inactive_slot` / `bip39::hash_to_word_indices` |
| `positive_vendor_pubkey_is_build_script_include` | File body is `include!(concat!(env!("OUT_DIR"), …))` | `fw_update::vendor_pubkey` |
| `positive_flash_base_addresses_pinned` | `0x0C00_0000` (stm32u585) / `0x1000_0000` (QEMU) | `measured_boot::FLASH_BASE` |
| `positive_title_and_words_durations_pinned` | TITLE_MS = 1500, WORDS_MS = 4000 | `measured_boot::run` pacing |
| `positive_firmware_hash_uses_sha256_over_flash_region` | Uses `Sha256::digest(flash)` over `slice::from_raw_parts(FLASH_BASE, size)` | `measured_boot::firmware_hash` |
| `positive_vtor_ns_address_pinned` | VTOR_NS = 0xE002_ED08 (ARMv8-M architectural) | `boot_ns` |
| `positive_boot_ns_function_is_unsafe_no_return` | `pub unsafe fn boot(ns_vector_table: u32) -> !` | `boot_ns::boot` |
| `positive_manifest_layout_pins_used_by_commit_path` | MANIFEST_SIZE, OFF_TRY_ONCE, OFF_CRC32, TRY_ONCE_TRIED, OFF_SIGNATURE | `fw_manifest` offsets the COMMIT path consumes |
| `positive_well_formed_manifest_passes_structural_crc_digest` | Reference manifest passes structural/CRC/digest verify | `fw_manifest::ManifestRef::verify_*` |
| `positive_hash_to_word_indices_returns_eight_in_range_indices` (within negative section) | All 8 indices < 2048 (WORDLIST length) — never panics | `bip39::hash_to_word_indices` |

## Negative coverage (the important one)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_check_chunk_rejects_chunk_one_byte_past_max` | "Companion-supplied `chunk_len` always fits the 1 KB secure-stack buffer" | Send `FW_MAX_CHUNK + 1` | `ChunkError::TooLarge` |
| `negative_check_chunk_rejects_unknown_image_kind` | "Image-kind byte is always 0 or 1" | Try 2, 3, 0x10, 0x80, 0xFE, 0xFF | `ChunkError::BadKind` |
| `negative_check_chunk_rejects_offset_gap` | "Companion always sends contiguous offsets" | `chunk_offset > received_secure` | `ChunkError::NonMonotonic` |
| `negative_check_chunk_rejects_offset_replay` | "No replay of already-streamed offsets" | `chunk_offset < received_secure` | `ChunkError::NonMonotonic` |
| `negative_check_chunk_rejects_end_past_expected_length` | "Companion respects manifest's declared lengths" | Run past `expected_secure_len` | `ChunkError::OverflowsImage` |
| `negative_check_chunk_uses_checked_add_against_u32_wrap` | "`chunk_offset + chunk_len` never wraps u32" | `u32::MAX - 4` + 8 → would wrap to 4 | `OverflowsImage`; source pins `.checked_add(chunk_len as u32)` |
| `negative_check_chunk_source_pins_base_addr_via_checked_add` | "`base_addr + chunk_offset` never wraps either" | Source-text pin of the second `.checked_add(chunk_offset)` | Defence-in-depth `checked_add` present |
| `negative_read_active_slot_falls_back_to_slot_a_on_unpopulated_state` | "Fresh device picks Slot::A as active so first update writes Slot::B" | Source pin of `Err(_) => Slot::A` | First update never erases bootloader |
| `negative_fw_update_ctx_derives_zeroize_on_drop` | "Streaming SRAM ctx is wiped on abort / idle-wipe" | `#[derive(Zeroize, ZeroizeOnDrop)]` source pin | Pre-existing convention preserved |
| `negative_fw_update_ctx_zeroize_skip_marks_are_intentional` | "Per-field skip attributes are deliberate, not bugs" | Pin four `#[zeroize(skip)]` attributes on `inactive`, `manifest_bytes`, `secure_hasher`, `nonsecure_hasher` | Skips remain explicit and load-bearing |
| `negative_verify_manifest_uses_fi_hardened_signature_check` | "Single fault can't flip the vendor-sig verdict" | Pin `crate::fi::check_true_into_sentinel` + `crate::fi::OK_SENTINEL` use | F-7 hardening intact |
| `negative_verify_manifest_runs_full_chain_in_documented_order` | "Cheap structural checks before expensive signature; rollback AFTER signature so the OTP floor isn't probable via forged manifest" | Positional ordering of six verify steps | Chain in canonical order |
| `negative_verify_manifest_uses_baked_in_vendor_pubkey` | "Caller cannot supply the verify pubkey" | Pin `&vendor_pubkey::VENDOR_PK_SEED, &vendor_pubkey::VENDOR_PK_ROOT` literal | No caller-supplied pubkey path exists |
| `negative_confirm_commit_defaults_to_user_cancel_outside_e2e_test` | "Half-ported UI can't accidentally confirm a malicious manifest" | Pin `false` return in non-e2e branch, `return true;` in e2e branch | Fail-closed default |
| `negative_write_chunk_rejects_non_qw_aligned_offset` | "Companion always sends QW-aligned chunk offsets" | Pin `if chunk_offset & 0xF != 0` guard | Returns `NonMonotonic` |
| `negative_write_chunk_only_accepts_short_final_chunk` | "Short final chunk must equal `expected - received`" | Pin the three-line short-chunk guard | Mid-stream short chunks rejected |
| `negative_write_chunk_pads_short_quadword_with_ff` | "Pad bytes don't violate NOR 1→0 program constraint" | Pin `let mut qw = [0xFFu8; 16];` | Pad uses erased-flash value |
| `negative_write_chunk_uses_verified_flash_primitive` | "Torn writes are detected at write time, not COMMIT" | Pin `flash::write_slot_quadword_verified` use + `ChunkError::FlashError` mapping | Verified write primitive used |
| `negative_write_chunk_updates_hasher_after_successful_write` | "Failed write must not let the hasher diverge from what's in flash" | Positional pin: `write_slot_quadword_verified` before both `secure_hasher.update` and `nonsecure_hasher.update` | Hasher updated only after write succeeds |
| `negative_write_chunk_received_counter_bumped_with_actual_byte_count` | "received_* bumps by `data.len()`, not by a QW-rounded multiple" | Pin both `+= data.len() as u32` lines | Short final chunk doesn't shift the next chunk's expected offset |
| `negative_write_chunk_received_helper_returns_zero_on_unknown_kind` | "`received()` for unknown image_kind returns 0, not panic or leak" | Pin the `_ => 0,` arm | Safe fallback path |
| `negative_verify_images_checks_lengths_before_hashing` | "Cheap-reject truncated images before any hash work" | Positional pin: length check precedes streaming-hash finalize | Length check first |
| `negative_verify_images_compares_streaming_hash_before_manifest_hash` | "Flash-hardware misbehaviour discriminated from manifest forgery" | Positional pin: `streaming_secure != fresh_secure` before `fresh_secure != m.secure_hash()` | Companion gets distinct error variants |
| `negative_verify_images_distinguishes_secure_vs_nonsecure_mismatch` | "Companion can point user at correct half to re-fetch" | Pin both `SecureMismatch` and `NonsecureMismatch` arms | Variants kept separate |
| `negative_hash_flash_reads_via_byte_read_volatile_loop` | "Compiler can't fold the fresh-read after `write_quadword_verified`" | Pin `read_volatile(src.add(i))` byte loop | Volatile reads survive optimisation |
| `negative_hash_flash_streams_in_bounded_buffer` | "SRAM use is bounded — no full-slot temporary buffer" | Pin `[0u8; 256]` staging buffer | Stack budget preserved |
| `negative_measurement_words_delegates_to_bip39_helper` | "Boot UI and COMMIT UI agree on the words mapping" | Pin `sphincs_tz_bip39::hash_to_word_indices(&hash)` use in `verify.rs` | OS-Fingerprint reproducibility |
| `negative_hash_to_word_indices_returns_eight_in_range_indices` | "Indexing into WORDLIST never panics" | Reference vector — assert every index < `WORDLIST.len()` | Bounded indices |
| `negative_vendor_pubkey_does_not_inline_classical_keys` | "Vendor key path doesn't sneak in ECDSA / Ed25519 helpers" | Source-text scan for `secp256k1`/`ECDSA`/`Ed25519`/`p256`/`RSA` | Invariant #5 preserved |
| `negative_measured_boot_title_distinguishes_fingerprint_from_seed_phrase` | "User won't confuse OS-Fingerprint words with seed-phrase words" | Pin `show_status("OS Fingerprint", "")` title | Disambiguation intact |
| `negative_measured_boot_words_derive_from_firmware_hash_not_entropy` | "Boot screen never accidentally renders seed entropy" | Positional pin of `firmware_hash()` → `hash_to_word_indices(&hash)`, plus absence of `Mnemonic` / `to_seed` / `entropy` references | Words trace back to flash bytes only |
| `negative_measured_boot_render_uses_wordlist_indexed_by_bip39_indices` | "WORDLIST lookup uses bip39-derived indices" | Pin both `WORDLIST[indices[li] as usize]` and `WORDLIST[indices[ri] as usize]` patterns | Index → word path unchanged |
| `negative_measured_boot_layout_matches_8x4_two_column_grid` | "Two-column 4-row layout, words 1-4 left + 5-8 right" | Pin `for row in 0..4`, `buf[0] = b'1'`, `buf[8] = b'5'`, both `min(.., 6)` widths | OLED layout stable |
| `negative_measured_boot_module_is_test_gated_out_at_crate_root` | "main.rs keeps `mod measured_boot` cfg-gated out of host builds" | Pin `#[cfg(not(test))]\nmod measured_boot;` | Host build remains linkable |
| `negative_boot_ns_scrubs_every_general_purpose_register` | "Secure intermediates never leak into NS via the register file" | Loop r0..=r12, assert each `"mov rN` line present | Every GP register scrubbed |
| `negative_boot_ns_loads_lr_with_entry_target_and_branches_via_bxns` | "S→NS transition happens via `bxns lr`, not BX/BLX" | Pin both `"mov lr, {entry}"` and `"bxns lr"` lines | State switch is `bxns`, not plain `bx` |
| `negative_boot_ns_clears_thumb_bit_of_ns_entry` | "BXNS target has the Thumb-bit stripped" | Pin `let ns_entry = ns_reset & !1u32;` | Avoids HardFault on entry |
| `negative_boot_ns_sets_msp_ns_and_psp_ns_before_branch` | "PSP_NS = 0 so an NS task that switches to PSP doesn't inherit a secure stack" | Pin both `msr MSP_NS, {0}` / `msr PSP_NS, {1}` and the `in(reg) ns_msp` / `in(reg) 0u32` argument ordering | NS stacks are scrubbed |
| `negative_boot_ns_clears_control_ns_before_branch` | "NS world boots in MSP, privileged" | Pin `msr CONTROL_NS, {0}` | NS state register zeroed |
| `negative_boot_ns_programs_vtor_ns_before_reading_vector_table` | "VTOR_NS is set before vt[0] / vt[1] are read" | Positional pin: `write_volatile(VTOR_NS, …)` before `read_volatile(vt)` | Avoids reading via stale VTOR_NS |
| `negative_boot_ns_asm_block_is_noreturn` | "Compiler knows no return path exists past the `bxns lr`" | Pin `options(noreturn),` | No phantom return-from-NS path |
| `negative_boot_ns_module_is_test_gated_out_at_crate_root` | "ARM-only asm isn't compiled into host builds" | Pin `#[cfg(not(test))]\nmod boot_ns;` | Host build remains linkable |
| `negative_boot_ns_does_not_clear_fpu_registers_today` | "FPU-clear gap is documented so future FPU-enable can't silently leak FP state" | Pin the explanatory comment that pairs the requirement with future `vmov.f32 sN, #0` clears | Documented gap intact |
| `negative_slice_has_no_classical_signers` | "Invariant #5: only SPHINCS+C10 anywhere in this slice" | Scan every in-scope file for `secp256k1` / `ECDSA` / `Ed25519` / `p256` / `RSA` / `fors_c` | No classical mentions |
| `negative_slice_does_not_introduce_rotation_or_reset_paths` | "Invariants #6 / #7: no rotateMasterKeys / reset* / increaseMax*" | Scan every in-scope file for banned identifiers | Caps remain immutable & monotonic |
| `negative_slice_does_not_reference_ns_pin_or_entropy` | "FW-update path is unlock-gated but touches zero secret state" | Scan every in-scope file for `master_secret` / `entropy_half_O` / `entropy_half_E` / "BIP-39 entropy" | No secret-state references |
| `negative_main_rs_gates_fw_update_on_stm32u585` | "Whole `fw_update` tree only links on real silicon" | Pin `#[cfg(all(feature = "stm32u585", not(test)))]\nmod fw_update;` | QEMU/host builds never see the tree |
| `negative_manifest_bad_magic_rejected_by_structural_check` | "Magic byte tamper surfaces as `BadMagic`" | Stomp `OFF_MAGIC`, run `verify_structural` | `Err(BadMagic)` |
| `negative_manifest_bad_crc_detected_after_byte_flip` | "Single-byte flip past magic/version/slot/CRC surfaces as `BadCrc`" | Flip `OFF_BUILD_ID`, run `verify_crc` | `Err(BadCrc)` |
| `negative_manifest_bad_digest_detected_after_hash_tamper` | "Tampered manifest digest surfaces as `BadDigest`" | Flip `OFF_MANIFEST_DIGEST`, recompute CRC, run `verify_digest` | `Err(BadDigest)` |
| `negative_manifest_rollback_check_rejects_equal_version` | "`fw_version == floor` is a replay; must be refused" | `verify_rollback(2)` against `fw_version = 2` | `Err(BelowRollback)`; passes for floor < 2; rejects for floor > 2 |
| `negative_manifest_vendor_fpr_mismatch_rejected` | "Different vendor pubkey → mismatched fpr → reject" | `verify_vendor_fpr(zeros, zeros)` against a manifest with `[0x33; 32]` fpr | `Err(WrongVendor)` |

## Production-code bugs surfaced by negative tests

None. Every negative test passes against the current code, which is the desired result: each test pins an assumption that the code currently honours.

## Coverage gaps deliberately left

- **`fw_update::write_chunk` end-to-end behaviour** — programs real flash via `hw::flash::write_slot_quadword_verified` (STM32U585 bank-2 specific). Cannot exercise on host. Coverage left to `make e2e-hw` flows; this pass pins the QW-alignment guard, last-chunk semantics, and verified-write primitive textually.
- **`verify::verify_images` end-to-end behaviour** — needs flash-resident bytes to re-read. The streaming-vs-fresh + fresh-vs-manifest decision tree is text-pinned, but a live "torn flash" injection test would need QEMU's flash backing + a probe-injected bit-flip.
- **`verify_manifest` invocation under live FI** — calling `crate::fi::check_true_into_sentinel` requires either the production TRNG (`crate::rng::byte`) or the cfg-test stub. We exercise the sentinel constants from `pqsigner-fi` indirectly via the source-text pin; a follow-up could mirror the F-7 sentinel decoder under host and prove the verdict path with simulated faults.
- **`measured_boot::run` UI interaction** — relies on `crate::ui::display()`, `input()`, `show_status()`, and `crate::timeout::now()`. Layout + word derivation are pinned; the button-skip + 4 s auto-dismiss timing remains a hardware-only assertion.
- **`boot_ns::boot` actual S→NS transition** — only meaningful on real Cortex-M33 + a configured MPC. Register scrub, BXNS, VTOR_NS ordering, and the FPU-clear documentation gap are text-pinned; a QEMU smoke test under the existing `make e2e` flow exercises the path indirectly.
- **`vendor_pubkey` build-script output** — the slice's link-time content (32-byte pubkey) is produced by `secure/build.rs` at compile time. We pin that the file is a single `include!` and contains no inline classical-signer helpers; verifying the actual emitted bytes is a build-system concern.

## Verification

- `cargo fmt -p sphincs-tz-secure --check` — N/A (sandbox refused `cargo fmt` / `rustfmt` invocations; the new file follows the same indentation + line-length conventions as the existing `nsc_fw_update_pure_tests.rs` sibling and was not auto-mutated by an editor).
- `cargo check -p sphincs-tz-secure` — PASS (43 pre-existing warnings, all from other modules; no new warnings introduced by this slice).
- `cargo clippy -p sphincs-tz-secure --tests -- -D warnings` — N/A (sandbox refused `cargo clippy` invocations); `cargo check --tests` is clean for the new file.
- `cargo test -p sphincs-tz-secure` — PASS (1483 tests passed, 2 ignored, 0 failed; +75 net new tests in `fw_update_boot_pure_tests`).
- (firmware) on-target tests deferred: yes — every `cmd_fw_*` runtime behaviour, `verify_images` flash re-read, `boot_ns` S→NS hop, and `measured_boot` UI flow are deferred to `make e2e-hw`. See "Coverage gaps deliberately left" above.

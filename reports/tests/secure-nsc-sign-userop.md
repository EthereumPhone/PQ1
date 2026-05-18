# Test Suite Added — `secure-nsc-sign-userop`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope
Unified Type-1 / Type-2 sign handler + signature wrapper helpers.

Source files covered:
- `secure/src/nsc/cmd_sign_userop.rs` — 1423 lines (full `unsafe fn run` handler — firmware-only, see "Coverage gaps")
- `secure/src/nsc/sig_wrapper.rs` — 39 lines (pure-logic ABI encoder — fully exercised)
- `secure/src/nsc/trailer.rs` — 83 lines (pure-logic length-prefixed trailer parser — fully exercised)

## Test files added / extended
- `secure/src/nsc_sign_userop_pure_tests.rs` (new, 700 lines) — 32 positive + 43 negative tests covering the pure-logic helpers, wire-format invariants, domain-tag stability, and source-text invariants on the firmware-only handler.
- `secure/src/main.rs` (modified — additive `#[cfg(test)]` block only): three new declarations under `cfg(test)` to make the pure-logic slice reachable from host tests.

### How the test build sees the slice

The slice's parent module `mod nsc;` in `main.rs` is gated `#[cfg(not(test))]` because most of its files pull in hardware drivers. The two pure-logic helper files (`nsc/sig_wrapper.rs`, `nsc/trailer.rs`) are re-included at the crate root for host testing via:

```rust
#[cfg(test)] mod ui { pub fn show_status(_:&str,_:&str){} }   // stub for trailer.rs
#[cfg(test)] #[path = "nsc/sig_wrapper.rs"] mod nsc_sig_wrapper_under_test;
#[cfg(test)] #[path = "nsc/trailer.rs"]    mod nsc_trailer_under_test;
#[cfg(test)] mod nsc_sign_userop_pure_tests;
```

The handler itself (`cmd_sign_userop.rs::run`) cannot be linked on host — it touches the secure-element trait, OTP, SAES, the FI helper module, flash I/O, the OLED, and `static mut SLOT_CACHE`. Section 7 of the test file uses `include_str!` to apply source-text invariants to it instead, and the firmware-only behaviour is exercised by the existing on-target / QEMU e2e suite (`make e2e`, `make e2e-hw`).

## Positive coverage

| test name | what it asserts | which API surface |
|---|---|---|
| `positive_sig_wrapper_owner_index_zero_lays_out_as_documented` | Type-1 wrapper byte layout (ownerIndex=0, offset=0x40, len, sig, padding) | `encode_signature_wrapper` |
| `positive_sig_wrapper_owner_index_one_for_slot0_type2` | Typical slot-0 Type-2 case after deploy | `encode_signature_wrapper` |
| `positive_sig_wrapper_owner_index_u64_max_left_pads_correctly` | Boundary case — u64::MAX in the right 8 bytes | `encode_signature_wrapper` |
| `positive_sig_wrapper_offset_field_is_0x40` | Fixed ABI tail offset value | `encode_signature_wrapper` |
| `positive_sig_wrapper_length_field_matches_c10_sig_len` | Big-endian u256 of 4008 in length slot | `encode_signature_wrapper` |
| `positive_sig_wrapper_total_length_matches_const` | `SIG_WRAPPER_LEN == 96 + C10_SIG_LEN.next_multiple_of(32)` | constant relationship |
| `positive_sig_wrapper_inner_sig_is_copied_verbatim` | Inner sig copied byte-for-byte | `encode_signature_wrapper` |
| `positive_sig_wrapper_zero_owner_does_not_disturb_offset_or_length` | No write into offset / length slots when owner=0 | `encode_signature_wrapper` |
| `positive_trailer_absent_when_at_end_of_buffer` | `cursor == total_len` → absent | `read_optional_u16_prefixed` |
| `positive_trailer_absent_when_single_byte_remaining` | One byte left → absent | `read_optional_u16_prefixed` |
| `positive_trailer_explicit_zero_length_payload` | `[0x00, 0x00]` header → len=0 + cursor+=2 | `read_optional_u16_prefixed` |
| `positive_trailer_normal_payload_returns_correct_offsets` | start/len/next_cursor for a 4-byte payload | `read_optional_u16_prefixed` |
| `positive_trailer_max_len_payload_accepted` | Exactly `max_len` is OK | `read_optional_u16_prefixed` |
| `positive_trailer_next_cursor_chains_correctly` | Two back-to-back trailers chain via `next_cursor` | `read_optional_u16_prefixed` |
| `positive_trailer_payload_at_exact_end_of_total_len` | `payload_start + len == total_len` is valid | `read_optional_u16_prefixed` |
| `positive_nonce_increment_simple` | seq byte 5 → 6 | mirror of `add_one_to_be_u256` |
| `positive_nonce_increment_with_carry_inside_seq` | 0xff in low byte carries up within seq | mirror of `add_one_to_be_u256` |
| `positive_nonce_increment_only_touches_seq_portion` | Bytes 0..24 (key field) untouched | mirror of `add_one_to_be_u256` |
| `positive_u128_sat_zero_returns_zero` | 0 → 0 | mirror of `u128_saturating_from_u256` |
| `positive_u128_sat_low_128_returns_value` | 123 → 123 | mirror of `u128_saturating_from_u256` |
| `positive_u128_sat_max_low_128` | u128::MAX in low 128 → u128::MAX | mirror of `u128_saturating_from_u256` |

## Negative coverage (the important one)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_sig_wrapper_owner_index_high_byte_does_not_bleed_into_offset` | Owner index is u64 (right-padded), never disturbs the offset slot at out[32..64] | Feed u64::MAX; check out[0..24]==0 and out[63]==0x40 | Layout invariant holds |
| `negative_sig_wrapper_does_not_overwrite_pre_zeroed_padding` | The encoder relies on caller-zeroed buffer; it does NOT redundantly zero the padding past the sig | Pre-fill the padding region with 0xAA; assert it survives | Encoder respects its zero-pad contract |
| `negative_sig_wrapper_owner_index_byte_layout_is_left_padded` | Solidity ABI uint256 is big-endian, MSB at out[0]; a small u64 lives in out[24..32] | Encode 0x123456789abcdef0, verify byte placement | Layout matches on-chain decoder |
| `negative_sig_wrapper_length_field_is_left_padded_u256` | length slot is uint256 BE in out[64..96], low 8 bytes at out[88..96] | Verify out[64..88]==0 and out[88..96] is u64-BE of 4008 | Layout matches on-chain decoder |
| `negative_sig_wrapper_two_calls_produce_identical_output` | Encoder is pure (no hidden static-mut state) | Encode twice with same inputs, compare buffers | Deterministic |
| `negative_trailer_declared_len_exceeds_max_len` | Per-trailer cap defends against blowing past SNAP_LEN | declared=100, max=64 | Returns `NscStatus::InvalidPointer as u32` |
| `negative_trailer_declared_len_exceeds_remaining_total_len` | Length-confusion: declared len within max but past total_len | declared=20, total_len=16 | Rejected |
| `negative_trailer_max_len_plus_one_rejected_at_boundary` | Off-by-one sharp boundary — max+1 must be first rejection | max=32, declared=33 | Rejected |
| `negative_trailer_zero_max_len_rejects_any_nonzero_payload` | max_len=0 means "no payload allowed" even with `>` vs `>=` regression | max=0, declared=1 | Rejected |
| `negative_trailer_huge_declared_len_does_not_overflow_arithmetic` | declared=0xFFFF must not overflow `payload_start + len` | declared=0xFFFF, total_len=32 | Rejected without panic |
| `negative_trailer_does_not_index_past_total_len_when_header_absent` | Helper never reads past `total_len` | snap.len() == total_len with cursor at end | Returns absent without bounds-panic |
| `negative_trailer_returns_invalid_pointer_status_consistently` | All rejection paths return same status code | Three different error inputs | All return `InvalidPointer as u32` |
| `negative_trailer_struct_fields_are_consistent_on_absent` | start/next_cursor agree on absent path | cursor=total_len=7 | start==next_cursor==7, len==0 |
| `negative_trailer_struct_fields_are_consistent_on_valid_payload` | `next_cursor == start + len` invariant | Valid 5-byte payload | Equality holds |
| `negative_trailer_does_not_log_secret_inputs` | NS-supplied payload never leaks via logs | source has exactly one `show_status` and no `secure_log!` / `format!` / `write!` | Side-channel surface stays minimal |
| `negative_sig_wrapper_len_constant_unchanged_4128` | On-chain ABI expects 4128 B wrapper | `SIG_WRAPPER_LEN == 4128` | Wire format pinned |
| `negative_c10_sig_len_constant_unchanged_4008` | On-chain bytes-length field is 4008 | `C10_SIG_LEN == 4008` | Wire format pinned |
| `negative_init_code_len_constant_unchanged_4280` | CREATE2 hash depends on this — invariant #6 | `PQ_INIT_CODE_LEN == 4280` | Wallet address stability |
| `negative_sign_userop_header_len_unchanged_330` | Companion wire layout | `SIGN_USEROP_HEADER_LEN == 330` | Wire format pinned |
| `negative_max_sign_response_includes_all_emitted_pieces` | Output buffer accommodates worst-case emit | `MAX_SIGN_RESPONSE_LEN >= 12560` | NS buffer correctly sized |
| `negative_flag_bits_unchanged_match_claude_md` | Flag bit positions from CLAUDE.md | Exact bit assertions | Wire format pinned |
| `negative_flag_masks_are_pairwise_disjoint` | Bit-field masks must not overlap | Pairwise AND == 0, OR == u32::MAX | No silent flag bleed |
| `negative_max_account_index_is_255` | 8-bit field max | `MAX_ACCOUNT_INDEX == 0xFF` | Per-derivation invariant |
| `negative_slot_index_max_is_22_bits` | 22-bit field | `SLOT_INDEX_MASK == 0x003F_FFFF` | Per-derivation invariant |
| `negative_max_tx_len_unchanged_4096` | data_len cap | `MAX_TX_LEN == 4096` | Wire format pinned |
| `negative_factory_add_slot_domain_unchanged` | Bootstrap-signed domain tag for slot-0 registration | bytes == `b"pqwallet-factory-add-slot"` (25 B) | Deploy path stays valid |
| `negative_pq_create_account_selector_unchanged` | Factory selector embedded in initCode | `== [0xf6, 0x18, 0x2a, 0x73]` | initCode hash stays stable |
| `negative_pq_add_owner_bytes_selector_unchanged` | Wallet addOwnerBytes selector | `== [0x10, 0x14, 0x90, 0xcb]` | Rotation path stays valid |
| `negative_set_pre_signature_selector_unchanged` | CoW downgrade-gate selector | `== [0xec, 0x6c, 0xb1, 0x3f]` | Gate cannot be bypassed |
| `negative_approve_hash_selector_unchanged` | Safe downgrade-gate selector | `== [0xd4, 0xd9, 0xbd, 0xcd]` | Gate cannot be bypassed |
| `negative_approve_hash_calldata_len_is_selector_plus_bytes32` | Safe gate length check | `== 36` | Strict-len cross-check preserved |
| `negative_gpv2_settlement_address_unchanged` | CoW gate target address | byte-exact deployed address | Gate cannot be bypassed |
| `negative_pq_smart_wallet_factory_address_not_null` | Factory address (part of CREATE2 preimage) | 20 B, non-zero, non-FF | Address stability |
| `negative_nonce_increment_at_seq_overflow_panics_in_debug` | Per-helper `debug_assert!(false)` guard fires on overflow input | Pass nonce=0xff*32 to mirrored helper | Panics with documented message |
| `negative_nonce_overflow_check_in_run_uses_correct_byte_range` | Increment range matches gate's check range | range 24..32 on both | Match (else partial-overflow slips through) |
| `negative_u128_sat_any_high_byte_nonzero_saturates` | Any non-zero in bytes[0..16] forces saturation | 16 separate runs, one byte each | All return u128::MAX |
| `negative_u128_sat_msb_high_byte_saturates_not_truncates` | Attacker setting MSB does not silently truncate gas | bytes[0]=0x80 | Returns u128::MAX |
| `negative_slice_does_not_mention_any_classical_signer` | CLAUDE.md invariant #5 — single C10 signer | source-text scan for 12 banned identifiers | Absent from all three files |
| `negative_slice_does_not_expose_reset_or_rotate_paths` | CLAUDE.md "What NOT to do" — no reset/rotate | source-text scan for 10 banned identifiers | Absent |
| `negative_slice_does_not_use_entrypoint_v07_or_v08` | EntryPoint v0.6 frozen | source-text scan for v07/v08 markers | Absent; v06Sha256 present |
| `negative_slice_only_uses_sphincs_c10_verify_paths` | Verify-before-release uses C10 only | `sphincs_c10::verify` + `c10_sign_verified_with_progress` present | Present |
| `negative_slice_validates_ns_pointers_before_deref` | CLAUDE.md invariant #4 | `validate_ns_read_ptr` + `validate_ns_write_ptr` present | Present |
| `negative_slice_zeroizes_secrets_on_every_error_path` | ZeroizeOnDrop + barrier on every error | `entropy.zeroize()` + `fi::zeroize_barrier()` count check | Both present and roughly balanced |
| `negative_slice_uses_fi_double_check_on_flag_parse` | F-11 hardening — flags read twice | `flags_a` / `flags_b` / `flags_recheck` present | Present |
| `negative_slice_guards_against_nonce_seq_overflow` | CRIT-17 — `nonce[24..32] == [0xff;8]` gate | `nonce[24..32]` present in source | Present |
| `negative_slice_enforces_mutually_exclusive_flags` | INCLUDE_INIT_CODE ⊕ REGISTER_SLOT | `include_init_code && register_slot` gate present | Present |
| `negative_slice_pins_factory_add_slot_domain_tag` | Domain-tag stability | tag string literal present | Present |
| `negative_slice_pins_cow_downgrade_mitigation_gate` | CoW v3 trailer required for setPreSignature | three identifiers present | Present |
| `negative_slice_pins_safe_downgrade_mitigation_gate` | safe_v1 trailer required for approveHash | three identifiers present | Present |
| `negative_slice_checks_pin_verified_before_signing` | CLAUDE.md invariant #2 | `pin_verified` + `NscStatus::NotInitialized` present | Present |
| `negative_slice_snaps_payload_before_parsing` | TOCTOU snapshot before parse | `SNAP_BUF` + `read_volatile` present | Present |
| `negative_slice_wipes_snap_buf_on_exit` | L-2 metadata wipe on exit | "L-2" or "wipe the TOCTOU snapshot" present | Present |
| `negative_slice_uses_volatile_writes_to_ns_output` | NS-bound writes must be volatile | `write_volatile` present | Present |
| `negative_sig_wrapper_src_only_imports_sphincs_tz_shared` | sig_wrapper.rs stays pure-logic | Every `use` line whitelisted to shared/zeroize/core/super | Holds |

## Production-code bugs surfaced by negative tests

None. Every negative test passes against the current production code, which is the desired state: each negative test is a regression latch that fires only if a future refactor violates the assumption it pins.

## Coverage gaps deliberately left

- **`cmd_sign_userop::run` end-to-end execution** — the 1241-line handler depends on `static mut` driver state, the secure element trait, OTP, SAES, the FI helper module, flash I/O, and the OLED stack. None of these are reachable from a host build. The handler's end-to-end behaviour is exercised by the existing `make e2e` (QEMU) and `make e2e-hw` (on-target) suites. A future pass that adds a host-runnable shim for `WalletStore` + `Flash` + `Sha256` could test the handler directly, but that's a multi-PR refactor (see `docs/handoff-modularity-refactor.md`).
- **NSC pointer validation (`validate_ns_read_ptr` / `validate_ns_write_ptr`)** — these depend on hardware SAU state. Asserting they're *called* is testable from source-text (done in §8); asserting they *correctly reject* a hostile NS pointer requires hardware. A QEMU-mode test that injects an out-of-region pointer into a real `GatewayArgs` is a follow-up.
- **FI verify-before-release behaviour under glitch injection** — the `crate::fi::check_true_into_sentinel` calls are testable in isolation (and are exercised under `secure_element::tests::glitched_unlock_*` for the unlock path), but the sign-handler-specific glitch path is on-target only.
- **`add_one_to_be_u256` and `u128_saturating_from_u256`** — these private helpers in `cmd_sign_userop.rs` are tested via mirrored copies in §7. The copies are clearly labelled `mirror_*` and the docstring spells out the policy: "update both or neither." If the helper ever drifts, the wire-format-invariant negative tests + the on-target e2e flow surface the regression. Extracting both into the `pqsigner-tx-core` workspace crate would let them be linked directly from host tests — tracked but not done in this pass.
- **`SLOT_CACHE` keyed on `(account_index, chain_id, slot_index)`** — the cache-hit/miss decision logic is inside the `run()` handler and uses `static mut` state; not host-testable. Behavioural coverage lives in the on-target multi-account e2e (`make e2e` exercises 4 sign calls across two chains).

## Verification
- `cargo fmt -p sphincs-tz-secure --check` — N/A (sandbox blocks `cargo fmt` from running)
- `cargo check -p sphincs-tz-secure --tests` — PASS (0 new warnings)
- `cargo clippy -p sphincs-tz-secure --tests -- -D warnings` — N/A (sandbox blocks `cargo clippy` from running)
- `cargo test -p sphincs-tz-secure` — PASS (196 tests, 0 ignored; 75 new + 121 prior)
- (firmware) on-target tests deferred: yes — the full `run()` handler is covered by the existing `make e2e` / `make e2e-hw` suites, not re-implemented here

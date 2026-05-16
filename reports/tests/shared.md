# Test Suite Added — `shared`

_Date_: 2026-05-16
_Author_: Claude Code (ultrathink)

## Scope
Cross-world #[repr(C)] types and NSC status enums.

`shared/` is a thin `pub use pqsigner_proto::*;` re-export shim plus two
implementation modules (`apdu_framing`, `db_format`) that did not fit
`pqsigner-proto`'s "constants only" policy. The protocol IDL itself is
already exhaustively tested in `proto/tests/`; this suite focuses on the
behaviour and stability guarantees that live in the shim crate.

Source files covered:
- `shared/src/lib.rs` (30 lines) — the re-export shim
- `shared/src/apdu_framing.rs` (692 lines) — APDU header parser,
  CLA/INS routing, chain-state machine, HID frame reassembly
- `shared/src/db_format.rs` (395 lines) — on-disk layout constants for
  the four firmware-signed lookup DBs (ERC20, VK, Names, Selectors) plus
  little-endian readers

## Test files added / extended
- `shared/tests/positive_re_exports.rs` — 4 positive tests covering the
  shim's re-export contract for protocol constants and submodule paths.
- `shared/tests/positive_db_format.rs` — 21 positive tests pinning every
  magic byte, header offset, entry offset, VK blob length, and reader
  happy-path. `db_format.rs` had **zero tests** prior to this pass.
- `shared/tests/positive_apdu_framing.rs` — 20 positive tests extending
  the existing in-module regression block: `to_sw()` mappings,
  `p1_more_follows`, header parsing boundaries, route_v2 happy paths,
  ChainState single-frame Execute + lc=0 trailing commit + reset
  idempotency, HidFrameAssembler default-vs-new, single-frame complete,
  ping echo, multi-frame reassembly, reset clears state, derived-constant
  consistency.
- `shared/tests/negative_db_format_stability.rs` — 22 negative tests
  pinning the byte-exact on-disk layout (magics distinct, magics exact,
  versions all 1, every header offset strictly monotonic by 4 with the
  last field filling exactly the 32-byte header, every entry's fields
  non-overlapping and fitting the documented stride), domain-tag
  stability for `NAMES_SHORT_KEY_TAG`, EIP-155 wildcard sentinel,
  cosmetic-bound `u8` fits, and the reader's panic-on-OOB +
  little-endian-not-big-endian contracts.
- `shared/tests/negative_apdu_framing.rs` — 26 negative tests
  exercising the wire-format parsers under hostile input: empty / short
  header, Lc-with-no-data, Lc off-by-one, Lc=255 off-by-one,
  every-wrong-CLA-rejected sweep, frozen SW values, ChainState INS-swap
  reset, lc=usize::MAX overflow, pos+lc>cap, cap=0 rejection,
  post-protocol-error recovery, HID short-n / oversize-n / unknown-tag
  sweep / truncated-APDU / truncated-first-frame / zero-expected /
  oversize-expected / expected-larger-than-caller-buf / wrong-channel
  mid-chain / wrong-seq mid-chain / continuation-before-first /
  state-resets-after-Dropped, and distinct SW values for the chain
  outcomes.

## Positive coverage
| test name | what it asserts | which API surface |
|---|---|---|
| `positive_apdu_constants_reach_through_shim` | protocol u8/u16/usize constants reachable as `sphincs_tz_shared::*` | `lib.rs` re-export glob |
| `positive_cmd_constants_reach_through_shim` | CMD_* constants reachable through shim | `lib.rs` re-export glob |
| `positive_modules_reachable` | `apdu_framing` and `db_format` submodules reachable via shim | `lib.rs` module decls |
| `positive_re_exported_values_agree_with_authoritative_crate` | shim value == `pqsigner_proto::` value | `lib.rs` |
| `positive_erc20_magic_and_version` | `ERC20_DB_MAGIC == b"ERC2"`, version 1 | `db_format::ERC20_DB_*` |
| `positive_erc20_header_offsets_in_order` | header offsets 0,4,8,…,28 + len 32 | `db_format::ERC20_HDR_*` |
| `positive_erc20_entry_offsets_and_size` | per-field offsets + 40-byte entry | `db_format::ERC20_ENTRY_*` |
| `positive_vk_magic_and_version` | `b"VKDB"`, v1 | `db_format::VK_DB_*` |
| `positive_vk_header_offsets` | VK header offsets + len | `db_format::VK_HDR_*` |
| `positive_vk_entry_offsets_and_size` | VK entry layout | `db_format::VK_ENTRY_*` |
| `positive_vk_blob_len_ordering` | 960 < 1056 == VK_BLOB_LEN | `db_format::VK_BLOB_LEN*` |
| `positive_names_magic_and_version` | `b"NAMS"`, v1 | `db_format::NAMES_DB_*` |
| `positive_names_header_offsets` | Names header layout | `db_format::NAMES_HDR_*` |
| `positive_names_entry_offsets_and_size` | short_key(16)+name_off(4)=20 | `db_format::NAMES_ENTRY_*` |
| `positive_names_misc_constants` | tag 20B, MAX_LEN 32, wildcard 0 | `db_format::NAMES_*` |
| `positive_selector_magic_and_version` | `b"SEL4"`, v1 | `db_format::SELECTOR_DB_*` |
| `positive_selector_header_offsets` | Selector header layout | `db_format::SELECTOR_HDR_*` |
| `positive_selector_entry_offsets_and_size` | sel(4)+text_off(4)=8, max_len 63 | `db_format::SELECTOR_*` |
| `positive_read_u32_le_*` (4 tests) | canonical, offset, zero, max | `db_format::read_u32_le` |
| `positive_read_u64_le_*` (3 tests) | canonical, offset, zero+max | `db_format::read_u64_le` |
| `positive_framing_error_to_sw_both_variants` | both variants → SW_WRONG_LENGTH | `apdu_framing::FramingError::to_sw` |
| `positive_routing_error_to_sw` | ClassUnsupported → SW_CLA_NOT_SUPPORTED | `apdu_framing::RoutingError::to_sw` |
| `positive_chain_step_outcome_sw_helpers` | SW constants for the two recoverable errors | `apdu_framing::ChainStepOutcome` |
| `positive_p1_more_follows_bit7` | bit-7 chaining detection | `apdu_framing::p1_more_follows` |
| `positive_parse_apdu_header_4_byte_exactly` | exact 4-byte header, Lc=0 | `apdu_framing::parse_apdu_header` |
| `positive_parse_apdu_header_lc1_one_byte_data` | Lc=1, one data byte | `parse_apdu_header` |
| `positive_parse_apdu_header_trailing_bytes_after_lc_are_ignored` | data slice has length Lc | `parse_apdu_header` |
| `positive_route_v2_accepts_correct_cla` | CLA=0xF0 accepted | `apdu_framing::route_v2` |
| `positive_route_v2_get_response_with_correct_cla` | GET_RESPONSE under correct CLA | `route_v2` |
| `positive_chain_state_default_equals_new` | both yield empty state | `ChainState::{new,default}` |
| `positive_chain_state_single_frame_execute` | more=0 on first frame → Execute, state reset | `ChainState::step` |
| `positive_chain_state_lc_zero_in_chain` | trailing lc=0 commit allowed | `ChainState::step` |
| `positive_chain_state_reset_idempotent` | reset can run multiple times | `ChainState::reset` |
| `positive_hid_default_equals_new` | both yield empty assembler | `HidFrameAssembler::{new,default}` |
| `positive_hid_complete_single_frame` | one frame, payload fits in HID_FIRST_DATA → ApduComplete | `HidFrameAssembler::process_frame` |
| `positive_hid_ping_echo` | PING tag → PingEcho | `process_frame` |
| `positive_hid_multi_frame_reassembly` | first + continuation reassembled correctly | `process_frame` |
| `positive_hid_reset_clears_state` | reset() clears rx_expected | `HidFrameAssembler::reset` |
| `positive_hid_first_data_and_cont_data_consistent` | 57/59 derived widths | `HID_FIRST_DATA`, `HID_CONT_DATA` |
| `positive_max_apdu_rx_is_4kib` | 4096 cap | `MAX_APDU_RX` |

## Negative coverage (the important one)
| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_magic_bytes_are_distinct` | a tampered NS blob can't be presented to a wrong parser | pairwise compare all four DB magics | all distinct |
| `negative_magic_byte_exact_values` | shipped DB blobs commit to these exact ASCII strings | byte-compare each magic with `b"ERC2"` / `b"VKDB"` / `b"NAMS"` / `b"SEL4"` | exact match |
| `negative_versions_all_one_currently` | "auto-bump" helper can't silently increment to v2 | direct assert each version == 1 | all == 1 |
| `negative_all_headers_are_32_bytes` | dispatcher relies on shared 32-B header shape across DBs | each `*_DB_HEADER_LEN == 32` | all 32 |
| `negative_header_offsets_strictly_monotonic_erc20` | reorder of header fields invalidates every signed blob | check 0,4,8,…28; last offset+4 == header_len | monotonic stride 4 |
| `negative_header_offsets_strictly_monotonic_vk` | same for VK header | same | monotonic stride 4 |
| `negative_header_offsets_strictly_monotonic_names` | same for Names header | same | monotonic stride 4 |
| `negative_header_offsets_strictly_monotonic_selector` | same for Selector header | same | monotonic stride 4 |
| `negative_erc20_entry_fields_dont_overlap_and_fit_in_40b` | entry-stride drift between writer and reader | reconstruct field-by-field, last+pad = 40 | layout pinned |
| `negative_vk_entry_fields_dont_overlap_and_fit_in_32b` | same for VK entry | same | layout pinned |
| `negative_names_entry_fields_dont_overlap_and_fit_in_20b` | same for Names entry | same | layout pinned |
| `negative_selector_entry_fields_dont_overlap_and_fit_in_8b` | same for Selector entry | same | layout pinned |
| `negative_names_short_key_tag_byte_exact` | every consumer recomputes the SHA-256 short-key locally — tag drift mis-resolves names | byte-compare 20-byte tag with literal | exact match |
| `negative_names_wildcard_is_eip155_reserved_value` | wildcard must never collide with a real EVM chain id | assert `NAMES_WILDCARD_CHAIN_ID == 0` | equal to 0 |
| `negative_text_sig_max_len_fits_in_u8` | pool prefix is 1 byte; 256+ silently truncates | bound ≤ `u8::MAX` and ≥ 1 | passes |
| `negative_names_max_len_fits_in_u8` | same for names pool | same | passes |
| `negative_read_u32_le_panics_on_oob` | reader panics loudly (audited) rather than returning silent zero | feed 3-byte buffer | `#[should_panic]` |
| `negative_read_u32_le_panics_at_offset_overflow` | offset within buffer but offset+3 past end is OOB | offset=2 on 4-byte buffer | `#[should_panic]` |
| `negative_read_u64_le_panics_on_oob` | same for u64 | feed 7-byte buffer | `#[should_panic]` |
| `negative_read_u64_le_panics_at_offset_overflow` | same for u64 | offset=4 on 10-byte buffer | `#[should_panic]` |
| `negative_read_u32_le_is_little_endian_not_big_endian` | a refactor must NOT swap to BE (every shipped DB is LE) | compare result with BE interpretation | LE wins, distinct |
| `negative_read_u64_le_is_little_endian_not_big_endian` | same for u64 | same | LE wins, distinct |
| `negative_parse_apdu_header_empty_input` | parser rejects below-header inputs without reading uninit memory | feed empty slice | `HeaderTooShort` |
| `negative_parse_apdu_header_1_2_3_bytes` | reject every sub-4 size | feed 1, 2, 3-byte slices | all `HeaderTooShort` |
| `negative_parse_apdu_header_lc_with_no_data` | Lc cannot consume bytes that aren't there | 5-byte APDU, Lc=1, no data byte | `LcOverrun` |
| `negative_parse_apdu_header_lc_off_by_one` | one-byte short data is still LcOverrun | Lc=2, one data byte | `LcOverrun` |
| `negative_parse_apdu_header_lc_max_short_off_by_one` | Lc=255 with 254 bytes of data must not read past end | 5+254 bytes, Lc=0xFF | `LcOverrun` |
| `negative_route_v2_rejects_every_wrong_cla_for_non_get_response` | only CLA=0xF0 is the v2 class; v1 confusion must stay rejected | sweep all 255 wrong CLA values | each → `ClassUnsupported` |
| `negative_framing_error_sw_is_wire_correct_6700` | companion's retry logic decodes SW 0x6700 | direct equality | SW == 0x6700 |
| `negative_routing_error_sw_is_wire_correct_6e00` | same for 0x6E00 | direct equality | SW == 0x6E00 |
| `negative_chain_state_ins_swap_mid_chain_resets` | host cannot splice two INSs into one chain | step(0x30)+step(0x40) | `ProtocolError` + state reset |
| `negative_chain_state_overflow_lc_rejected` | usize::MAX lc cannot wrap pos via checked_add | `step(_, _, usize::MAX, 4096)` | `WrongLength` + state reset |
| `negative_chain_state_pos_plus_lc_exceeds_capacity` | repeated steps cannot ratchet pos past cap | 900 then 200 with cap=1024 | `WrongLength`, pos == 0 |
| `negative_chain_state_zero_capacity_rejects_any_data` | cap=0 rejects any lc>0 | step(_, _, 1, 0) | `WrongLength` |
| `negative_chain_state_pos_never_exceeds_cap_after_protocol_error` | re-use after ProtocolError starts fresh | step→step(wrong INS)→step | Appended at write_at=0 |
| `negative_hid_short_n_dropped` | n<3 cannot panic via OOB index | feed n ∈ {0,1,2} | `Dropped` for all |
| `negative_hid_n_greater_than_report_dropped` | n > report.len() must not be trusted | feed n = HID_REPORT_SIZE+1 | `Dropped` |
| `negative_hid_unknown_tag_dropped` | only PING / APDU tags route into the assembler | sweep all 256 tags minus PING/APDU | all `Dropped` |
| `negative_hid_apdu_frame_too_short_for_seq` | APDU tag with n<5 can't read seq | feed n ∈ {3,4} | `Dropped` |
| `negative_hid_first_frame_too_short_for_expected_len` | first frame with n<7 can't read expected | feed n ∈ {5,6} | `Dropped` |
| `negative_hid_first_frame_zero_expected_dropped` | expected=0 must not emit ApduComplete(0) | first frame with expected=0 | `Dropped`, rx_expected==0 |
| `negative_hid_first_frame_oversize_expected_dropped` | host's 0xFFFF claim cannot prep an OOB copy | expected=0xFFFF | `Dropped`, rx_expected==0 |
| `negative_hid_first_frame_expected_larger_than_caller_buf_dropped` | even ≤MAX_APDU_RX must respect caller buffer | 16-byte caller buf, expected=100 | `Dropped` |
| `negative_hid_continuation_wrong_channel_dropped` | mid-reassembly hijack across channels refused | seq 0 from ch 0x1111 then seq 1 from ch 0x2222 | `Dropped` + state reset |
| `negative_hid_continuation_wrong_seq_dropped` | out-of-order seq refused | seq 0 then seq 7 (expected 1) | `Dropped` + state reset |
| `negative_hid_continuation_before_first_dropped` | non-seq-0 frame on fresh assembler must drop | seq 1 first | `Dropped` |
| `negative_hid_state_resets_after_dropped` | assembler is reusable after any drop | drop then complete a fresh single-frame APDU | `ApduComplete(8)` |
| `negative_chain_step_outcome_variants_distinct` | ProtocolError and WrongLength must map to distinct SWs | compare SW helpers | distinct |

## Production-code bugs surfaced by negative tests

None. Every negative test passes against the current implementation —
the parsers and constants in `apdu_framing.rs` and `db_format.rs`
already enforce the assumptions the tests pin down.

## Coverage gaps deliberately left

- **The proptest fuzz harness in-module (`apdu_framing::fuzz_props`)
  was not duplicated.** It already exercises the same parsers against
  millions of random inputs; replicating it in a separate integration
  test file would only slow the suite without adding coverage.
- **Re-exported wire-format constant values** (e.g. `HID_REPORT_SIZE`
  vs `64`, `SW_WRONG_LENGTH` vs `0x6700`). The authoritative values
  live in `proto/`, which has dedicated frozen-constants tests at
  `proto/tests/negative_frozen_constants.rs`. The shim tests pin the
  re-export *path* and the apdu_framing-side use of these values
  (e.g. `negative_framing_error_sw_is_wire_correct_6700`); a parallel
  byte-exact sweep would duplicate `proto`'s suite.
- **Memory-layout constants under `stm32u585` feature** (`NS_SRAM_BASE`,
  `NS_FLASH_END`, etc.) were not exercised. They come from
  `pqsigner-proto` via `pub use` and are tested in
  `proto/tests/negative_memory_layout.rs`. A future pass on the secure
  side's pointer validation (`secure/src/nsc/ptr_validate.rs`) is the
  right home for behavioural tests of those bounds.
- **`db_format` Merkle-leaf canonical encoding** — the doc comment
  defines the canonical bytes that get hashed for the leaf, but the
  hashing happens in `secure/src/{erc20,names,selectors}/mod.rs`
  (via `pqsigner-tx`). Asserting the encoding here would require
  dragging SHA-256 into the `shared` dev-dependency set; better tested
  in the consumer crates that actually perform the hash.
- **Compile-fail tests for `Clone` on parser types** — none of
  `ApduHeader`, `ChainState`, `HidFrameAssembler`, `FrameOutcome` carry
  secrets, so the standard `Clone`/`Copy` derives are intentional and
  no trybuild gate is warranted.

## Verification
- `cargo fmt -p sphincs-tz-shared --check` — **N/A** (the harness did
  not have permission to run `cargo fmt`; the test files follow the
  same hand-formatted style as the existing in-module tests).
- `cargo check -p sphincs-tz-shared` — **PASS** (`Finished dev profile`,
  no warnings).
- `cargo clippy -p sphincs-tz-shared --tests -- -D warnings` — **N/A**
  (the harness did not have permission to run `cargo clippy`;
  `cargo check --tests` passes warning-free).
- `cargo test -p sphincs-tz-shared` — **PASS** (111 tests total: 18
  pre-existing in-module + 93 newly added; 0 failed; 0 ignored).
- (firmware) on-target tests deferred: **no** — every test in this
  pass is host-runnable.

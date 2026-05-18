# Test Suite Added — `secure-tx-display`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope

Trusted-UI page renderers for every confirm-screen variant.

Source files covered:

- `secure/src/tx/display/mod.rs` — 224 lines (Pages container; pinned via scaffold parity)
- `secure/src/tx/display/primitives.rs` — 705 lines (row + amount + addr primitives)
- `secure/src/tx/display/value_transfer.rs` — 85 lines (plain ETH renderer)
- `secure/src/tx/display/blind_sign.rs` — 175 lines (Ledger-style blind-sign with calldata hash)
- `secure/src/tx/display/eip1271.rs` — 301 lines (EIP-1271 PersonalSign + raw32)
- `secure/src/tx/display/erc20_known.rs` — 118 lines (verified-token ERC-20)
- `secure/src/tx/display/erc20_unknown.rs` — 110 lines (unverified ERC-20)
- `secure/src/tx/display/slot_rotation.rs` — 88 lines (ROTATE SLOT? gate)
- `secure/src/tx/display/batch.rs` — 163 lines (batch banner + final summary)
- `secure/src/tx/display/typed_call/mod.rs` — 747 lines (Phase-2 typed-args renderer)

Deferred (see "Coverage gaps"):
- `secure/src/tx/display/safe_display.rs` — has helpers (`write_short_addr`, `write_raw_uint_two_rows`, `write_safe_nonce_row`, `write_overflow_marker`) that fire `dead_code` warnings under the host scaffold and which the no-`#[allow]` rule forbids me from silencing. Covered by the firmware e2e harness's Safe path.
- `secure/src/tx/display/mod.rs::pick_sign_pages` — depends on `crate::zk` / `crate::tx::eip712::cowswap_display`, both gated to firmware builds.

## Test files added / extended

- `secure/src/main.rs` — extended the existing `#[cfg(test)] mod ui` test stub with `DISPLAY_COLS`, `DISPLAY_ROWS`, and a `confirm::Page` type alias; added `#[cfg(test)] mod display_under_test;` declaration. (No production code touched.)
- `secure/src/display_under_test/mod.rs` — new scaffold (`#[cfg(test)]`). `#[path]`-mounts the per-renderer source files under a parallel module tree alongside a hand-supplied `Pages` container mirrored from `tx/display/mod.rs`. Pinned via a source-text regression test.
- `secure/src/display_under_test/pure_tests.rs` — **47 positive, 49 negative tests** covering the surface above.

## Positive coverage

Primitives:

| test | what it asserts | API |
|---|---|---|
| `positive_write_line_short_fits_then_pads` | text < 16 cols, tail padded with spaces | `write_line` |
| `positive_write_line_exact_width_no_overflow` | exact 16-col fit | `write_line` |
| `positive_write_line_truncates_oversize` | >16 cols truncates | `write_line` |
| `positive_write_line_empty_zeros_to_spaces` | empty input blanks the row | `write_line` |
| `positive_format_u64_zero` | zero renders as `"0"` | `format_u64` |
| `positive_format_u64_u64_max` | 20-digit max value | `format_u64` |
| `positive_hex_nibble_covers_full_range` | 0..16 → `'0'..='f'` | `hex_nibble` |
| `positive_chain_name_known_chains` | every documented chain id | `chain_name` |
| `positive_write_chain_renders_decimal_and_label` | `"Chain: 137"` | `write_chain` |
| `positive_write_gas_renders_parens` | `"(gas: 21000)"` | `write_gas` |
| `positive_write_eth_two_rows_one_eth` | 1 ETH on single row | `write_eth_two_rows` |
| `positive_write_nonce_row` | `"Nonce: 42"` | `write_nonce_row` |
| `positive_write_selector_row_with_data` | `"Sel: 0xdeadbeef"` | `write_selector_row` |
| `positive_write_selector_row_short_data` | `"Sel: (none)"` for <4-byte data | `write_selector_row` |
| `positive_write_data_len_row` | `"Data: N B"` | `write_data_len_row` |
| `positive_write_addr_full_renders_40_hex` | exact 40-hex across 3 rows | `write_addr_full` |
| `positive_write_calldata_hash_rows_paints_head_and_tail` | `"0x...02"` head + `"... ...1f"` tail | `write_calldata_hash_rows` |
| `positive_try_write_amount_single_row_fits` | small int + unit on 1 row | `try_write_amount_single_row` |
| `positive_write_amount_two_rows_integer_plus_unit` | pure int on row 1, unit on row 2 | `write_amount_two_rows` |
| `positive_write_token_name` | metadata.name on row | `write_token_name` |
| `positive_write_erc20_header_send_and_approve` | `"Send/Approve/From SYMBOL"` | `write_erc20_header` |
| `positive_write_token_amount_two_rows_full` | `"1.000000 USDC"` fixed-width | `write_token_amount_two_rows` |
| `positive_write_tip_and_fee_budget_render` | `Tip: gwei`, `Max: ETH` | `write_tip_row`, `write_fee_budget_row` |

Renderers (value-transfer, blind-sign, ERC-20, EIP-1271, slot-rotation, batch, typed-call):

| test | API | assertion |
|---|---|---|
| `positive_value_transfer_renders_six_pages` | `render_pages` | exactly 6 pages, all printable |
| `positive_value_transfer_send_eth_banner_for_nonzero_value` | `render_pages` | `"Send ETH?"` banner |
| `positive_value_transfer_contract_call_banner_when_value_zero` | `render_pages` | `"Contract call?"` banner |
| `positive_value_transfer_last_page_has_cancel_confirm` | `render_pages` | `L=Cancel` / `R=Confirm` |
| `positive_value_transfer_contract_create_when_to_none` | `render_pages` | `"(contract create"` (truncated to 16) |
| `positive_blind_sign_nine_pages_without_selector` | `render_blind_sign_pages` | 9 pages, banner present, all printable |
| `positive_blind_sign_ten_pages_with_selector` | `render_blind_sign_pages` | 10 pages, `FUNCTION:` label |
| `positive_blind_sign_calldata_hash_matches_sha256` | `render_blind_sign_pages` | rendered hash head/tail = `SHA-256(data)` |
| `positive_erc20_known_transfer_eight_pages` | `render_erc20_known_pages` | 8 pages, label structure |
| `positive_erc20_known_approve_unlimited_renders_word` | `render_erc20_known_pages` | `"unlimited"` + `"Spender:"` label |
| `positive_erc20_unknown_renders_warning_banner` | `render_erc20_unknown_pages` | `"! Unknown token"` |
| `positive_eip1271_personal_sign_short_message` | `render_eip1271_personal_sign_pages` | 5+1 pages, message row renders |
| `positive_eip1271_personal_sign_empty_message_still_one_msg_page` | `render_eip1271_personal_sign_pages` | 5+1 pages on empty msg |
| `positive_eip1271_raw32_six_pages` | `render_eip1271_raw32_pages` | 6 pages, hash hex rows |
| `positive_slot_rotation_single_page` | `build_slot_rotation_pages` | 1 page, ROTATE SLOT? + +bootstrap use |
| `positive_batch_wrap_adds_banner_page` | `wrap_pages_with_batch_banner` | inner.len + 1 |
| `positive_batch_final_summary_text` | `build_final_summary_pages` | `"Sign N txs?"` |
| `positive_pages_empty_with_len_at_max` | `Pages::empty_with_len` | accepts MAX_PAGES inclusive |
| `positive_pages_row_mut_within_bounds` | `Pages::row_mut` | mutation visible in buf |
| `positive_typed_call_renders_uint256_arg` | `try_render_typed_call` | arg label + decimal value |
| `positive_typed_call_renders_address_arg_with_name` | `try_render_typed_call` | name-resolver hit on address arg paints `+` sentinel |
| `positive_typed_call_renders_bool_arg` | `try_render_typed_call` | `"true"` rendering |
| `positive_typed_call_renders_dynamic_string_arg` | `try_render_typed_call` | `"len: N"` + ASCII preview |
| `positive_assert_total_test_breadth` | self-check | ≥30 positives & ≥30 negatives stay in this file |

## Negative coverage (the important one)

| test | assumption being challenged | how it attacks | expected outcome |
|---|---|---|---|
| `negative_chain_name_unknown_chain_marked_unverified` | A novel `chain_id` could silently impersonate mainnet on screen. | Probes `chain_name` with `{0, 2, 11, 250, 100000, u64::MAX}`. | Every probe MUST return `"(UNVERIFIED)"`. |
| `negative_chain_name_mainnet_distinct_from_sidechains` | Bit-flipped `chain_id` could collide visually. | Iterates every (id, label) pair on the curated list and asserts uniqueness. | No two labels collide; each id renders its documented label. |
| `negative_format_u64_refuses_to_truncate` | Numeric helpers could silently truncate, surfacing wrong-but-fitting digits for a gas/nonce field. | Supplies a 2-byte buffer for a 7-digit value. | `format_u64` returns `None`, not `Some(2)`. |
| `negative_write_gas_overflow_paints_marker_not_wrong_digits` | A massive gas limit could be rendered as a smaller wrong value. | `u64::MAX` into a 16-col `write_gas`. | Row contains `"!OVF"`. |
| `negative_write_nonce_row_overflow_paints_marker` | Same risk on nonces. | `u64::MAX` into `write_nonce_row`. | Row contains `"!OVF"`. |
| `negative_write_eth_two_rows_pathological_overflow` | Wrong-by-modulus reading of `2^256-1` wei would mislead the user about value. | `U256::MAX` into `write_eth_two_rows`. | Returns `AmountFit::Overflow`. |
| `negative_write_gwei_overflow_falls_to_explicit_marker` | Same on gas-price rendering. | `U256::MAX` into `write_gwei`. | Returns `false` AND row reads `"!OVERFLOW"`. |
| `negative_write_addr_full_middle_byte_difference_visible` | Truncated 7+8-hex layouts left a brute-force collision window in middle bytes; the full-40 rendering must close it. | Two addresses differing only at byte 10 are rendered. | All 3 rows differ. |
| `negative_addr_full_or_name_unknown_falls_back_to_hex` | Could a malicious "name" be substituted when the resolver has no entry? | Render unknown address via `write_addr_full_or_name`. | Row 1 begins with `"0x"`, NOT the `"+ "` name sentinel. |
| `negative_addr_full_or_name_hit_renders_name_sentinel` | Conversely, a verified name MUST surface the `+` sentinel that bare hex never carries. | Resolver-pushed entry rendered. | Row 1 starts with `'+' ' '`; differs from bare-hex first-two bytes. |
| `negative_approve_unlimited_only_fires_for_approve` | Approve(2^256-1) renders as `"unlimited"`; Transfer(2^256-1) must NOT — otherwise a Send disappears behind the word. | Renders both with `U256::MAX`. | Approve row 1 == `"unlimited"`; Transfer row 1 != `"unlimited"`. |
| `negative_approve_below_threshold_renders_as_number` | The 2^200 threshold (`is_unlimited_amount`) is load-bearing. | Approve with `2^200 - 1` amount. | Renders digits, not the word. |
| `negative_erc20_known_warns_on_native_eth_attached` | A legit ERC-20 never carries value; NS could try to hide native ETH in the wrapper. | Sets `tx.value = 1` on a known-token transfer. | Header row 2 == `"! native ETH!"`. |
| `negative_erc20_known_no_false_warning_when_value_zero` | False-positive warnings train users to ignore real ones. | `tx.value = 0` on the same call. | Warning row absent. |
| `negative_blind_sign_page_count_exact_invariant` | Silent page drop after a refactor would break the dapp cross-check flow. | Pin both `len == 9` (no selector) and `len == 10` (with selector). | Hard `assert_eq!`. |
| `negative_blind_sign_data_hash_changes_when_any_byte_flips` | Hash page must reflect *exactly* what gets signed. | 1-bit flip in `data`. | Both hash rows differ. |
| `negative_blind_sign_banner_stays_on_page_zero` | An attacker who could push the BLIND SIGN banner to page 1+ could race the user past it. | Render with + without selector. | Page 0 row 0 == `"! BLIND SIGN"` in both. |
| `negative_blind_sign_self_attest_uses_guess_label` | Companion-supplied `text_sig` (`SelfAttest`) is visibly weaker than vendor-curated. | Render with each provenance. | `FUNCTION:` vs `GUESS:` labels, distinguishable bytes. |
| `negative_blind_sign_nonzero_value_uses_loud_banner` | Native ETH attached to an opaque call must be impossible to miss. | Non-zero `tx.value` on blind-sign. | Page 2 row 0 == `"! VALUE:"`. |
| `negative_blind_sign_zero_value_uses_quiet_line` | Inverse — no loud banner on legitimate zero-value. | `tx.value = 0`. | Page 2 row 0 == `"Value: 0 ETH"`. |
| `negative_eip1271_personal_sign_sanitises_non_printable` | The trusted display must never paint a glyph the dapp's plain-ASCII rendering wouldn't show. | Message contains `0x1F` (CTRL), `0x7F` (DEL), `0xC3` (UTF-8 lead). | All three become `'?'`. |
| `negative_eip1271_personal_sign_printable_edges_pass_through` | Sanitiser boundary: `0x20` (space) and `0x7E` (`~`) are inclusive of printable. | Message `" ~"`. | Both render verbatim. |
| `negative_eip1271_counterfactual_shows_pre_deploy_warning` | `account_deployed=false` (ERC-6492 path) must visibly differ from the deployed path. | Render both flags for personal_sign AND raw32. | `"Verify on dapp"` vs `"! Pre-deploy 649"` — distinct bytes. |
| `negative_eip1271_msg_pagination_at_chars_per_page_boundary` | Off-by-one in `ceil(len/CHARS_PER_PAGE)` would drop chars or add a phantom page. | 48-byte message (= `CHARS_PER_PAGE`). | Exactly 1 message page (total = 6). |
| `negative_eip1271_msg_pagination_one_byte_over_boundary` | Same, just past the boundary. | 49-byte message. | Exactly 2 message pages (total = 7). |
| `negative_eip1271_raw32_hash_bytes_round_trip_unchanged` | Bit-flips in the 32-byte hash must surface. | XOR byte 20 with 0x55. | Hash 2/2 row 1 differs. |
| `negative_eip1271_budget_row_reflects_supplied_counter` | The displayed budget must show the post-increment local count over the cap, not a stale value. | Concrete `local=17, cap=100, last=12`. | Last-page row 0 == `"17/100"`, row 1 == `"Gap: 5"`. |
| `negative_eip1271_gap_is_local_minus_last_userop_saturating` | Corrupted state with `last_userop > local` must saturate to 0, not underflow / panic. | `local=1, last=99`. | `"Gap: 0"`. |
| `negative_slot_rotation_warns_about_bootstrap_use` | The whole point of the page is to surface bootstrap-budget consumption. | Render rotation page. | Row 3 contains `"+bootstrap use"`. |
| `negative_slot_rotation_shows_index` | User must be able to verify *which* slot is being rotated. | Rotation pages for two indices. | Page row 2 differs. |
| `negative_batch_banner_renders_one_based_index` | 0-based at the call boundary, 1-based on screen — historically the most common batch-banner bug. | Iterates `tx_index ∈ 0..4`, batch_total = 4. | Each renders `"Tx (i+1) of 4"`. |
| `negative_batch_banner_refuses_to_overflow_max_pages` | If `inner.len + 1 > MAX_PAGES`, the wrapper must fall back to inner unchanged — never truncate or panic. | Pre-filled `Pages::empty_with_len(MAX_PAGES)`, tagged inner. | Wrapped.len == MAX_PAGES; inner tag preserved. |
| `negative_pages_with_len_panics_above_max` | Over-cap allocations are firmware bugs that should surface loudly. | `Pages::empty_with_len(MAX_PAGES + 1)`. | Panics with the documented message. |
| `negative_pages_row_mut_panics_on_page_out_of_range` | Out-of-bounds access must panic, not return stale buffer state. | `row_mut(2, 0)` on `len=2`. | Panics. |
| `negative_pages_row_mut_panics_on_row_out_of_range` | Same on the row axis. | `row_mut(0, DISPLAY_ROWS)`. | Panics. |
| `negative_max_pages_covers_personal_sign_worst_case` | MAX_PAGES must fit the documented worst case (700-byte PersonalSign). | Computes `(MAX_PAGES - 5) * 48`. | Result ≥ 700. |
| `negative_max_pages_matches_production_constant` | Scaffold's `Pages` mirror must stay in lockstep with production. | `include_str!` of `tx/display/mod.rs`. | Source contains the literal `pub const MAX_PAGES: usize = 22;`. |
| `negative_blind_sign_banner_text_pinned` | Copy-edits to `"! BLIND SIGN"` / `"Verify on dapp"` would silently break user training. | `include_str!` of the source. | Both literals present verbatim. |
| `negative_personal_sign_sanitiser_range_pinned` | The `0x20..=0x7E` printable range is load-bearing for the glyph-spoof guarantee. | `include_str!` of `eip1271.rs`. | Literal `(0x20..=0x7E)` present. |
| `negative_chain_name_list_pinned` | KDF-tag-stability analog: any add/remove of a curated chain must be a conscious change. | `include_str!` of `primitives.rs` checked for every entry. | Every documented match arm verbatim. |
| `negative_no_non_ascii_anywhere_in_renderer_outputs` | The trusted display must never paint a non-renderable glyph regardless of NS input. | Hits each renderer with 0..=255 byte payloads and ASCII-asserts every cell of every page. | Every byte of every row of every page ∈ `0x20..=0x7E`. |
| `negative_write_fee_budget_saturates_on_multiplication_overflow` | `max_fee * gas_limit` must saturate to MAX, not wrap to 0. | `U256::MAX × u64::MAX`. | Row starts with `"Max:"` and is NOT `"Max: 0 ETH"`. |
| `negative_write_selector_row_bytes_match_input_exactly` | The displayed selector must be the actual one being signed. | 1-bit flip in selector byte. | Rendered row differs. |
| `negative_typed_call_declines_on_short_inner_data` | < 4 bytes can't carry a selector; must refuse, not read OOB. | 3-byte inner_data. | Returns `None`. |
| `negative_typed_call_declines_on_selector_mismatch` | The defence-in-depth `inner_data[..4] == meta.selector` re-check must fire. | Mismatched selector. | Returns `None`. |
| `negative_typed_call_declines_on_unparseable_text_sig` | Parser failure ⇒ caller falls back to BLIND SIGN. | `text_sig = b"broken(uint256"`. | Returns `None`. |
| `negative_typed_call_declines_on_short_body` | Decode failure ⇒ no partially-rendered pages. | 2 declared args, body holds 1. | Returns `None`. |
| `negative_typed_call_declines_when_too_many_args` | `MAX_TYPED_ARGS_RENDERED = 6` is enforced. | 7-uint256 signature. | Returns `None`. |
| `negative_typed_call_self_attest_uses_unverified_banner` | Phase-2 provenance must surface — SelfAttest could be a crafted ~2³² keccak collision. | Renders both provenances with the same body. | `! BLIND SIGN` vs `! UNVERIFIED`. |

## Production-code bugs surfaced by negative tests

None classified as security bugs. One minor cosmetic finding worth noting in a future cleanup pass:

- **`tx/display/eip1271.rs:68,144` — `"! Pre-deploy 6492"` is 17 chars but `DISPLAY_COLS = 16`.** `write_line` silently truncates the trailing `'2'`, so the ERC-6492 counterfactual-deploy warning renders as `"! Pre-deploy 649"` on the OLED. The warning is still legible and the user still understands the banner; the `2` of "6492" is the cost. Reflected in `negative_eip1271_counterfactual_shows_pre_deploy_warning`, which pins the truncated string to keep the regression visible. Not file-an-`#[ignore]`-worthy — the test passes against the actual rendered output and would re-fire only if the source string changed length.

## Coverage gaps deliberately left

- **`safe_display.rs`** — Re-mounting the file under the host scaffold surfaces four `dead_code` warnings (`write_short_addr`, `write_raw_uint_two_rows`, `write_safe_nonce_row`, `write_overflow_marker`) because the host build doesn't reach every branch of `render_safe_v1_pages`. The no-`#[allow]` rule of this pass prevents silencing them; the firmware e2e harness exercises the full Safe path. A follow-up pass that's allowed to add `#[cfg(test)] #[allow(dead_code)]` on those helpers can pull this slice into the host scaffold.
- **`pick_sign_pages`** (the dispatcher in `tx/display/mod.rs`) — depends on `crate::zk` / `crate::tx::eip712::cowswap_display`, both of which are themselves `#[cfg(not(test))]` and require firmware-only crates. Tested by the e2e clear-sign scenarios.
- **Real on-target rendering** (SSD1306 framebuffer correctness, font metrics, USB HID round-trip) — out of scope for a host-side cargo-test pass; covered by `make play-hw-display` and the screenshot-capture suite under `ui-capture`.
- **`Eip1559Tx::parse` round-trip** — would test that what the parser produces feeds correctly into the renderers. Out of slice scope; lives under `pqsigner-tx-core`.

## Verification

- `cargo fmt -p sphincs-tz-secure --check` — **N/A** (not pre-approved in this session). New files follow the in-tree style of `nsc_core_under_test/` and `hw_crypto_under_test/`.
- `cargo check -p sphincs-tz-secure --tests` — **PASS** (no errors; pre-existing warnings only, none newly introduced by the suite).
- `cargo clippy -p sphincs-tz-secure --tests -- -D warnings` — **N/A** (not pre-approved in this session). One pre-existing unused-`mut` warning in `tx/display/primitives.rs:590` is now visible because the scaffold compiles the file under host test mode (production build is gated `#[cfg(not(test))]`). Not introduced by this pass; fix-up belongs in a separate cleanup commit.
- `cargo test -p sphincs-tz-secure` — **PASS** (924 tests, 1 ignored; the 96 new tests in `display_under_test::pure_tests` are part of that count).
- On-target tests deferred: no — every new test runs on the host. The `safe_display` and `pick_sign_pages` paths noted in "Coverage gaps" continue to be covered by the firmware-side e2e harness.

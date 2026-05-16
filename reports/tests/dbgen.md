# Test Suite Added — `dbgen`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope
Host Merkle-DB builder for trust-bundles. `dbgen` reads curated JSON in
`secure/data/` and emits four binary blobs (ERC-20 metadata, ZK VK,
Names, Selectors) plus the 32-byte Merkle roots that the secure-world
firmware embeds as its trust anchors. Format drift here silently
re-keys every shipped wallet.

Source files covered:
- `dbgen/src/merkle.rs:134` — SHA-256 Merkle tree (`leaf_hash`,
  `node_hash`, `MerkleTree::{build, root, depth, proof}`,
  `verify_proof`)
- `dbgen/src/erc20.rs:522` — ERC-20 DB writer + canonical leaf encoder +
  host-side round-trip parser
- `dbgen/src/names.rs:357` — Names DB writer + `names_short_key` +
  canonical leaf encoder
- `dbgen/src/selectors.rs:345` — Selectors DB writer + `parse_selector`
  + canonical leaf encoder
- `dbgen/src/erc20_poseidon.rs:245` — Poseidon-Merkle parallel tree
  builder + BLS12-381 field-element leaf encoder + `scalar_to_le32`

Out of scope this pass: `vks.rs` (needs binary VK fixture files on
disk) and `poseidon.rs` (already had a pre-existing test suite — left
intact).

## Test files added / extended
- `dbgen/src/merkle.rs` — added `#[cfg(test)] mod tests`, 7 positive +
  9 negative tests covering domain separation, tampering, position
  binding, padding ambiguity, and empty/oversize input panics.
- `dbgen/src/erc20.rs` — added `#[cfg(test)] mod tests`, 5 positive +
  11 negative tests covering canonical encoding stability, build_db
  validation gates, and round-trip rejection of tampered blobs.
- `dbgen/src/names.rs` — added `#[cfg(test)] mod tests`, 5 positive +
  11 negative tests pinning `NAMES_SHORT_KEY_TAG`, chain_id big-
  endianness, wildcard vs real chain, and NAMES_MAX_LEN.
- `dbgen/src/selectors.rs` — added `#[cfg(test)] mod tests`, 5 positive
  + 10 negative tests covering selector parsing, ASCII gating,
  duplicate rejection, and tampered-blob round-trip.
- `dbgen/src/erc20_poseidon.rs` — added `#[cfg(test)] mod tests`, 6
  positive + 9 negative tests pinning `MAX_SYMBOL_LEN = 6`, the
  6-field leaf layout, symbol-packing endianness, and Poseidon tree
  verify rejections.
- `dbgen/Cargo.toml` — added `[dev-dependencies] tempfile = "3"` to
  drive JSON-fixture `build_db` tests without bind-mounting on-disk
  files.

Total: 28 positive + 50 negative tests (plus 5 pre-existing
`poseidon::tests`) → 83 total, all passing.

## Positive coverage

| test name | what it asserts | which API surface |
|---|---|---|
| `merkle::positive_leaf_hash_known_vector_empty` | `leaf_hash(&[]) == sha256(0x00)` | `merkle::leaf_hash` |
| `merkle::positive_leaf_hash_known_vector_abc` | `leaf_hash(b"abc") == sha256(0x00‖abc)` | `merkle::leaf_hash` |
| `merkle::positive_node_hash_known_vector` | `node_hash(0,ff) == sha256(0x01‖0‖ff)` | `merkle::node_hash` |
| `merkle::positive_single_leaf_tree_root_is_leaf` | 1-leaf tree: depth 0, root==leaf, empty proof verifies | `MerkleTree::{build,root,depth,proof}` + `verify_proof` |
| `merkle::positive_two_leaf_tree` | Tree of 2 leaves: depth 1, correct sibling order in proofs | `MerkleTree::*` |
| `merkle::positive_padding_three_leaves_to_four` | Bitcoin-style padding duplicates last leaf | `MerkleTree::build` |
| `merkle::positive_full_tree_eight_leaves_all_verify` | 8-leaf tree, depth 3, every index verifies | `MerkleTree::*` |
| `erc20::positive_canonical_erc20_leaf_byte_frozen` | Byte-exact preimage for a known input | `erc20::canonical_erc20_leaf` |
| `erc20::positive_build_db_minimal_round_trip` | Single entry: blob magic, root, round-trip | `erc20::build_db`, `round_trip_check` |
| `erc20::positive_build_db_sorts_and_interns_strings` | Same name/symbol across chains dedups in pool | `erc20::build_db` |
| `erc20::positive_build_db_accepts_address_without_0x` | Bare 40-hex address accepted | `erc20::build_db` |
| `erc20::positive_build_db_emits_correct_header_offsets` | Header fields lay out as documented | `erc20::build_db` |
| `names::positive_canonical_names_leaf_byte_frozen` | Byte-exact names canonical leaf | `names::canonical_names_leaf` |
| `names::positive_names_short_key_byte_frozen` | 16-byte short_key matches `sha256(tag‖chain_be‖addr)[..16]` | `names::names_short_key` |
| `names::positive_names_short_key_tag_value_stable` | `NAMES_SHORT_KEY_TAG == b"pqsigner-name-key-v1"` | `shared::NAMES_SHORT_KEY_TAG` |
| `names::positive_build_db_chain_agnostic_entry_round_trips` | `chain_id` omitted (=0) works as wildcard | `names::build_db` |
| `names::positive_build_db_multi_chain_round_trip` | 2 chains, same name → string interned once | `names::build_db` |
| `selectors::positive_canonical_selector_leaf_byte_frozen` | Byte-exact selector canonical leaf | `selectors::canonical_selector_leaf` |
| `selectors::positive_parse_selector_with_and_without_0x_prefix` | Both `"0xabcd..."` and `"abcd..."` accepted | `selectors::parse_selector` |
| `selectors::positive_build_db_round_trip` | Known selectors round-trip end to end | `selectors::build_db` |
| `selectors::positive_build_db_sorts_selectors` | Unsorted input → sorted on-disk array | `selectors::build_db` |
| `selectors::positive_build_db_interns_text_sigs` | Two selectors sharing a sig dedup in pool | `selectors::build_db` |
| `erc20_poseidon::positive_max_symbol_len_frozen_at_six` | `MAX_SYMBOL_LEN == 6` | `erc20_poseidon::MAX_SYMBOL_LEN` |
| `erc20_poseidon::positive_canonical_poseidon_leaf_field_layout` | 6-field layout matches doc-comment / circuit | `canonical_erc20_poseidon_leaf` |
| `erc20_poseidon::positive_canonical_symbol_at_max_length` | 6-byte symbol accepted (boundary) | same |
| `erc20_poseidon::positive_tree_round_trip_two_leaves` | 2-leaf Poseidon tree verifies both leaves | `PoseidonMerkleTree`, `verify_proof` |
| `erc20_poseidon::positive_tree_padded_three_leaves` | 3-leaf padding duplicates last leaf | `PoseidonMerkleTree::build` |
| `erc20_poseidon::positive_scalar_to_le32_round_trip` | `scalar_to_le32` → `Scalar::from_bytes` round-trips | `erc20_poseidon::scalar_to_le32` |

## Negative coverage (the important one)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `merkle::negative_domain_separation_leaf_vs_node` | "Leaf and inner-node domains are separated by the 0x00/0x01 prefix; an attacker who controls a leaf's canonical bytes cannot forge an inner node." | Computes `leaf_hash(L‖R)` (raw concat) and asserts it does **not** equal `node_hash(L,R)`. | `assert_ne!` passes — prefixes are distinct, so a leaf cannot mimic an internal node. |
| `merkle::negative_tampered_canonical_rejected` | "Flipping any byte of the canonical leaf bytes breaks `verify_proof`." | Mutates each byte position of a known canonical and verifies the proof rejects each variant. | Every mutated variant fails verify; the original passes. |
| `merkle::negative_tampered_sibling_rejected` | "Flipping any byte of any sibling in the proof breaks `verify_proof`." | Walks every proof level, flips bit 0 of byte 0, asserts reject, restores, repeats. | Each tampered sibling fails; restored proof verifies. |
| `merkle::negative_tampered_root_rejected` | "An expected_root that does not match the blob must not verify." | XORs a bit into the expected root. | Verify rejects. |
| `merkle::negative_wrong_index_rejected` | "Position binding: a valid proof for index i must not verify at index j ≠ i." | Uses index 3's proof but claims indices 4 and 2. | Both reject. |
| `merkle::negative_empty_leaves_panics` | "0-leaf trees have no well-defined root; `MerkleTree::build` panics so an attacker cannot fabricate a root for an empty entry set." | Calls `build(vec![])`. | `#[should_panic]` with the documented assert message. |
| `merkle::negative_build_does_not_rehash_inputs` | "`MerkleTree::build` takes leaf **hashes**, not canonical bytes — it must not rehash its input. A regression would silently change every shipped on-chain root." | Builds a 1-leaf tree from a synthetic 32-byte value and asserts `root() == input`. | Holds. |
| `merkle::negative_proof_out_of_range_panics` | "An out-of-range index passed to `proof` must surface (panic) rather than silently wrap or return a bogus list." | Calls `proof(99)` on a 4-leaf tree. | `#[should_panic]`. |
| `merkle::negative_padded_slot_ambiguity_is_documented` | "Bitcoin-style padding lets the last real leaf verify at the padded slot too — the runtime parser must gate on `entry_cnt` to refuse padded indices." | Builds 3-leaf tree, generates proofs for indices 2 and 3, asserts both verify against the root with the same canonical bytes. | Both verify (this pins the documented behaviour so a future "tighten the verifier" change cannot silently break the shipped trust anchor). |
| `erc20::negative_build_db_empty_json_rejected` | "An empty entry set must not yield a header claiming `entry_cnt = 0` with an attacker-chosen root." | Hands `build_db` a `[]` JSON file. | Errors with "no entries". |
| `erc20::negative_build_db_name_too_long_rejected` | "Names ≥ 256 bytes would silently truncate via `len as u8`, producing leaves the secure verifier cannot reconstruct." | 256-byte name. | Errors with "name too long". |
| `erc20::negative_build_db_symbol_too_long_rejected` | Same, but for symbol. | 300-byte symbol. | Errors with "symbol too long". |
| `erc20::negative_build_db_bad_address_length_rejected` | "Every address must parse to exactly 20 bytes; a short address must not produce a 20-byte zero-padded leaf." | `"0xabcd"`. | Errors with "40 hex". |
| `erc20::negative_build_db_non_hex_address_rejected` | "Non-hex address must be rejected at curation time." | `"0xZZZZ...Z"`. | Errors via `hex::decode`. |
| `erc20::negative_build_db_duplicate_chain_contract_rejected` | "Duplicate `(chain_id, contract)` rows must be rejected so an attacker can't substitute entry B at index of entry A via sort instability." | Two rows with identical chain+addr. | Errors with "duplicate". |
| `erc20::negative_build_db_same_contract_different_metadata_rejected` | "Same address on two chains with conflicting name/symbol is almost always a copy-paste typo; refuse so the trusted UI cannot show 'WETH' on chain A and 'DAI' on chain B for the same bytes." | USDC + DAI metadata at same address. | Errors with "multiple chains". |
| `erc20::negative_round_trip_tampered_entry_decimals_rejected` | "A single-byte tamper of the entries region must fail `round_trip_check`." | Flips the decimals byte from 18 to 6. | Errors (decimals mismatch or Merkle proof failure). |
| `erc20::negative_round_trip_wrong_root_rejected` | "`round_trip_check` must reject when the expected root doesn't match the recomputed one — this is the trust-anchor gate." | XORs a byte of the root. | Errors with "Merkle". |
| `erc20::negative_canonical_length_prefix_is_u8` | "Name/symbol length prefixes are u8 (1 byte). A future regression to varint or u16 would silently shift every byte after." | Builds canonical for a 255-byte name; asserts the prefix at offset 29 is `255` and the symbol prefix follows immediately. | Holds. |
| `erc20::negative_canonical_fields_each_affect_hash` | "Every field (`chain_id`, `contract`, `decimals`, `name`, `symbol`) must contribute to the leaf hash. An internal alignment gap would let an attacker substitute one field for another." | Six perturbations, each varying one field. | All six hashes differ from baseline. |
| `names::negative_build_db_empty_json_rejected` | Same as erc20. | `[]`. | Errors with "no entries". |
| `names::negative_build_db_empty_name_rejected` | "Empty-name entries would render zero-width labels, allowing a malicious bundle to hide an address." | `""`. | Errors with "empty name". |
| `names::negative_build_db_name_too_long_rejected` | "Names past `NAMES_MAX_LEN` cannot fit on the two-row OLED — refuse at curation time so the renderer never sees a truncated label." | 33-byte name. | Errors with "too long". |
| `names::negative_build_db_non_ascii_name_rejected` | "Non-printable bytes are a UI-injection vector (cursor moves / ANSI escapes / NUL terminators)." | JSON escape `` (BEL). | Errors with "non-printable". |
| `names::negative_build_db_high_byte_name_rejected` | Same property for high-bit bytes. | UTF-8 `"café"` (bytes 0xc3, 0xa9). | Errors with "non-printable". |
| `names::negative_build_db_duplicate_short_key_rejected` | "Two rows with the same `(chain_id, addr)` produce identical `short_key`s; sort stability would silently pick whichever came second." | Two rows identical except for name. | Errors with "duplicate". |
| `names::negative_short_key_chain_id_is_big_endian_not_little` | "`names_short_key` MUST hash `chain_id` big-endian; a regression to LE silently re-keys every wallet's name DB." | Computes both a BE-hashed and a LE-hashed short_key for chain_id 1, asserts they differ. | Differ. |
| `names::negative_short_key_wildcard_differs_from_real_chain` | "`chain_id = 0` (wildcard) and `chain_id = 1` at the same address must produce different short_keys or the fallback lookup path collides with a real entry." | Computes both. | Differ. |
| `names::negative_build_db_bad_address_rejected` | Same as erc20. | `"0xbeef"`. | Errors via `parse_hex_address`. |
| `names::negative_round_trip_tampered_short_key_rejected` | "Flipping a byte of any on-disk short_key breaks the binary search OR the Merkle proof." | Flips first byte of first entry. | Errors with "missing" or "Merkle". |
| `names::negative_names_max_len_frozen` | "Bumping `NAMES_MAX_LEN` past 32 cannot be incidental — it changes the trusted-UI rendering invariant." | Asserts `== 32`. | Holds. |
| `selectors::negative_build_db_empty_json_rejected` | Same as erc20/names. | `[]`. | Errors with "no entries". |
| `selectors::negative_build_db_short_selector_rejected` | "Selector must parse to exactly 4 bytes — a shorter prefix could substitute calldata[0..4]." | `"0xabcd"`. | Errors with "8 hex". |
| `selectors::negative_build_db_long_selector_rejected` | Same property, opposite direction. | `"0xa9059cbb00"`. | Errors with "8 hex". |
| `selectors::negative_build_db_non_hex_selector_rejected` | Non-hex must be rejected. | `"0xZZZZZZZZ"`. | Errors via `hex::decode`. |
| `selectors::negative_build_db_empty_text_sig_rejected` | "Blank sig would render as empty rows in the trusted UI." | `""`. | Errors with "empty". |
| `selectors::negative_build_db_text_sig_too_long_rejected` | "Past `SELECTOR_TEXT_SIG_MAX_LEN` can't fit across three 16-col rows + continuation marker — refuse so the renderer never sees a truncated sig." | 64-byte sig. | Errors with "too long". |
| `selectors::negative_build_db_non_printable_text_sig_rejected` | "Non-printable bytes are a terminal-escape injection vector." | JSON tab `\t`. | Errors with "non-printable". |
| `selectors::negative_build_db_duplicate_selector_rejected` | "Adversarial 4byte collisions must not reach the Merkle root — curator gates here so the secure-side trust anchor commits to a single canonical sig per selector." | Same selector, different sigs. | Errors with "duplicate". |
| `selectors::negative_round_trip_tampered_selector_rejected` | "Single-byte tamper of an on-disk selector must fail round-trip." | XORs 0xff into the first entry's selector. | Errors with "missing" or "Merkle". |
| `selectors::negative_text_sig_max_len_frozen` | "Bumping the UI ceiling cannot be incidental." | Asserts `== 63`. | Holds. |
| `erc20_poseidon::negative_empty_symbol_rejected` | "Empty symbol can't be packed into the field-element layout the circuit expects." | `b""`. | Errors with "symbol_len". |
| `erc20_poseidon::negative_oversize_symbol_rejected` | "Symbol past `MAX_SYMBOL_LEN = 6` cannot be packed; bumping the const requires a circuit-side change." | 7-byte symbol. | Errors with "symbol_len". |
| `erc20_poseidon::negative_non_printable_symbol_rejected` | "Non-printable bytes break the trusted UI display path." | BEL (0x07) embedded. | Errors with "printable ASCII". |
| `erc20_poseidon::negative_high_byte_symbol_rejected` | Same property, top-half byte. | 0x80 embedded. | Errors with "printable ASCII". |
| `erc20_poseidon::negative_tampered_leaf_rejected` | "Poseidon tree's trust property mirrors the SHA-256 tree — wrong leaf must not verify." | Swaps real leaf for `Scalar::from(99)`. | Reject. |
| `erc20_poseidon::negative_tampered_sibling_rejected` | "Tampered sibling must invalidate the proof." | Overwrites `proof[0]` with `Scalar::from(0xdead)`. | Reject. |
| `erc20_poseidon::negative_wrong_index_rejected` | "Position binding for the Poseidon tree mirrors the SHA-256 tree." | leaf 0's proof with index 1. | Reject. |
| `erc20_poseidon::negative_empty_leaves_panics` | Same as the SHA-256 tree. | `build(vec![])`. | `#[should_panic]`. |
| `erc20_poseidon::negative_symbol_packing_position_matters` | "Symbol is packed big-endian and right-padded with `0x20`. A regression to LE or left-pad would silently re-hash every leaf, breaking the circuit." | Compares `"AB"` vs `"BA"` and `"AB"` vs `"A"` in field f3 / f4. | Both pairs differ. |

## Production-code bugs surfaced by negative tests

None. Every negative test asserts the existing production code's
contract, and all pass. The
`negative_padded_slot_ambiguity_is_documented` test pins a known
property of Bitcoin-style padding (last-real-leaf verifies at both
real index and padded index); this is a *characteristic* of the
scheme, not a bug, and the runtime parser guards against it by
gating proofs on `entry_cnt` — not exploitable from the dbgen side.

## Coverage gaps deliberately left

- **`vks.rs`** — `vks::build_db` needs binary VK fixture files on
  disk (960 B and 1056 B blobs). Synthesising those would either
  require parsing a real Groth16 VK or hard-coding 1056 B of fixture
  in-test, neither of which adds load-bearing coverage beyond what
  `erc20.rs` + `merkle.rs` already exercise. A future pass with a
  ready-made `secure/data/vks/test-fixture.bin` would close this.
- **`poseidon.rs`** — already had a pre-existing test suite
  (poseidon{2,5,6,7}_vs_js, scalar_to_dec_round_trip) that pins the
  permutation against `poseidon-bls12381` JS reference vectors. Left
  untouched.
- **`main.rs` (the `dbgen` binary itself)** — runs `build_db` for
  each module, writes outputs, and renders `db_roots.rs`. The
  individual `build_db` round-trips are covered above; testing the
  binary end-to-end would require either subprocess spawning or
  factoring `main` into a library function. Either is invasive
  enough to wait for a follow-up.
- **`render_db_roots` / `emit_root`** — pure string formatting; not
  load-bearing for trust. A snapshot test of the rendered string
  would be appropriate but is low-priority.
- **Concurrent dbgen runs** — N/A: dbgen is a single-process build
  tool.

## Verification

- `cargo fmt -p dbgen --check` — **N/A (command requires user
  approval that was not granted in this session)**. The test code
  was written to match the formatting of the existing module.
- `cargo check -p dbgen` — **PASS** (also implicitly via `cargo test`).
- `cargo clippy -p dbgen --tests -- -D warnings` — **N/A (command
  requires user approval that was not granted in this session)**.
- `cargo test -p dbgen` — **PASS** (83 tests, 0 ignored, 0 failed).
- (firmware) on-target tests deferred: **no** — `dbgen` is a host-
  side build tool, all tests run on the host.

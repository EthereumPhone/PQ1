# Fuzz harnesses

Coverage-guided libFuzzer targets for PQSigner's pure-logic parsers.
The proptest sibling is `secure/src/fuzz_props.rs` (always-on, runs
under `cargo test`); this directory adds the coverage-guided variant
called out in `docs/trezor-comparison.md §2.4`.

This is a **standalone workspace** — `Cargo.toml` at the repo root
excludes `fuzz/` so cargo-fuzz's nightly + sanitizer requirements
don't bleed into the firmware build. You can ignore this directory
entirely unless you're actively fuzzing.

## One-time setup

```bash
cargo install cargo-fuzz       # 0.12+; uses libFuzzer
rustup install nightly         # cargo-fuzz needs nightly for -Z sanitizer
```

## Run a target

From this directory:

```bash
cd fuzz
cargo +nightly fuzz run aa_userop_parse_header
cargo +nightly fuzz run tx_core_rlp_decode_item
cargo +nightly fuzz run tx_core_eip1559_parse
cargo +nightly fuzz run tx_erc20_parse_calldata
cargo +nightly fuzz run tx_erc20_verify_bundle
```

libFuzzer runs until you `Ctrl-C` or it finds a crash; a crash
produces an artifact under `fuzz/artifacts/<target>/`. Reproduce
locally:

```bash
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hex>
```

For CI you typically want a bounded run:

```bash
cargo +nightly fuzz run <target> -- -max_total_time=600    # 10 minutes
```

## Targets, what they exercise, and the proptest cross-check

| Target | Function | Counterpart proptest |
|---|---|---|
| `aa_userop_parse_header` | `pqsigner_aa::userop::parse_header` — the SIGN_USEROP / CLEAR_SIGN wire-format parser CLAUDE.md §"Wire formats" describes | `fuzz_props::aa_userop_parse_header_never_panics` |
| `tx_core_rlp_decode_item` | `pqsigner_tx_core::rlp::decode_item` — foundational RLP decoder | `fuzz_props::rlp_decode_item_never_panics` |
| `tx_core_eip1559_parse` | `pqsigner_tx_core::eip1559::parse` — EIP-1559 envelope decoder | `fuzz_props::eip1559_parse_never_panics` |
| `tx_erc20_parse_calldata` | `pqsigner_tx::erc20::calldata::parse_erc20_calldata` — Solidity-ABI ERC-20 method dispatch | `fuzz_props::parse_erc20_calldata_never_panics` |
| `tx_erc20_verify_bundle` | `pqsigner_tx::erc20::bundle::verify_erc20_bundle` — Merkle-bundle verifier | `fuzz_props::verify_erc20_bundle_never_panics` |

Every target asserts the same single invariant: **the parser terminates in bounded time and returns a well-typed result for any input slice** — no panic, no OOB, no UB. Inputs reach these parsers across the NS→S trust boundary (USB host payload → NSC gateway → TOCTOU-snapshotted buffer), so any panic here is a direct DoS path from "anyone with a USB cable" to "secure-world halt."

## Seed corpora

Optional but useful for warming up libFuzzer's coverage map. None
checked in yet — add a few well-formed bytes under
`fuzz/corpus/<target>/` once you've identified high-value seeds.
Example for `aa_userop_parse_header`: a 330-byte hex blob from a
known-good `make e2e` UserOp would do it.

## What's *not* covered yet

The trezor-comparison §2.4 ask also called out **NSC pointer-
validation** (`secure/src/nsc/ptr_validate.rs`). That module lives
inside `secure::nsc` which is `#[cfg(all(feature = "se050",
not(test)))]`-gated at the crate root, so it isn't reachable from a
`[lib]`-style fuzz harness without first relocating it to a host-
buildable spot (similar refactor to `crate::scp03_logic`). Tracked
as a follow-up; the proptest harness in `fuzz_props.rs` doesn't
cover `ptr_validate` either, so the gap is the same in both
directions.

## When this finds something

1. Reproduce locally with the artifact from `fuzz/artifacts/`.
2. Open the failing input — if it's a 1-block panic, it's almost
   certainly an arithmetic overflow / unchecked slice index.
3. Write a regression `#[test]` in the relevant `fuzz_props.rs`
   `proptest!` block (one specific failing input, not a generator)
   so the fix is permanent.
4. Save the artifact to `fuzz/corpus/<target>/` so libFuzzer never
   regresses on the same shape.

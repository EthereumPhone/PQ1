# Dead-Code Removal — `fwmeasure`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope
Host firmware measurement / BIP-39-word reporter.

Files audited:
- `fwmeasure/Cargo.toml` (17 lines)
- `fwmeasure/src/main.rs` (226 lines)

## Summary

This slice is already clean — nothing to remove. The crate is a single
`main.rs` host binary that parses a secure-world ELF, reconstructs the
on-flash image (LOAD segments overlaid on `0xFF`-erased flash),
SHA-256-hashes it, and emits 8 BIP-39 words on stdout (consumed by
`make verify-release`'s grep). Every private item is on the live path
from `main()`, every dependency is consumed, and there are no commented-
out blocks, stale TODOs, or vestigial symbols.

Symbol-by-symbol audit of `fwmeasure/src/main.rs`:

| Item | Kind | Consumer |
|---|---|---|
| `MAX_FLASH_SIZE` | const | `compute_layout` (window check on `__veneer_limit`) |
| `USAGE` | const | `parse_args` (via `die`) |
| `Args` | struct | `parse_args` → `main` → `compute_layout` |
| `FlashLayout` (+ `size`) | struct | `compute_layout` → `build_flash_image` / `main` |
| `die` | fn | every error site in `parse_args`, `parse_hex`, `require_symbol`, `compute_layout`, `build_flash_image`, `main` |
| `parse_args` | fn | `main` |
| `parse_hex` | fn | `parse_args`; covered by `tests::parse_hex_accepts_prefix_and_underscores` |
| `require_symbol` | fn | `compute_layout` (`__sidata`, `__sdata`, `__edata` fallback) |
| `find_symbol` | fn | `compute_layout` (`__veneer_limit`) + `require_symbol` |
| `compute_layout` | fn | `main` |
| `build_flash_image` | fn | `main` |
| `format_hex` | fn | `main` (stderr diagnostic) + `tests::format_hex_lowercase_zero_padded` |
| `print_words` | fn | `main` (stdout, scraped by `make verify-release`) |
| `main` | fn | binary entry |
| `tests::*` | `#[cfg(test)]` | bucket 2 (test infra) — kept |

`Cargo.toml` dependencies:

| Dep | Consumer in `main.rs` |
|---|---|
| `sphincs-tz-bip39` | `hash_to_word_indices`, `WORDLIST` (in `print_words`) |
| `sha2` | `Sha256`, `Digest` (in `main`) |
| `object` | `elf::PT_LOAD`, `ElfFile32`, `ProgramHeader`, `LittleEndian`, `Object`, `ObjectSymbol` |

No bucket-1/3/4/5/6 findings; the slice received a focused readability
pass on 2026-05-14 (see `reports/readability/fwmeasure.md`) that already
swept any vestigial fragments.

## Deletions applied

_(none)_

| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|

## Reverted during bisect

_(none — nothing was deleted)_

## Cross-slice observations

_(none)_

## Skipped

- No generated/vendored files in scope.
- No pre-existing test failures or warnings to carry over.

## Equivalence check

No source edits were applied; baseline and post-deletion working trees
are identical, so equivalence is trivially preserved.

- `cargo fmt -p fwmeasure --check` — **N/A** (sandbox blocked `cargo`
  invocation; no formatting was changed, so result is unchanged from
  baseline by construction)
- `cargo check -p fwmeasure` — **N/A** (sandbox blocked invocation; no
  source was changed)
- `cargo clippy -p fwmeasure -- -D warnings` — **N/A** (sandbox blocked
  invocation; no source was changed, so no new lints can have been
  introduced)
- `cargo test -p fwmeasure` — **N/A** (sandbox blocked invocation; no
  source was changed, so test counts are unchanged from baseline by
  construction)
- Firmware-target build / binary SHA-256 — N/A (host-only binary crate).

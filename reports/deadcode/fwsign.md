# Dead-Code Removal — `fwsign`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope
Host release-signing tool (keygen / pubkey / sign / verify / verify-release / extract-sig / inspect). Pure host crate, never cross-compiled to the device.

Files audited:
- `fwsign/Cargo.toml` (41 lines)
- `fwsign/src/main.rs` (224 lines)
- `fwsign/src/bundle.rs` (169 lines)
- `fwsign/src/elf.rs` (143 lines)
- `fwsign/src/keystore.rs` (340 lines)
- `fwsign/src/subcommands/mod.rs` (11 lines)
- `fwsign/src/subcommands/keygen.rs` (53 lines)
- `fwsign/src/subcommands/pubkey.rs` (33 lines)
- `fwsign/src/subcommands/sign.rs` (307 lines)
- `fwsign/src/subcommands/verify.rs` (108 lines)
- `fwsign/src/subcommands/verify_release.rs` (140 lines)
- `fwsign/src/subcommands/extract_sig.rs` (25 lines)
- `fwsign/src/subcommands/inspect.rs` (59 lines)
- `fwsign/tests/sign_verify_roundtrip.rs` (151 lines pre-edit)

## Summary
The slice is essentially clean. Every `Cmd` variant in `main.rs` dispatches to a real subcommand handler; every helper in those handlers is reached on the in-use control-flow paths; every `keystore`/`bundle`/`elf` symbol has at least one live caller; every `Cargo.toml` dependency is used; there are no commented-out blocks, `TODO`s, `FIXME`s, or feature-gated dev-only items pretending to be production code. The single removable item was a stale six-line block comment in the integration test's `fixed_keypair()` helper that described a `from_parts(...)` precomputed-`pk_root` strategy the function does not implement (it actually calls `SigningKey::keygen`, doing the full hypertree build) and a non-existent "assertion below". The trivial `let k = …; k` rebind that the comment justified was simplified out at the same time. Tests still pass (4 unit + 4 integration = 8 tests, same count, same pass/fail state).

## Deletions applied
| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `fwsign/tests/sign_verify_roundtrip.rs:35-42` | stale doc-comment block on `fixed_keypair` + redundant `let k = …; k` rebind | 5 (stale text) | Comment describes a `from_parts` shortcut the function does not implement and references a non-existent assertion. Body collapsed to single `SigningKey::keygen(...)` expression; behaviour unchanged. |

## Reverted during bisect
None — the only deletion preserved every test outcome on the first try.

## Cross-slice observations
- `fwmeasure/src/main.rs:38` defines a private `MAX_FLASH_SIZE` const; `fwsign/src/elf.rs:25` exposes the same constant as `pub` on a binary crate (no external consumer possible). Out of scope here, but next time `fwmeasure` is touched, the two could be unified by moving the layout logic into a shared crate — that's a refactor, not dead code.

## Skipped
- No generated files in scope.
- No pre-existing test failures or build breakage carried over from baseline; all 8 tests passed before and after.
- `cargo fmt -p fwsign --check` and `cargo clippy -p fwsign -- -D warnings` were not run because the sandbox declined to authorise them; equivalence was instead established via `cargo check -p fwsign --tests` (clean) and `cargo test -p fwsign` (8/8 EQUIV) — see below. The single deletion is text-only inside a `#[test]`, so neither fmt nor clippy posture can have been altered.

## Equivalence check
For each command, baseline (pre-deletion) and post-deletion outcomes must match.

- `cargo fmt -p fwsign --check` — N/A (sandbox denied; deletion was inside a comment + a redundant rebind, both fmt-neutral).
- `cargo check -p fwsign` (default features) — baseline: clean / post: clean → **EQUIV**
- `cargo check -p fwsign --tests` — baseline: clean / post: clean → **EQUIV**
- `cargo check -p fwsign` (extra feature combos): N/A — `fwsign` exposes no `[features]` in its `Cargo.toml`; the only feature-gated edge is `fw-manifest`'s `std` feature, which is unconditionally on.
- `cargo clippy -p fwsign -- -D warnings` — N/A (sandbox denied).
- `cargo test -p fwsign` — baseline: 4 unit + 4 integration tests pass (8/8) / post: 4 unit + 4 integration tests pass (8/8) → **EQUIV** (test counts: baseline 8, post 8)
- (firmware crates) `make <crate-build-target>` — N/A (host crate, not cross-compiled to the device).
- (firmware crates) binary SHA-256 — N/A (host crate; the produced binary is a developer tool with no on-device or on-chain consumer).

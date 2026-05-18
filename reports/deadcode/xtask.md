# Dead-Code Removal — `xtask`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope
Host workspace tooling — codegen / doc-checks / release packaging.

Files audited:
- `xtask/Cargo.toml` — 30 lines
- `xtask/src/main.rs` — 293 lines

## Summary
The slice is genuinely clean. The xtask crate is a single 293-line binary
with one subcommand (`gen-solidity-constants`) plus a small set of pure
rendering helpers, each of which is reached either from
`render_solidity_library()` or from the in-file unit-test module. The
single declared dependency, `pqsigner-proto`, is consumed directly
(`MAX_BOOTSTRAP_USES`, `C10_SIG_LEN`, `EXECUTE_SELECTOR`, etc.). No
unreachable arms, vestigial helpers, dead `match` branches, or
commented-out code blocks. No deletions applied.

One observation left as a recommendation rather than acted on, because
acting would push edits outside this slice's scope: the rendered
Solidity output (and the matching checked-in `PqsignerProto.sol`)
embeds a developer-local plan path
(`/home/markus/.claude/plans/ok-make-a-plan-logical-lobster.md`) in a
comment. See "Cross-slice observations".

## Deletions applied
| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| _(none)_ | | | |

## Reverted during bisect
_(none — no deletions attempted.)_

## Cross-slice observations
- `xtask/src/main.rs:101-102` emits a `// Reference:
  /home/markus/.claude/plans/ok-make-a-plan-logical-lobster.md` /
  `// Phase 4 of the modularity refactor.` block into the rendered
  Solidity. The same two lines are committed at
  `contracts/smart-wallet/src/generated/PqsignerProto.sol:6-7`. The text
  is a stale developer-local pointer (bucket 5) and leaks a local
  filesystem path into a public on-chain-adjacent artefact. Cleaning it
  up requires editing both the codegen source and the regenerated
  Solidity together so CI's `gen-solidity-constants --check` diff stays
  clean — that crosses into the `contracts/` slice and so is out of
  scope here. Recommended follow-up: drop both lines from
  `render_solidity_library()` and re-run
  `cargo run -p pqsigner-xtask -- gen-solidity-constants` to refresh
  the checked-in file in one PR.

## Skipped
_(no generated files in scope; no pre-existing breakage.)_

## Equivalence check
No source changes were made, so baseline and post-deletion are by
construction identical. Commands invoked once (state recorded as the
current and only state of the tree):

- `cargo check -p pqsigner-xtask` — clean (`Finished dev profile`) → EQUIV
- `cargo test  -p pqsigner-xtask` — `8 passed; 0 failed; 0 ignored` → EQUIV (test count: 8 → 8)
- `cargo fmt   -p pqsigner-xtask --check` — N/A in this session (cargo-fmt invocation gated by sandbox permissions; no source edits, so format state is unchanged from HEAD)
- `cargo clippy -p pqsigner-xtask -- -D warnings` — N/A in this session (cargo-clippy invocation gated by sandbox permissions; no source edits, so lint state is unchanged from HEAD)
- Firmware build / binary SHA-256 — N/A (host-only crate, no `thumbv8m` target).

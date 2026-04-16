# Research Bundles

Self-contained files for driving AI deep-research sessions on PQSigner
hardening questions. Each bundle is a single markdown file containing:

1. **The research question** (at the top, so the model sees it first).
2. **A condensed project briefing** — architecture, trade-offs,
   accepted invariants, style guidance.
3. **Relevant source code + docs** inlined from the repo, so the
   session can critique specific code paths without needing repo
   access.

## How to use

```
1. Pick the prompt you want researched.
2. Upload the corresponding `{LETTER}-*.md` file to your AI deep-
   research tool (Claude web, Gemini Deep Research, etc.) as the
   *only* attachment.
3. Send an empty or minimal message ("Please research the question at
   the top of the attached file.") — the question text is already in
   the file header.
4. When the result comes back, save it as e.g. `results/A-fault-
   injection.result.md` in this directory, or wherever you prefer.
```

Each bundle is 50-120 KB of markdown. Well under typical file-upload
limits (Claude web supports ~30 MB per attachment / 200k tokens of
conversation context).

## The research tracks

| Letter | Topic | Primary code bundled |
|---|---|---|
| **A** | Fault-injection resistance for PQ signing + PIN path | `dual_se.rs`, `sign_and_emit.rs`, `cmd_request_unlock.rs`, `state.rs`, `crypto.rs` |
| **B** | Production key management (SCP03 rotation, PBS wrap, HUK-SAES) | `se050/scp03.rs`, `optiga/shield.rs`, `hw/flash.rs`, `docs/se050-factory-reset.md` |
| **C** | SLH-DSA side-channel landscape on Cortex-M33 | `crypto.rs`, `sign_and_emit.rs`, `cmd_sign_userop.rs`, `secure/Cargo.toml` |
| **D** | USB stack hardening for USB-C-only design | `hw/usb_hw.rs`, `nonsecure/src/usb/*`, `docs/usb-protocol-v2.md` |
| **E** | Supply-chain + provisioning attestation | `docs/architecture.md`, `docs/pq-aa-wallet-design.md`, `docs/HARDENING.md` |
| **F** | Comparison against Trezor Safe 7 (Oct 2025) | `README.md`, `CLAUDE.md`, `docs/architecture.md`, `docs/pq-aa-wallet-design.md`, `docs/HARDENING.md`, `docs/brownout-hardening.md`, `docs/production-security.md`, `docs/ai-research-briefing.md`, `dual_se.rs`, `nsc/mod.rs` |

All tracks are orthogonal and can be run in parallel (one
conversation per bundle). Results feed back into
`docs/brownout-hardening.md`, `docs/work-todo.md`, and the
architecture docs.

## Regenerating bundles after code changes

The bundles are snapshots of the code. When relevant files change, re-
run the builder:

```
bash docs/research-bundles/build.sh
```

This regenerates all five from the current tree.

## Maintenance

- **`build.sh`** is the source of truth for which files go into which
  bundle. Edit it to add/remove files from a bundle; then re-run.
- **Condensed preamble** (architecture + trade-offs) lives in the
  `write_preamble` function inside `build.sh`. Edit there when the
  project architecture materially changes; the edit propagates to all
  five bundles on next build.
- **Question text** lives in the per-bundle `make_bundle_X` heredoc at
  the top of each case. Edit there to refine a prompt.

## Why this shape

The single-file-per-prompt structure solves three problems:
- **Privacy**: the repo is private and we can't share a link. One
  attachment per session is manageable.
- **Self-contained**: each bundle stands alone. Claude web doesn't
  need to load a separate briefing file or ask clarifying questions
  about architecture.
- **Reproducible**: `build.sh` regenerates identical bundles from a
  given commit, so results can be correlated with the exact code
  snapshot that was researched.

The trade-off is size duplication: each bundle ~50 KB contains the
~4 KB project preamble. For five bundles that's ~20 KB of duplicated
text. Negligible.

## After results arrive

Create a `docs/research-bundles/results/` subdirectory (not yet made)
and drop the output markdown from each session in as
`{LETTER}-{topic}.result.md`. When enough results have accumulated,
synthesise findings into:
- `docs/brownout-hardening.md` updates for hardware-supervisor advice
- `docs/work-todo.md` line items for new gaps
- New top-level design docs for architectural changes (e.g., a
  `docs/supply-chain.md` informed by bundle E's output)

Git history + commit messages should tie result files to their
originating bundle commit so we always know which code state was
researched.

# Readability & Excellence Review — `secure`

_Date_: 2026-05-14
_Reviewer_: Claude Code (ultrathink)

## Summary

`sphincs-tz-secure` is the project's flagship crate (132 Rust files, ~26.5 k LOC) and is in unusually good shape for its size: explicit `unsafe` taxonomy with mostly justified `// SAFETY:` comments, an `unsafe`-encapsulated MMIO layer (`hw::mmio`), `Zeroize`/`subtle` everywhere secrets touch, dense feature-flag fences with informative `compile_error!`s, and 118 passing host-side property / unit tests. The crate already follows almost every rule in the project's "What NOT to do" list. Most of what's left is **comment hygiene** — module-level docs were written as PR notes ("Phase 5 PR 5.3 moved …"), not as present-tense documentation. The audit therefore focused on trimming PR-anecdote prose, adding a missing `# Safety` doc on `sau.rs::configure_sau_region`, and pinning one previously-floating `unsafe` block's safety justification. No behaviour, ABI, KDF tag, or invariant changed. The non-trivial follow-ups (splitting `cmd_sign_userop.rs` / `hw/flash.rs`, pruning the cfg-test "unused import" noise, escalating `tamp` to wipe) are listed under "Recommendations not applied" because each is too big or invariant-touching for a comment-quality pass.

## Changes applied

- `secure/src/aa/mod.rs:1-13,38-41` — rewrote the "Phase 5 PR 5.2 of the modularity refactor moved …" prelude into a present-tense statement of what `pqsigner-aa` is and why this module is a shim. Trimmed the trailing CRIT-5 audit-finding anecdote to a forward-looking description of the trust model.
- `secure/src/crypto.rs:1-22` — same PR-anecdote rewrite. Module doc now describes the split, not the historical commit; intradoc links (`[`pqsigner_domain`]`, `[`crate::fi`]`) replace prose paths.
- `secure/src/tx/mod.rs:1-15` — dropped "Phase 5 PR 5.1 of the modularity refactor" framing; kept the substantive note about which submodules remain secure-world-bound.
- `secure/src/erc20/mod.rs:1-7`, `secure/src/names/mod.rs:1-6`, `secure/src/selectors/mod.rs:1-6` — same trim across the three trust-gate shims.
- `secure/src/pin.rs:1-5` — replaced the outer `///` doc that pointed at "desktop/src/main.rs lines 320-460" with an inner `//!` module doc (correct rustdoc target) that names the actual callers.
- `secure/src/secure_element.rs:1-7` — converted the top `///`-block (which rustdoc was rendering against the first item, not the module) to a proper `//!` module-doc.
- `secure/src/sau.rs:19-27` — added a `# Safety` paragraph to `unsafe fn configure_sau_region` documenting the single-threaded-boot precondition and the alignment/overlap requirements; previously it was bare `unsafe fn` with no contract.
- `secure/src/measured_boot.rs:43-50` — added the missing `// SAFETY:` comment immediately above the `unsafe { core::ptr::addr_of!(__veneer_limit) … }` line. The justification existed lower down in `firmware_hash`, but the lone `unsafe` at `flash_end` was uncommented.
- `secure/src/nsc/mod.rs:84-98` — dropped the dangling `Reference: /home/markus/.claude/plans/ok-make-a-plan-logical-lobster.md` user-local path from the production-feature `compile_error!` rationale. The justification text stays; only the dead pointer is gone.

## Recommendations not applied

These are real but out of scope for a comment-hygiene pass — each either touches an invariant, requires a ≥300-line refactor, or affects cross-crate API:

- **Split `secure/src/nsc/cmd_sign_userop.rs` (1329 lines).** CLAUDE.md already calls this out as the unified Type 1 / Type 2 sign handler. It deserves a per-section module (`parse`, `t1_emit`, `t2_emit`, `display_dispatch`, `wire_emit`) but the wire-format / invariant surface is delicate and the split should happen alongside a re-derivation review, not as part of a readability sweep.
- **Split `secure/src/hw/flash.rs` (1392 lines).** Bank-1 page-123 off-chain log + page-124 PIN counter + page-125 admin-wipe flag + page-126 PBS + FW-update bank-2 primitives all share one file. Splitting them is straightforward mechanically but each function is called from cfg-fenced code paths and the public surface is consumed by `offchain_state`, `nsc`, `fw_update`, and the dual-SE driver.
- **`secure/src/main.rs:6` — `#![cfg_attr(not(test), feature(cmse_nonsecure_entry))]` triggers `unused_features` because the actual veneer attribute is only emitted inside `nsc/` modules.** A `#[allow(unused_features)]` would silence it, but the cleaner fix is to also feature-gate the attribute on `target_arch = "arm"` so host builds don't even see it.
- **Cargo.toml comment churn.** Roughly half of `secure/Cargo.toml` is feature-flag documentation written like commit messages ("Phase-8 PR 1 — axis aliases", "work-todo #20 Stage A"). All useful, but rotting on a per-PR cadence. A pass that collapses these into a single `docs/feature-flags.md` and shrinks the Cargo.toml comments to a one-liner per flag would help — too large for this audit.
- **79 `cargo build` warnings** under `mock-se,debug-log,ui-semihosting` (the default Make build). Almost all are `unused_import` / `dead_code` in pub-reexport shims (`aa::eip1271`, `aa::eip6492`, etc.) that *are* used on the device path. Adding `#[allow(unused_imports)]` to each shim would silence the noise without hiding genuine dead code; preferred fix is to flip the shims to `#[cfg(not(test))] pub use …` so they only exist where consumers do.
- **`tamp` IRQ handler is still log-only on this branch.** `CLAUDE.md` explicitly flags this as a Pre-Production Caveat awaiting `trigger_lockout_wipe()` wiring. Not for this pass.
- **`secure/src/offchain_state.rs:37-60,117-207` — the mock backend exposes seven `pub unsafe fn`s that internally touch `static mut TABLE`.** The `unsafe` is structurally required by the type-signature parity with `hw::flash`, but every internal call could be wrapped behind a tiny `with_table` helper to remove the per-function `core::ptr::addr_of_mut!` boilerplate. Improvement, but visible API change to a hot-path module.

## Verification

- `cargo fmt -p sphincs-tz-secure --check` — **N/A** (tool requires interactive approval in this session; no whitespace-affecting edits were made — every change is inside doc comments).
- `cargo clippy -p sphincs-tz-secure -- -D warnings` — **N/A** (same approval gate). No new clippy lints introduced (doc-comment-only diff).
- `cargo test -p sphincs-tz-secure --tests --release` — **PASS** (118 passed; 0 failed; 0 ignored; pre-change baseline matched post-change).
- `make secure` (i.e. `cargo build --target thumbv8m.main-none-eabi -p sphincs-tz-secure --no-default-features --features mock-se,debug-log,ui-semihosting`) — **PASS** (release build succeeds; warning count unchanged at 79).

## What this crate already does well

- **`unsafe` taxonomy is explicit.** CLAUDE.md enumerates five required and one avoidable category; the codebase tracks them. CMSE veneers, NS-pointer derefs after `NsPtr<T>` validation, SHA-256 extern hooks, FI volatile helpers, and the `hw::mmio::{Reg32, RoReg32}` encapsulation all consistently use the categories.
- **FI hardening is real, not theatre.** `crypto::c10_sign_verified_with_progress` doesn't just call `sphincs_c10::verify`; it routes the boolean through `fi::check_true_into_sentinel`, wraps with `wait_random()`, and a `core::hint::black_box` defeats LLVM's CSE — with a comment that cites the SCA finding that motivated it (F-1).
- **Property tests where it matters.** `fuzz_props` hammers every byte-eating parser (APDU TLV, EIP-1559, ERC-20 / name / selector bundles, AA userop header, firmware-update ref chain) with proptest. Every parser is panic-free by construction.
- **Mutual-exclusivity is enforced at compile time, not in docs.** `nsc/mod.rs:101-265` is a wall of `compile_error!`s with prose messages naming the exact files/Make recipes the user should look at next. A wrong feature combo gives a paragraph-long explanation, not a cryptic linker error.
- **Reset-cause classification has unit tests** (`reset_cause.rs:156-216`) covering every branch and the `is_abnormal` matrix.
- **NIST KATs are first-class.** `cmac.rs` runs the full SP 800-38B Appendix D.3 vector set plus boundary cases on `kdf_cmac_counter_generic` (label-too-long, output-too-long, max-valid, empty output).
- **`shared::CMD_*` is documented in tabular form in `nsc/mod.rs`** so the wire-protocol surface is grokkable from a single screen.

## Cross-crate observations

- `bls12_381_pka` emits five `#[must_use]` attribute warnings on trait-method impls (`scalar.rs:652,657`, `g1.rs:982`, `g2.rs:1127`, `pairings.rs:481`). The compiler explicitly says this will become a hard error in a future release. The fix is to move `#[must_use]` onto the trait definitions themselves, not the impl blocks.
- `aa/mod.rs:42-43` re-exports `pqsigner_aa::eip1271` and `pqsigner_aa::eip6492` that show up as "unused import" in the default Make build — they *are* consumed on the device path (via `cmd_sign_offchain` and the EIP-6492 wrapper). Same pattern in `tx/mod.rs:31` for `hash`, and in `erc20/mod.rs`, `names/mod.rs`, `selectors/mod.rs`. Cleaner fix in the parent shim crates (`pqsigner-aa`, `pqsigner-tx-core`, `pqsigner-tx`) would be to gate the test-only sub-items so the re-exports don't dangle, but every consumer crate is also under audit.
- The "Phase 5 PR 5.X" framing isn't unique to `secure/` — the workspace-extracted crates (`pqsigner-aa`, `pqsigner-tx-core`, `pqsigner-domain`, `pqsigner-tx`) likely have the mirror-image PR-anecdote on their own `lib.rs`. Worth a coordinated pass.
- `hal` crate is referenced from CLAUDE.md's key-file map but `secure/` itself does not consume it (it deals in concrete drivers, not the trait surface). Consider re-positioning `hal` in the file map as a *future* trait shim, not a current dependency, to avoid confusion.

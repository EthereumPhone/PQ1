# Handoff — ERC-7730 / ERC-8213 Clear-Signing, Phase 5 (final phase)

Date written: 2026-05-14. Last firmware status: Phases 1–4 complete on `master` (`cfb0e89` is the most recent Phase-4 commit).

This is the "start here" doc for the next implementer picking up **the final phase of the clear-signing initiative**. Phase 4 (`cfb0e89`) shipped the on-device renderer, ERC-8213 fingerprint pages, and the EIP-712 typed offchain sign completion. Phase 5 closes the remaining audit-grade polish, companion tooling, tests, docs, and the registry-mirror handoff so the firmware is ship-ready.

Original plan (`~/.claude/plans/carefully-read-understand-this-transient-feigenbaum.md`) split the trailing work into Phases 5+, 7+, 8+, 9+ (consolidated to 5 in the 2026-05-14 plan). This handoff **merges all remaining items into a single final phase** — there is no Phase 6.

## What's left

Twelve buckets in rough priority order. Items marked **MUST** block production; items marked **SHOULD** are nice-to-have but unblock the audit trail; items marked **MAY** are pure quality-of-life.

### 1. **MUST** — Flip production attestation gate

`secure/data/erc7730/policy.toml` currently has `allow_unattested_dev_descriptors = true`. CI must gate shipped firmware on `false`. The flip is conditional on landing the registry mirror (item 2) so the seed corpus has an attestation chain to anchor against; until then the dev gate is `true` everywhere except a CI matrix entry that builds with the production policy and confirms the seed corpus rebuilds clean.

### 2. **MUST** — Registry-mirror submodule

`secure/data/erc7730/*.json` is a hand-pulled 8-descriptor slice from the ethereum/clear-signing-erc7730-registry. Production needs:

- Submodule pointing at a vendored fork of the registry pinned to a known good SHA.
- `dbgen::erc7730::compile_descriptor` extended to follow `includes` references (currently rejected — see `dbgen/src/erc7730.rs` "includes resolution" comment). The registry's ERC-2612 permit templates live in `includes`; without resolution we cannot ingest them.
- `xtask gen-erc7730-descriptors` re-runs against the submodule head to regenerate `ERC7730_DESCRIPTORS_ROOT`.

### 3. **MUST** — Cargo feature `erc7730-dev-unattested`

Add a `[features]` entry that gates the renderer to accept descriptors that fail the attestation policy. Required for the bring-up phase (developers loading custom descriptors without an attestation chain); MUST be `compile_error!`-fenced against `mode-production` in `secure/src/nsc/mod.rs` (mirrors the existing `debug-log` / `e2e-test` / `mock-se` / `otp-hardcoded-master-key` / `ui-capture` fences).

### 4. **MUST** — Wire the EIP-712 typed sign through `make e2e`

Phase 4's `cmd_sign_offchain.rs` kind=2 path is exercised at compile time but no e2e scenario drives it through QEMU. Add Scenario 5p in `nonsecure/src/e2e_test.rs`:
- Permit2-style EIP-712 typed sign for WETH-Sepolia (matches the existing `tools/companion-stub/erc7730_db_e2e.bin`).
- Companion-side trailer assembly mirrors Scenario 5m but with `kind = OFFCHAIN_KIND_EIP712_TYPED` + domain_separator + primary_type_hash + encoded_data.
- Assert the secure-world log shows the descriptor match + the EIP-712 final hash on a fingerprint page that matches an independent `viem` reference computed at NS build time.

### 5. **SHOULD** — Full `AbiView` build for dynamic types + nested-calldata recursion

Phase 4 ships a direct path-walker that only handles static types (uint256, address, bool, bytes32, static tuples). Dynamic types (bytes, string, dynamic arrays, dynamic tuples) need:

- Per-format type signature carried in the on-device IR. Two options:
  - (a) Extend the IR format header with a u8 type-encoding byte per field. Wire-format change — invalidates `ERC7730_DESCRIPTORS_ROOT`.
  - (b) Carry the format-key string in the IR (host emitter parses it; on-device renderer parses it). Larger but no positional ABI assumptions.
- Recommendation: **(a)** with a "shape descriptor" byte per field (uint / address / bool / bytesN / bytes / string / tuple-static / tuple-dynamic / array-static / array-dynamic). The walker then knows how to interpret the slot.
- Once shape descriptors are on-wire, `secure/src/tx/display/erc7730/calldata_nested.rs` upgrades from its current `Reject("nested calldata p5")` stub to a depth-bounded recursion (cap at 4, walker's `MAX_NESTING = 8` is the inner cap).

This is the longest item in the bucket. If time is tight, ship Phase 5 without it and call it Phase 6; otherwise consolidate.

### 6. **SHOULD** — FI-hardened cross-check pairs

`secure/src/tx/erc7730.rs` re-exports `cross_check_contract` / `cross_check_eip712` from `pqsigner-erc7730`. Both run as a single boolean check today. Migrate the callers in `cmd_sign_userop.rs:478-493`, `cmd_sign_userop_batch.rs:245-260`, and `cmd_sign_offchain.rs:330-350` to the `crate::fi::check_true_into_sentinel` idiom that the existing C10 verify-before-release pattern uses (`crypto::c10_sign_verified*`). Double-evaluated with `wait_random` between calls; sentinel-encoded return so a single fault cannot defeat the gate.

### 7. **SHOULD** — Cyfrin `clearsig` Python parity scripts

`tools/cross_parity_erc7730.py`: ingest `secure/data/erc7730/*.json`, run through Cyfrin's `clearsig` reference renderer, compare against the firmware's on-device output (via QEMU's `ui-capture` SHA-256 dumps). `tools/cross_parity_erc8213.py`: independent viem + safe-hash-rs vector regeneration of the fingerprint hashes for cross-implementation parity.

Run both in CI on every PR that touches `secure/data/erc7730/` or `pqsigner-erc7730/`. The Python pipeline catches semantic-equivalence drift; the host-side Rust round-trip catches wire-format drift.

### 8. **SHOULD** — UI capture fixtures + sign-time benchmark

`tests/ui_fixtures_erc7730.json`: one fixture per FormatOp (14 entries) + one per nested-calldata scenario + one per fingerprint Kind, each pinning a SHA-256 of the `ui-capture` frame. Generate by running QEMU under `--features ui-capture` once; manually verify the rendered text is correct; pin the SHA-256.

`make test-key-speed` (DWT-timed signing bench): assert the ERC-7730 renderer adds ≤ 30 ms to a Type-2 sign on a cached slot. The walker is bounded (`MAX_NESTING = 8`, ≤ 24 fields per format), but the worst-case page-emit cost across 14 formatters benefits from a measured ceiling so future changes don't accidentally blow the budget.

`make e2e-erc7730-hw`: drive the e2e scenarios over `probe-rs` on real STM32U585 (matches the existing `make play-hw-display` arrow-key forwarder). Validates that the renderer's stack budget + render time hold on real silicon.

### 9. **SHOULD** — Fuzz harness extension

`fuzz/fuzz_targets/erc7730_walker.rs` covers `walker::resolve_program` against adversarial path bytes. Extend with two more harnesses:
- `fuzz/fuzz_targets/erc7730_params_parse.rs` — drives `tx::erc7730_render::params::parse` against adversarial TLV blobs. **Blocker**: the parser lives in `secure/src/tx/erc7730_render/`, which `pqsigner-fuzz` does not depend on. Move `params` + `visibility` into `pqsigner-erc7730/src/{params,visibility}.rs` (the `RenderErr` type moves too, or splits into a parser-level `ParamError` + a renderer-level `RenderErr` wrapper).
- `fuzz/fuzz_targets/erc7730_render_dispatch.rs` — drives `display::erc7730::render_erc7730_pages` against a fixed VerifiedDescriptor + arbitrary `inner_data`. Blocker: depends on `Pages` which lives in `display::*`, gated `#[cfg(not(test))]`. Either: (a) ungate `Pages` (it has no UI hardware dep — just a type alias over `[[u8; 16]; 4]`) or (b) build a host-test-only `Pages` shim in `pqsigner-fuzz`.

Recommendation: do (a) for `Pages` — move the type to a non-gated module (e.g., `secure/src/display_buffer.rs` or back to `crate::tx::display::pages`) so unit tests + fuzz harnesses can reach it. The hardware-bound `confirm()` call stays gated separately.

### 10. **SHOULD** — Docs

Three new files + three updates:

- `docs/erc7730-integration.md` (new): full spec of the on-device IR, trailer format, formatter coverage, what is and is not verified on-device. Include the "what NOT to do" footnote about ERC-8176 verification staying host-only (preserves invariant #5).
- `docs/erc8213-fingerprints.md` (new): cross-device verification recipe with `cast` / `viem` / `safe-hash-rs` examples for each `Kind` variant.
- `docs/companion-erc7730-integration.md` (new): trailer format from the companion side, lookup flow against `tools/companion-stub/erc7730_db.bin`, attestation policy file format.
- `README.md` (edit): mention `clearsigning.org` support, link the new docs.
- `CLAUDE.md` (edit): add an entry to "Key File Map" for `pqsigner-erc7730/`, `secure/src/tx/erc7730_render/`, `secure/src/tx/display/erc7730/`, and `secure/src/tx/display/erc8213.rs`. Update "What NOT to do" to clarify "no on-device 8176 verification" and "no PersonalSign-of-pre-wrapped-hash inversions" (i.e., dapps that hard-check `wallet.isValidSignature(replaySafeHash(H), sig)` would double-wrap — that's a dapp bug, not a firmware bug, but worth documenting).
- `docs/usb-protocol-v2.md` (edit): document `OFFCHAIN_KIND_EIP712_TYPED = 2` wire format that Phase 3 reserved + Phase 4 implemented.

### 11. **MAY** — Compact-mode display toggle

Phase 4 collapsed `Visibility::Optional` into `Visibility::Always`. Phase 5 may distinguish them via a user-settable "compact mode" toggle in the settings page: compact mode skips fields marked `Optional`, regular mode renders them. Wire bit is preserved so a future firmware can read this without a descriptor reflash.

### 12. **MAY** — Timing-channel + stack-budget reviews

- Visibility-rule evaluation paths are public (descriptor bytecode is Merkle-verified, not secret) — no secret-dependent timing concerns. Audit-grade: document this in `docs/HARDENING.md`.
- Walker recurses for nested calldata (capped at depth 4 in the renderer, depth 8 in the walker proper). Add a stack canary at the renderer entry point so a hostile descriptor that somehow defeats the depth cap cannot smash the stack silently.

---

## Architectural choices already locked (do NOT revisit)

These are baked into Phases 1–4 and changing them invalidates the on-chain wallet address, the firmware-pinned Merkle root, or both. The Phase 3 handoff has the full list; Phase 4 adds:

1. **EIP-712 typed sign-envelope is PersonalSign-wrapped.** The firmware wraps the 32-byte EIP-712 final hash AS a personal-sign message. Solady's `ERC1271` accepts it because our `SignatureWrapper` carries no appended data. NO new typehash, NO `TypedDataSign` appended-data branch. Verified by `aa/src/eip1271.rs:5-8` + `contracts/smart-wallet/src/PQSmartWallet.sol:362-395`.
2. **ERC-8213 fingerprint is 2 pages.** Page F is the banner ("8213 Fingerprint" + kind label); page F+1 is the full 32-byte hash split 4 rows × 8 hex bytes. Existing single-page `write_calldata_hash_rows` truncates to 14 hex; the 8213 spec mandates the full digest. 2 pages × 22 page cap = ~6 pages of headroom after the longest existing renderer.
3. **MustMatch → Reject + fall-through.** Phase 4 does NOT enforce `MustMatch` (no value-list on-wire yet); it rejects and falls through to blind-sign with a status banner. Phase 5's wire-format extension for `IfNotIn` / `MustMatch` value lists slots into the existing `ParamSet::visibility_values` field — the parser already accepts trailing bytes after the visibility byte; just wire the comparator.
4. **Path resolution bypasses `resolve_path`.** Phase 4 walks the path program manually, accumulating a slot offset, and reads the corresponding 32-byte word straight out of `inner_data` post-selector. Phase 3's `walker::resolve_path` requires an `AbiView` tree which Phase 4 cannot build without on-wire ABI type info. Phase 5 either keeps the direct walker (and just adds dynamic-type handling there) or switches to a full AbiView build once the on-wire shape descriptor lands (item 5).
5. **Batch mode is "render-the-match + blind-sign-the-rest".** A batch has ONE descriptor; only the inner tx whose `to` matches gets descriptor pages. Multi-descriptor batches need a Phase 5 wire-format change (Phase 4's reservation in `proto/src/lib.rs::ERC7730_MAX_TRAILER_LEN` is single-slot only).

## What Phases 1–4 already shipped

| Component | File(s) | Status |
|---|---|---|
| On-device IR parser + walker + bundle verifier + binding cross-check | `pqsigner-erc7730/src/{ir,walker,bundle,binding}.rs` | unchanged since Phase 1 (+ Phase 3 walker upgrades) |
| Host IR compiler + Merkle DB + xtask gate + 20-leaf seed corpus | `dbgen/src/erc7730.rs`, `secure/data/erc7730/`, `xtask gen-erc7730-descriptors` | unchanged since Phase 2 |
| `OFFCHAIN_KIND_EIP712_TYPED = 2` wire reservation + trailer parser on all three sign dispatchers + `VerifiedDescriptor` plumbing | `proto/src/lib.rs`, `secure/src/nsc/cmd_sign_*.rs` | Phase 3 |
| 14 FormatOp renderers + intent banner + ERC-8213 fingerprint pages + EIP-712 typed sign completion + `pick_sign_pages` ladder rung + per-tx batch dispatch | `secure/src/tx/display/erc7730/`, `secure/src/tx/display/erc8213.rs`, `secure/src/tx/erc7730_render/`, `tx-core/src/erc8213.rs` | Phase 4 (this handoff's predecessor) |

## Verification recipe for Phase 5

When you think Phase 5 is done:

```bash
# 1. All test groups
cargo test -p pqsigner-erc7730 --tests
cargo test -p pqsigner-tx-core --tests
cargo test -p dbgen --test erc7730_roundtrip
cargo test -p sphincs-tz-secure --tests \
  --no-default-features --features mock-se,debug-log,ui-semihosting

# 2. Cross-compile for the firmware target
cargo build -p pqsigner-erc7730 --target thumbv8m.main-none-eabi
cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi \
  --no-default-features --features dual-se,ui-oled,stm32u585,debug-log

# 3. Production policy build (item 1)
cargo run -p dbgen -- --policy production
cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi \
  --no-default-features --features dual-se,ui-oled,stm32u585,mode-production
# Must fail loudly if any descriptor fails the production attestation
# policy.

# 4. End-to-end smoke through QEMU
make e2e   # Scenarios 5m (contract render) + 5p (EIP-712 typed) +
           # 5q (batch with per-tx + batch-final fingerprints)

# 5. Codegen drift check
make check-erc7730-descriptors
cargo run -q -p pqsigner-xtask -- gen-solidity-constants --check

# 6. Fuzz 1-minute smoke (24h soak runs in CI separately)
cargo +nightly fuzz run erc7730_walker -- -max_total_time=60
cargo +nightly fuzz run erc7730_params_parse -- -max_total_time=60
cargo +nightly fuzz run erc7730_render_dispatch -- -max_total_time=60

# 7. UI capture comparison (item 8)
cargo test -p sphincs-tz-secure --features ui-capture \
  --no-default-features --features mock-se,debug-log,ui-semihosting \
  -- --nocapture \
  | tools/ui_fixture.py compare tests/ui_fixtures_erc7730.json

# 8. Cross-implementation parity (item 7)
python tools/cross_parity_erc7730.py --corpus secure/data/erc7730/
python tools/cross_parity_erc8213.py

# 9. HW bench (item 8)
make e2e-erc7730-hw
make test-key-speed   # asserts the ≤30ms walker bound
```

Then add a row to `docs/work-todo.md`'s Completion Log: `YYYY-MM-DD — Phase 5: ERC-7730 final — registry mirror + audit polish + dynamic-type renderer + docs + parity`.

## Common gotchas

1. **Production attestation flip is wire-format-stable.** Flipping `allow_unattested_dev_descriptors = true → false` does NOT change the IR shape or the Merkle root format. It only changes which descriptors qualify for inclusion. The host pipeline rejects unattested descriptors at `dbgen` time; on-device firmware never sees them.
2. **Dynamic-type support changes the Merkle root.** Adding shape-descriptor bytes to the IR header changes the per-leaf hash → `ERC7730_DESCRIPTORS_ROOT` changes → every existing companion-side `erc7730_db.bin` needs regeneration. Coordinate with companion app team. The `dbgen --check` gate catches this.
3. **`personal_sign_replay_safe_hash` semantics.** When a dapp pre-wraps an EIP-712 hash and calls `wallet.isValidSignature(replaySafeHash(H), sig)`, the on-chain Solady will re-wrap it → double-wrap → verification fails. That's a dapp bug. Document in `docs/erc7730-integration.md` and `CLAUDE.md`.
4. **Test gating.** `secure/src/tx/display/*` is `#[cfg(not(test))]`-gated because it depends on `crate::ui::*` hardware bindings. Renderer unit tests cannot run in host test mode without moving Pages or splitting the UI-bound parts. The Phase 5 fuzz-harness blocker (item 9) is the cleanest forcing function to fix this.
5. **Optional → compact-mode distinction.** Phase 4 collapsed `Optional` into `Always`. A descriptor author who wants compact-mode behaviour today gets full-render instead. Phase 5's compact-mode toggle preserves backward compatibility (the wire byte was always present; only the renderer behaviour changes).
6. **EIP-712 typed sign needs entropy unlock.** The kind=2 path derives a wallet address via `proxy_address(bootstrap_pubkey)` which needs the entropy reconstruction from §7 of `cmd_sign_offchain.rs`. Don't try to short-circuit the kind=2 path before the unlock + entropy decode — it'll panic on the missing entropy.

## Plan-file pointer

The full 5-phase plan lives at:

```
~/.claude/plans/carefully-read-understand-this-transient-feigenbaum.md
```

Phase 4 plan: `~/.claude/plans/fully-implement-phase-4-nested-puppy.md` (captures the architectural decisions and the sequencing).

If something here disagrees with either plan, the plan is authoritative for *intent*; this handoff is authoritative for *what Phases 1–4 actually shipped*. Update one or the other if you find drift.

## References

- Phase 3 handoff: `docs/handoff-erc7730-phase3.md`
- Phase 2 handoff: `docs/handoff-erc7730-phase2.md`
- Phase 4 work-todo entry: `docs/work-todo.md` (2026-05-14 row, Phase 4)
- Phase 4 commit: `cfb0e89`
- Clear Signing announcement (2026-05-12): <https://clearsigning.org> · <https://blog.ethereum.org/2026/05/12/clear-signing-announcement>
- ERC-7730 spec: <https://eips.ethereum.org/EIPS/eip-7730>
- ERC-7730 registry: <https://github.com/ethereum/clear-signing-erc7730-registry>
- ERC-8176 (Magicians thread): <https://ethereum-magicians.org/t/erc-8176-integrity-verification-for-erc-7730/27911>
- ERC-8213 (Magicians thread): <https://ethereum-magicians.org/t/erc-8213-wallet-signature-and-calldata-digest-display/24295>
- Cyfrin clearsig (Python reference): <https://github.com/Cyfrin/clearsig>

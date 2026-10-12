COMMENT_ON: 381
---
**What the 2026-10 security frontier research adds to this decision: a concrete shape for the "remove/gate" branch, what it would break, and what the "accept" branch would still owe.** Nothing below is decided. The first box is the owner's.

RAW32 is off-chain kind 0: the companion sends 32 opaque bytes and the device signs them (after its own replay-safe nesting) behind a `! BLIND RAW32` page.

### State on master (`c2fab970`)

- `secure/src/nsc/cmd_sign_offchain.rs:213`: the RAW32 arm is admitted in every build. The only check is the length test at `secure/src/nsc/cmd_sign_offchain.rs:214`.
- No cargo feature gates it. A search of `secure/Cargo.toml` for "raw32" finds nothing, and the production-forbidden list that starts at `Makefile:2672` has no RAW32 entry.
- `docs/companion/companion-app-integration.md:968` already states the preferred policy ("Production should disable RAW32"), so the gate branch matches the written preference. It is still this issue's open decision.
- By source read, removing RAW32 leaves no substitute path in the other off-chain kinds. Typed data must bind to a pinned ERC-7730 descriptor or the handler refuses (`secure/src/nsc/cmd_sign_offchain.rs:486`, `secure/src/nsc/cmd_sign_offchain.rs:528`), and the handler comment at `secure/src/nsc/cmd_sign_offchain.rs:440` says the typed path never falls back to a raw hash. `personal_sign` signs the hash of an EIP-191-prefixed message, so turning it into a signature over a chosen typed-data digest would need a keccak preimage. The research reviewer did not trace the absent-descriptor path line by line.

### Proposed mechanism for the gate branch

Firmware only. The research rates the cost as small.

- [ ] **Owner:** choose "gate" or "accept" on this issue.
- [ ] Add a cargo feature `offchain-raw32`, default off, enabled only by the bench and end-to-end profiles. Copy the forced-blind pattern: that feature is declared at `secure/Cargo.toml:946` and kept out of production by its entry in the forbidden set at `Makefile:2675`. (The `compile_error!` at `secure/src/nsc/mod.rs:274` is a different thing: it checks that feature's prerequisites, it does not forbid it.)
- [ ] Add `offchain-raw32` to `PROD_FORBIDDEN`, and add a new `compile_error!` that rejects `mode-production` together with `offchain-raw32`, so the source fence and the build gate agree.
- [ ] Reject kind 0 at the kind match (`secure/src/nsc/cmd_sign_offchain.rs:213`), before any display or key derivation, so the RAW32 page code is not linked into a feature-off image.
- [ ] Return a dedicated status so a companion can tell "disabled" from "malformed": a new discriminant in `NscStatus` (`proto/src/lib.rs:2117`), its USB status-word mapping, and a check of the generated Solidity constants.
- [ ] Put the kind-admission decision in a workspace crate (for example `aa`), not in `secure/src/nsc`. That module is declared at `secure/src/main.rs:171` under `#[cfg(not(test))]`, so a feature-off test written inside it would never run on the host. Assert the refusal in the QEMU end-to-end run as well.
- [ ] Opt the bench flows in explicitly. `mode-e2e` and `mode-bench` (`secure/Cargo.toml:158`, `secure/Cargo.toml:159`) need the feature, or the scenario asserted at `Makefile:524` and driven at `nonsecure/src/e2e_test.rs:2491` goes red. The host tools that send kind 0 (`tools/hid_sign_offchain.py:79`, `tools/test_hid_sign_offchain.py`, `tools/demo_px_flows.py`) need a note. The source-text pins at `secure/src/nsc_batch_offchain_pure_tests.rs:1116` match on the RAW32 branches and need care.

### What the gate does and does not do

- It closes the off-chain downgrade only (a hostile companion relabelling the final hash of a Permit, a Safe transaction or a CoW order as RAW32). The on-chain loud blind tiers stay: unknown calldata, and an `operation=0` call to a MultiSend address. The result should not be worded as "no blind path".
- Typed data that has no pinned descriptor becomes unsignable off-chain. That is wider than `eth_sign`-style flows. Whether to add a lower "structure only" typed-data tier afterwards is a separate owner decision (research item CS-05, not drafted as an issue) and should not be taken before this one.
- Safe flows: `docs/companion/companion-safe-tx-integration.md:388` says a Safe `signMessage` flow "works as a `RAW32` off-chain sig" today. With RAW32 off that flow stops. Today a Safe transaction hash sent as RAW32 is the one off-chain way to obtain this wallet's signature on a Safe transaction without the on-device Safe verifier (pinned MultiSendCallOnly allowlist, DELEGATECALL refusal). The supported Safe route is the on-chain `approveHash` UserOp, which decodes the Safe transaction on the device. A companion-side "MUST NOT" binds only honest companions, so this issue is the real fence for that case too.

### If the accept branch is chosen instead

- The research first proposed a per-signature ceremony for an enabled RAW32 (fresh PIN, a session cap, a use counter) and then dropped it: it adds friction, not meaning; one signature is enough for a drain; a counter is reported by the same hostile companion; a durable counter would be new per-signature flash state; and a fresh PIN per signature goes through `gated_unlock` and inherits the attempt-burn problem in #692.
- So the accept branch rests on the phishing UX tests this issue already asks for. They have no design yet.

Precedent, from the research and not re-checked for this comment: Trezor core has no blind typed-hash handler; the legacy Trezor One handler takes a domain-separator hash plus a message hash, so it stays EIP-712-framed and is less opaque than RAW32. A Ledger "blind signing disabled by default" requirement was cited but not independently checked.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item CS-01, section 5). Report priority P1 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

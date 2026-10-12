TITLE: Design a secure-world spending-policy guard: allowlists, per-operation caps and forbid toggles checked on the decoded request before the confirm screen
LABELS: enhancement,priority:medium,surface:clear-signing,surface:secure-element,source:frontier-research-2026-10
---
## Summary

Today the device signs whatever the user confirms. There is no device-side rule such as "only these recipients", "never more than N per operation", "never an unlimited approve" or "refuse every blind request". A policy held and enforced in the secure world would refuse an out-of-policy request before the confirm screen, which protects against a compromised companion and a hurried user, and delays (does not defeat) a coercer. Coldcard ships this class of control for Bitcoin. This is a design-first issue: several parts need an owner decision before any code. It is about firmware on the device. It is not the on-chain policy layer, which is the wallet-contract decision in #867, and nothing here changes the wallet contract. No issue tracks a device-side guard; the only written record is one row of a roadmap research document.

## What the code does today

- No policy record, allowlist or cap exists in the firmware. A search of `secure/src`, `aa/src`, `tx/src`, `proto/src` and `shared/src` for spending-policy, allowlist and spend-limit names finds nothing relevant.
- `secure/src/tx/display/dispatch.rs:548`: the display ladder picks a renderer for each request. It decides how to show a request, never whether the request is allowed.
- `secure/src/sign_rate.rs:45` and `secure/src/sign_rate.rs:49`: the only limiter is a 1 s minimum interval and 250 signatures per unlock session. `secure/src/sign_rate.rs:30` says the state is SRAM-only, so it resets on re-unlock or power cycle.
- `secure/src/timeout.rs:253`: `now()` is a tick counter from boot. The board has no battery, so there is no trusted wall-clock time.
- `geometry/src/lib.rs:121`: the page registry assigns all 256 flash pages. Pages 123 to 127 each have an owner (for example `geometry/src/lib.rs:131`), and the one spare, `geometry/src/lib.rs:137`, must stay erased.
- `secure/src/nsc/cmd_fw_commit.rs:9`: no reviewed firmware rollback backend exists yet.
- `docs/feature-roadmap-research-2026-06.md:74`: the roadmap row that names an "On-device clear-sign policy guard" as research, not as an owner commitment.

## What is already tracked elsewhere

- #867 covers the on-chain policy decision (guard hook in the wallet, vault contract). This issue is the device-side complement and does not depend on it.
- #636 and #280 cover the duress PIN, which answers coercion with a decoy wallet. It sets no limits.
- #343 covers native ERC-20 rendering. #381 covers whether RAW32 blind signing ships.
- So this issue is only about a device-enforced policy over what may be signed.

## Proposed work

- [ ] **Owner:** decide whether the guard is a product feature, and for which release. Nothing below is approved.
- [ ] Write the design before code. Extend an existing document if one fits; otherwise a short design note.
- [ ] Policy content, fixed-size and edited rarely: a small recipient allowlist, a chain allowlist, per-operation caps (native and per token), forbid toggles (Safe management, unlimited approve), and a lockdown bit.
- [ ] Evaluate the policy on the same decoded representation the renderer shows, after decoding and before confirm, so the check and the display cannot disagree. Put the refusal under the existing fault-injection discipline (`fi::CfiCounter`).
- [ ] Cover every release route, not only the ladder for a single user operation (UserOp): deploy, rotation and normal UserOps; batches, with an aggregate cap across members; all off-chain signature kinds; Safe multiSend records; Safe-wrapped CoW Swap orders. A route left out is a bypass.
- [ ] With a policy active, the blind tiers refuse: blind sign, RAW32 (a bare 32-byte hash), forced blind, unknown tokens, undecodable calldata.
- [ ] Use a count quota built on the existing page-123 signature tally, so no new per-signature flash state is added. Do not design a time-based limit: there is no trusted time on this board.
- [ ] Decide how a policy edit is authorised. Either (a) a separate credential enforced in secure-element silicon, following the duress-PIN pattern (`secure/src/se050/mod.rs:73` is the duress UserID object), which adds secure-element objects and a provisioning step; or (b) the roadmap's on-device confirm, optionally with the bootstrap key. A compare on the microcontroller is ruled out by the "no software PIN compare" rule.
- [ ] Decide where the record lives. No page is free. The options the research found are spare words in page 125 (erased on admin wipe, so a wipe clears the policy), a secure-element object, or a geometry change. Reconcile the choice with the first-boot check that pages 123 to 127 are blank (`secure/src/first_boot/mod.rs:201`).
- [ ] "Own account" as an allowed recipient means the current account, or a set cached when the policy is set. Recomputing all 256 account addresses per signature means 256 key generations.
- [ ] Define which policy applies after a duress unlock.
- [ ] Land the evaluator first as pure logic in a workspace crate with host tests, before any handler wiring.

## What it needs

Firmware, plus a factory provisioning step if the secure-element credential is chosen. No board change. The secure-element option waits on the provisioning ceremonies that are already deferred; it does not ask to bring them forward.

## Limits

- It does not defeat a coercer who obtains the policy credential or the seed words. A seed restored on another device has no policy.
- Per-operation caps fall to splitting unless the count quota is in place, and a batch does the splitting under one confirm.
- While no rollback floor is live, a downgrade to an older signed image without the guard removes it with only the main PIN.
- Flash: the research estimates this as a large item (guard on about six routes, a policy-edit dialog, storage, tests) competing with a secure slot that is already tight. The cost of this item was not measured.
- A wall-clock velocity limit and an on-chain time bound were considered and dropped: no battery, and a time bound in the wallet would change the wallet address (invariant 6).
- The same roadmap row that allows policy configuration also rules out an on-device address book. The recipient allowlist has to stay small, fixed-size configuration to respect that.

## Related

#867, #636, #280, #343, #381, #540, #758, #374. Public source: [Coldcard spending policy (SSSP)](https://coldcard.com/docs/sssp/).

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item CS-03, section 5). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

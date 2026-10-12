TITLE: Owner decision: should production builds refuse a non-empty paymaster instead of warning and signing? The device signs a hash it cannot decode (review finding H-6 has no issue)
LABELS: enhancement,priority:low,surface:clear-signing,surface:onchain,source:frontier-research-2026-10
---
## Summary

A paymaster is a contract that pays the gas for an ERC-4337 user operation (UserOp) and may charge the user in tokens afterwards. The device receives only `sha256(paymasterAndData)`. It cannot show which paymaster is used, what token it charges or how much. Today a non-empty paymaster adds one generic warning page and the device signs. The recorded owner decision is that pq1 ships no paymaster-using companion, so in a production build a non-empty paymaster is not a supported request. The cheap control that matches that scope is to refuse it in production instead of warning. That is a new device-behaviour decision (it would also block a third-party companion that uses a paymaster), so the first box below is the owner's. The fuller alternative, decoding and showing the paymaster, is a product-scope reversal and is listed here only as the conditional follow-up. Finding H-6 of the 2026-05 security review ("signed but never displayed") is still an unticked box with no issue behind it; this issue gives it one.

## What the code does today

- `secure/src/nsc/cmd_sign_userop.rs:295`: the handler copies the 32-byte hash from the request. No raw paymaster bytes cross the wire.
- `secure/src/tx/display/value_page.rs:474`: the comment states that the firmware only ever receives the hash, so it can show that a paymaster is present and nothing else.
- `secure/src/tx/display/value_page.rs:466`: the comment records the owner decision of 2026-06-27/28 that pq1 does not ship a paymaster-using companion, and that the warning page is not an authorisation for one.
- `secure/src/tx/display/value_page.rs:508` (`enforce_paymaster_page`) appends the page built at `secure/src/tx/display/value_page.rs:546` ("! PAYMASTER SET", "Gas sponsored", "may debit tokens"). The single-sign handler calls it at `secure/src/nsc/cmd_sign_userop.rs:1577` and the batch handler at `secure/src/nsc/cmd_sign_userop_batch.rs:1824`. After the page is shown and confirmed, both sign.
- `secure/src/nsc/cmd_sign_userop_forced.rs:384`: the default-off forced-blind handler already requires an empty paymaster. That is the only route that refuses today.
- `docs/security/security-review-2026-05.md:367` and `docs/security/security-review-2026-05.md:421`: finding H-6 and its unticked checkbox.
- `docs/companion/companion-batch-sign-integration.md:297` says the batch summary shows an "optional paymaster identity". The page shows presence only, no identity.

## What is already tracked elsewhere

- #328 covers the fault-injection inspection still owed on the existing presence page. #337 and #333 cover its completion receipts and append discipline. None of them covers what the page says or whether production should sign at all.
- No issue covers H-6, a production refusal, or paymaster decoding (searched the tracker for paymaster, sponsor, Pimlico and gas abstraction).
- So this issue is about the production refusal, the H-6 record and one doc correction.

## Proposed work

- [ ] **Owner:** confirm that a production device should refuse a paymaster outright instead of warning and signing.
- [ ] Under `mode-production`, refuse any request whose paymaster hash is not the empty-input hash, in the single-sign and batch handlers, before any display. Use the existing sentinel and control-flow-counter pattern for the refusal so one skipped branch does not turn it into a signature.
- [ ] Keep `enforce_paymaster_page` behind the refusal as a second layer, so a skipped refusal still produces the loud page.
- [ ] Leave bench and end-to-end builds able to exercise the page, so the #328 inspection still has a target.
- [ ] Add a host test and a QEMU scenario for the refusal. Put the decision in a workspace crate; code under `secure/src/nsc` is compiled out of host tests.
- [ ] Record in `docs/security/security-review-2026-05.md` that H-6 is tracked here, and state the chosen outcome when it lands.
- [ ] Correct `docs/companion/companion-batch-sign-integration.md:297` ("paymaster identity" should read "paymaster presence warning").
- [ ] Only if the owner later reverses the no-paymaster decision: carry the raw bytes as a trailer and hash them in the secure world, show the paymaster address with a Merkle-verified name or an explicit "unknown", and flag an `approve` whose spender is the paymaster in the same operation. That is a wire change to a format listed as frozen and needs its own decision.

## What it needs

Firmware only.

## Limits

- The threat is narrow. A hostile paymaster can take tokens only through an allowance the wallet already granted, and a legitimate token paymaster charges about the gas cost.
- A production refusal removes sponsored transactions entirely until the decision is revisited. That is the recorded scope today, but it is a product limit and should be stated in the companion guide.
- If decoding is ever built: for an unknown paymaster no maximum cost can be shown (the debit is bounded only by the allowance); a pinned "maximum cost" is only as true as the firmware's copy of that paymaster's formula; and the approve cross-check misses Permit2, `increaseAllowance`, nested Safe approvals and allowances granted earlier.
- The research first described this as a hole the documents do not state. That was wrong: the code comment, the red-teaming plan (`docs/security/red-teaming.md`, section 7.6) and H-6 all state it.
- No on-device or on-chain paymaster test was run.

## Related

#328, #337, #333, #353 (a planned wire bump that a later paymaster field could share).

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item CS-04, section 5). Report priority P3 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

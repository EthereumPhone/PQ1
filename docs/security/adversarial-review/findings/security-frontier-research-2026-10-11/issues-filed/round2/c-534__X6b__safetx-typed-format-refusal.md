COMMENT_ON: 534
---
**A concrete case for this issue, from the 2026-10 security frontier research (item X6b): the Safe transaction typed-data format is kept out of the catalogue today by a compile failure, not by a recorded refusal.**

### State on master (`c2fab970`)

- The vendored registry carries Safe typed-data descriptors. `secure/data/erc7730-registry/registry/safe/common-eip712-Safe.json:9` and `secure/data/erc7730-registry/registry/safe/common-eip712-Safe.json:11` render the `operation` member as a raw number, and `secure/data/erc7730-registry/registry/safe/common-eip712-Safe.json:17` renders `data` as generic calldata. That format has no MultiSendCallOnly allowlist and no DELEGATECALL refusal. Those rules exist only in the native Safe verifier on the UserOp path.
- The descriptors emit nothing today. `secure/data/erc7730.review.txt:6486` lists `eip712-Safe-1.4.1.json` in the skip section with "no compilable formats in descriptor", because the upstream format does not render the `to` member. The exclusion is a side effect of an incomplete upstream file, not a recorded decision.
- The Safe typed-data descriptors carry no `_pqsigner` block, while the Safe calldata descriptors do declare `refusalOnlyFormats`. An upstream fix that renders `to` would make the format compilable at the next registry resync. Under the emit-all default this issue describes, what would then stand between it and emission is what this issue's body already names: the accepted-family inventory, the pinned counts and a reviewer (the inventory check is in `dbgen/tests/erc7730_eip712_reconciliation.rs:335`). By this issue's account those catch an unreviewed addition (not tested against this case for this comment). Nothing would refuse it structurally.
- Reach today is limited, which is why this is a comment and not a defect report. dbgen forces each listed deployment's chain and address into the domain (`dbgen/src/erc7730.rs:4708`), the firmware demands an exact domain-separator match (`secure/src/tx/erc7730.rs:159`), and the listed deployments are the Safe singletons, not a user's proxy. So a real Safe's typed data would still fail binding. The hazard becomes live with any per-proxy binding or curation edit.

### Why it matters

If the generic renderer ever became the path for a Safe transaction signed off-chain, the device would show `operation` as a number and the inner call as generic calldata, without the checks that make "a DELEGATECALL is never blind-signed" true on the UserOp path. The supported Safe route is the on-chain `approveHash` UserOp, which uses the native verifier.

### Proposed additions

- [ ] Mark the `SafeTx(...)` typed format in the `eip712-Safe*` and `eip712-SafeL2*` descriptors as refusal-only, using the existing mechanism (`dbgen/src/erc7730.rs:1047`), so it can never emit whatever upstream changes. Do the same for a Safe message format if a later resync brings one.
- [ ] Add a negative test: off-chain typed kinds 2 and 3 carrying the SafeTx type hash are refused.
- [ ] If the general default-deny in this issue lands first, it covers this case. The explicit mark is the cheap version: it turns a review catch into a refusal and records the intent either way.

Not checked: whether any other vendored typed-data descriptor has the same "excluded only because it fails to compile" status. The review file's skip section would answer that.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item X6b, section 12). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

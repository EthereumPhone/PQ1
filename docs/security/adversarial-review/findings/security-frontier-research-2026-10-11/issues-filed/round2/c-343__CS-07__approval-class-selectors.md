COMMENT_ON: 343
---
**Scope note from the 2026-10 security frontier research (item CS-07): three approval-class selectors this design decision should rule on, and two parts of the original proposal that should not be built.**

### What is missing on master (`c2fab970`)

The native decoder knows three selectors: transfer, transferFrom and approve (`tx/src/erc20/calldata.rs:31`, `tx/src/erc20/calldata.rs:33`, enum at `tx/src/erc20/calldata.rs:36`). A search of `secure/src`, `tx/src` and `pqsigner-erc7730/src` (tests excluded) finds no handling for:

- `setApprovalForAll(address,bool)` (`0xa22cb465`), which hands an operator every NFT in a collection,
- `increaseAllowance(address,uint256)` (`0x39509351`),
- `decreaseAllowance(address,uint256)` (`0xa457c2d7`).

These selectors are rendered only where the ERC-7730 catalogue pins a specific deployment (for example the entries at `secure/data/erc7730.review.txt:1341` and `secure/data/erc7730.review.txt:1154`). On any other contract they fall to rung 8 or 9 of the display ladder: the typed-call tier with a selector-only "GUESS:" name (#420), or loud blind sign (`secure/src/tx/display/dispatch.rs:565`).

### Proposed additions to this decision

- [ ] Rule on whether these three selectors get a native page, and in which tier. They are selector-only identifications on contracts with no authenticated metadata, so by the constraints already listed in this issue they cannot enter the clear tier. The candidate is a page under the unknown-contract banner that names the effect ("operator gets ALL tokens").
- [ ] If yes: require a canonical bool word (0 or 1) for `setApprovalForAll`, as #410 did for the catalogue route. Never label `decreaseAllowance` as a revoke. Keep `setApprovalForAll(_, false)` under the unknown-contract banner even though it is a revoke on a real NFT contract.
- [ ] Keep any native decoder strictly below the known-call refusal gate, so a catalogue-known `(chain, target, selector)` that arrives without its descriptor still refuses and the decoder can never become a downgrade path.
- [ ] Weigh the cost the research's reviewer raised: moving these calls from the "GUESS:" tier to a native page with a friendly verb lowers the loudness for an unauthenticated contract. That may be a reason to decline.

### Do not build

- **A native on-chain `permit()` decoder.** The wallet is a contract with one post-quantum verifier and no ECDSA key (invariant 5), so it can never be the owner of an EIP-2612 permit. An on-chain `permit` sent by the wallet only relays someone else's signature. Showing it as an approval by the user would misdescribe it. #425 already lists a generic permit policy as a non-goal.
- **More "revoke" wording on unauthenticated contracts.** #857 tracks the existing case where `approve(addr, 0)` on a contract with no token metadata is labelled "Revoke approval" (`secure/src/tx/display/erc20_unknown.rs:97`) although the same bytes grant token 0 on an NFT contract. New decoders should not repeat that.

The research's first draft also asked for revoke framing, spender naming and an unlimited label for `approve`. Those already ship (#474) and are not part of this note.

Cost if adopted, by the research's estimate: medium, because a new `Erc20Call` variant touches every consumer, both display paths, the proofs over them, and (for any edit under `pqsigner-erc7730/`) the tree-bound catalogue provenance hash.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item CS-07, section 5). Report priority P3 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

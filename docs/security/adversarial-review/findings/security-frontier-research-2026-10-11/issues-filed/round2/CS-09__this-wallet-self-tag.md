TITLE: Tag a fund-destination address that equals the current wallet ("THIS WALLET"), computed in the secure world and never taken from the companion
LABELS: enhancement,priority:low,surface:clear-signing,surface:trusted-ui,source:frontier-research-2026-10
---
## Summary

When a user moves funds to their own account (a swap receiver, a refund address, a transfer between their accounts), the device shows the destination as a full address like any other. Nothing on the trusted display says "this is you". A user who expects the destination to be their own wallet has to compare 40 hex characters by eye, and a missing or swapped address looks the same as a correct one. The secure world already derives and binds the wallet address on every signature, so it can label a matching destination itself, with no input from the companion. No issue tracks this. Address chunking, the other half of the research item, is already tracked by #273 for the 16x4 pages and is not repeated here.

## What the code does today

- `secure/src/nsc/cmd_sign_userop.rs:683` and `secure/src/nsc/cmd_sign_userop.rs:698`: before any display, the handler binds the request's sender to the CREATE2 address the device derives for this seed and account. So the current wallet address is known and authenticated in the secure world on every signature.
- `pqsigner-erc7730/src/display/primitives.rs:437` (`write_addr_full`) renders a destination as the full address in EIP-55 mixed-case checksum form (`pqsigner-erc7730/src/display/primitives.rs:375`), or a Merkle-verified name where one exists. No renderer compares a destination with the wallet address. A search of `secure/src/tx/display`, `secure/src/tx/eip712` and `pqsigner-erc7730/src/display` for a self label finds none.
- `secure/src/tx/display/cowswap_screens.rs:159`: the one related case. When a CoW order's receiver is the zero address, the Safe-wrapped route prints an owner label in its place. That is a protocol default, not a comparison with the wallet.
- `secure/src/nsc/state.rs:332`: public keys of other accounts are cached in a 16-entry least-recently-used cache, so whether a sibling account's address is available without a fresh key generation depends on what happened earlier in the session.
- `pqsigner-ui-px/src/check.rs:123` (`check_words_unbroken`): the pixel-UI conformance check recognises an address only as a line starting with `0x` followed by hex (`pqsigner-ui-px/src/check.rs:136`), then all-hex continuation lines totalling 40 characters.

## What is already tracked elsewhere

- #273 covers chunking the 16x4 address into 4-character groups on the unknown-recipient path. #366 lists the same item (td-1).
- #472 (closed) is about showing the wallet's own receive address on the device. #473 (closed) is about signer identity rows on sign pages. Neither labels a destination.
- #349 forbids presenting host-supplied labels as authenticated facts. A tag derived on the device is consistent with it.
- EIP-55 casing, which the research first listed as missing, is on master.
- So this issue is only about the self tag.

## Proposed work

- [ ] On fund-destination fields only (recipient, receiver, refund receiver, spender), print a fixed tag such as "THIS WALLET" when the address equals the bound sender. Never tag the call target.
- [ ] Make it deterministic: the current account is always tagged. A tag that appears only when a sibling happens to be cached would make a missing tag meaningless.
- [ ] Sibling accounts (the other 255 account indexes), optional second step: tag only from a companion hint "this is account N" that the device checks by recomputing that account's address. The sign input layout is frozen, so the hint needs a trailer or a new field and a decision.
- [ ] Put the comparison in a workspace crate with a host test for each route (value transfer, ERC-20, CoW receiver, Safe refund receiver, multiSend records).
- [ ] Check the page budget: a tag row must not push a Safe multiSend batch over the page limit, where overflow is a refusal.
- [ ] If pixel-UI address chunking is ever adopted (it needs a PQ-UI design decision first), rewrite `check_words_unbroken` in the same change. A chunked line with spaces or an isolated `0x` never starts a 40-character run, so the check would pass without checking anything.

## What it needs

Firmware only. The sibling step first needs a timing measurement on a bench board with a debug port: the cost of one extra master key generation on pq1 has not been measured (a code comment says under 1 s; the project notes record a whole first signature on pq1 at 14 to 17 s).

## Limits

- This does not address address poisoning in general. The usual victim is sending to a look-alike of someone else's address. The tag helps only a user who expects their own account and notices the tag is absent.
- An absent tag is a weak signal. Users may not notice a missing label.
- A keyed address tag echoed by the companion (the Trezor "address MAC" idea, a message authentication code over the address) was considered and dropped: keyed on the per-chip hardware key it would survive a re-seed and label a previous seed's addresses as this wallet, and with only 256 accounts on-device recomputation gives the same assurance with no new key.
- Refusing ERC-20 calls that carry native value was also considered: the value already gets a mandatory loud page, so it was left out.
- Nothing here was run on a device.

## Related

#273, #366, #349, #348, #472, #473. Precedent: Trezor chunks addresses and has a seed-derived address MAC used for payment-request refunds (`core/src/apps/common/address_mac.py` in trezor-firmware); neither is a general self label.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item CS-09, section 5). Report priority P3 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

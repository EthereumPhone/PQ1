TITLE: Show Sign-In with Ethereum (EIP-4361) messages as structured pages before the raw text, with on-device address and chain consistency checks
LABELS: enhancement,priority:low,surface:clear-signing,surface:offchain,source:frontier-research-2026-10
---
## Summary

Sign-In with Ethereum (SIWE, EIP-4361) is the standard text format a web app asks a wallet to sign to log a user in. It is the expected everyday use of the device's `personal_sign` path. Today the device shows such a message as an undifferentiated stream of 48 characters per page with every line break painted as `?`, so the domain, the address, the chain and the nonce are not recognisable as fields. This issue asks for a strict parser and a short set of structured pages shown before the raw message. The benefit is legibility and a warning on malformed look-alikes. It is not phishing protection: the device cannot know which website the user is on. No issue tracks SIWE (searched for SIWE, 4361 and sign-in). It depends on #154, which fixes the raw message rendering.

## What the code does today

- No SIWE parser exists. A search of the Rust sources for "siwe" and "4361" finds only comments, for example `proto/src/lib.rs:1258`, which sizes the 700-byte message cap for "a comfortable SIWE message".
- `secure/src/tx/display/eip1271.rs:503`: the 16x4 renderer maps every non-printable byte, including line feed, to `?`. `secure/src/tx/display/offchain_screens.rs:114` is the pixel-UI message emitter and produces only generic message screens.
- `aa/src/eip1271.rs:191`: the value that gets signed is already bound to this wallet's address and to the request's chain id (`aa/src/eip1271.rs:197`). A message that names another address or chain produces a signature that does not verify there.
- `secure/src/tx/display/eip1271.rs:281` (`context_page_exact`): the existing check that each context page appears exactly once in the transcript.
- `pqsigner-erc7730/src/display/mod.rs:74`: the dialog is limited to 31 pages.

## What is already tracked elsewhere

- #154 covers the non-injective raw rendering (`?` substitution, invisible trailing spaces, no length). The structured view is only an addition on top of faithful raw pages, so #154 comes first.
- #381 covers blind RAW32 signing, a different off-chain kind.
- So this issue is only about parsing and showing SIWE fields.

## Proposed work

- [ ] Measure first. Build the parser behind a feature and report its flash cost before adoption. The reviewer's guess of 3 to 6 KB for parser plus renderers is not a measurement.
- [ ] A strict, no-heap EIP-4361 parser in a workspace crate, exact-match on the grammar, with fuzz and bounded-model-check coverage. A lax parser would create a mismatch between the structured view and the signed bytes.
- [ ] If the message parses exactly, prepend structured pages: a sign-in banner, Domain, URI, Chain ID, Nonce, Statement, and expiry, not-before and a resources count when present. Long domains and URIs need wrap rules across pages.
- [ ] Keep the full raw message pages after the structured pages. They stay mandatory, so the scroll-to-end rule still covers every signed byte.
- [ ] Give structured pages a mark that raw message pages cannot reproduce, and extend the `context_page_exact` uniqueness check to them. Otherwise a non-SIWE message could lay out raw pages that imitate the structured ones.
- [ ] Address in the message differs from the wallet address: refuse. The signature would be useless anyway. Decide the EIP-55 rule (the grammar requires the checksummed form).
- [ ] Chain ID in the message differs from the request's chain id: show a loud warning by default. Refusing would break apps that hardcode chain 1; make refusal an owner option.
- [ ] Message contains the SIWE preamble but does not parse: show a loud "malformed sign-in" page (the standard says wallets should warn).
- [ ] If structured plus raw pages do not fit the page limit, refuse. Do not drop either view.
- [ ] Cover both display paths (16x4 and pixel UI) and check whether batch off-chain signing can carry `personal_sign`; if it can, apply the same rules or refuse SIWE in a batch.
- [ ] State in the companion guide that the device shows the domain but cannot check it against the browser origin, and that the companion remains responsible for that check.

## What it needs

Firmware only, after #154. Do not land it on a build whose secure slot is over budget; keep it behind a feature until the flash measurement is in.

## Limits

- The main phishing case (a login prompt for the attacker's domain) is not prevented. The device cannot verify the origin, so the Domain page helps only a user who reads it. Nothing may present this as phishing protection.
- The address and chain checks are early consistency checks, not a new barrier: the signature is already bound to the wallet and chain.
- A structured summary can train users to skip the raw pages. Keeping the raw pages mandatory limits that and makes the dialog longer.
- No SIWE flow ships in a companion yet, so demand is prospective.
- Flash cost is unmeasured. Nothing was run on a device.
- There is no vendor precedent to copy: Trezor has no SIWE parser.

## Related

#154, #381, #700. Specification: [EIP-4361](https://eips.ethereum.org/EIPS/eip-4361).

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item X7b, section 12). Report priority P3 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

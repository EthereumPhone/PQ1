COMMENT_ON: 154
---
**A fix design for this issue from the 2026-10 security frontier research (item X7a), after an independent review changed several parts of the first draft.** The defect is still present on master `c2fab970`. Line references below are current; the ones in the original sweep record have drifted.

### State on master

- `secure/src/tx/display/eip1271.rs:503` (`sanitise_byte`): every byte outside 0x20..0x7E, including line feed, becomes `?` (`secure/src/tx/display/eip1271.rs:511`). The doc comment at `secure/src/tx/display/eip1271.rs:330` states it.
- `secure/src/tx/display/eip1271.rs:404`: the message is cut into fixed 48-character pages. Rows are space-padded and the footer (`secure/src/tx/display/eip1271.rs:590`) shows only a page counter, so a trailing space is invisible and no byte length is shown.
- `secure/src/tx/display/offchain_screens.rs:103` is a second copy of the sanitiser on the pixel-UI path. Both paths must change together.
- `secure/src/nsc/cmd_sign_offchain.rs:220`: the only gate on the payload is the 700-byte cap (`proto/src/lib.rs:1263`). There is no content rule.
- `docs/companion/usb-protocol-v2.md:332` calls the payload a "UTF-8 message". Nothing checks UTF-8, and non-ASCII UTF-8 is painted as `?`.
- `secure/src/display_under_test/pure_tests.rs:1547` asserts the `?` substitution as intended behaviour. That test has to flip.

### Proposed design

- [ ] Classify the payload once. If every byte is printable ASCII or line feed, render as text. Anything else switches the whole message to a hex mode. No per-byte escapes, so there is no escape-character ambiguity.
- [ ] Text mode: render a line feed as a real line break plus one marker glyph that cannot occur in the payload. The 16x4 font table runs to 0x7F (`secure/build.rs:415`), and 0x7F is outside the text alphabet, so it is the one free slot; its glyph shape needs checking. The pixel atlas needs the same glyph, which changes the pinned atlas hash.
- [ ] Do not add a second marker for trailing spaces. One free glyph cannot mark both end-of-line and trailing space ("ab " and "ab" plus line feed would collide). Send any message with a line or an end that finishes in a space to hex mode or refuse it. The ERC-7730 constant renderer already rejects a trailing space for the same reason (`pqsigner-erc7730/src/display/render/formatters.rs:1637`).
- [ ] Add a "Len: N bytes" row in both modes. The length row alone does not give injectivity (two 21-byte messages that differ only in where a line feed sits paint the same rows without the marker), so it is an addition to the marker, not a replacement.
- [ ] Label hex mode loudly, like the `! BLIND RAW32` page. It is effectively a blind signature. Note that the 16x4 banner row is 16 columns.
- [ ] Make the renderer fallible and refuse before it allocates pages. `secure/src/tx/display/eip1271.rs:357` calls `Pages::with_len(total)`, which asserts when the total exceeds the page limit; once line feeds become line breaks, a payload of 700 line feeds needs far more pages than exist, and that assert would be a panic in the secure world.
- [ ] Page budget: the limit is 31 pages (`pqsigner-erc7730/src/display/mod.rs:74`). The reviewer counts 7 fixed pages for this dialog, including the 2 fingerprint pages (`pqsigner-erc7730/src/display/mod.rs:39`), which leaves 24 message pages and puts the hex-mode cap near 568 bytes. Some binary payloads that sign today will be refused. The pixel path must also fit its own screen limit and has duplicated page-count constants (`secure/src/tx/display/offchain_screens.rs:49`, `secure/src/tx/display/offchain_screens.rs:97`).
- [ ] Put the classifier and encoder in `aa` or a small new crate so host tests run them, and to avoid moving the tree-bound catalogue provenance hash that any edit under `pqsigner-erc7730/` moves.
- [ ] Acceptance: implement the inverse on the host (page transcript back to payload) and test `decode(render(m)) == m` with property tests or fuzzing at the full 700 bytes, with the proof-of-concept pairs from this issue as fixed vectors. A model-checker proof over two symbolic 700-byte payloads through both renderers was proposed first and is not feasible.
- [ ] Before sizing the pixel work, write a test for the suspected word-wrap collision in `emit_message` (`secure/src/tx/display/offchain_screens.rs:114`): a line that ends in a space keeps the byte and paints nothing. This was inferred from the code, not executed.
- [ ] Correct `docs/companion/usb-protocol-v2.md:332` to state the real content rule.

### Limits

- Severity stays at this issue's medium. The original sweep's own caveat stands: the attack needs a verifier that normalises bytes, and none has been shown. A `?`-for-line-feed twin of a Sign-In with Ethereum message is not a valid message of that format.
- Non-ASCII messages (accented or CJK text) become unreadable hex. That is honest and is a step back from Trezor's Unicode display.
- Trezor's hex fallback triggers only when UTF-8 decoding fails, so Trezor does not separate the pairs in this issue either. Only the hex fallback is parity; the rest goes beyond it.
- This fixes line structure and injectivity. It is not structured Sign-In with Ethereum display, which is a separate follow-up that depends on this issue.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item X7a, section 12). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

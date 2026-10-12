TITLE: Give Safe custody-change pages one shared danger classification: today a Safe-wrapped unlimited approve does not pulse and owner changes have plain heads
LABELS: enhancement,priority:medium,surface:clear-signing,surface:trusted-ui,source:frontier-research-2026-10
---
## Summary

The warning cue on a sign dialog is decided call site by call site: a `!` prefix on the 16x4 text pages, and a `pulse` boolean (warning rings around the icon) on the pixel UI (the `ui-px` display path). Nothing classifies an operation as dangerous once and feeds both display paths. The result is that the same fact gets a different cue depending on the route. An unlimited ERC-20 approve pulses when it is sent directly and does not pulse when it is wrapped in a Safe transaction. Adding, removing or swapping a Safe owner, changing the threshold and disabling a module have no cue unless the resulting threshold is 1 or 0, while enabling a module or changing the guard always do. The Safe route is the one the Radiant and Bybit attacks used, so it is the wrong place to be the quieter one. This issue asks for one classification, computed from the decoded operation, that both painters consume. No existing issue covers it: #600 is about repeated prompts, #762 about proof coverage of the pixel chrome, #329 about the forced-blind ceremony.

## What the code does today

- `secure/src/tx/display/screen_kit.rs:102`: the pixel emitter's `detail(...)` takes the cue as a bare `pulse: bool` argument. Each caller decides.
- `secure/src/tx/display/erc20_screens.rs:136`: a direct unlimited approve passes `true`.
- `secure/src/tx/display/safe_screens.rs:530`: the same unlimited approve inside a Safe transaction passes `false`. `secure/src/tx/display/safe_screens.rs:537` (unknown token) uses `value(...)`, which has no pulse.
- `secure/src/tx/display/safe_screens.rs:610`, `secure/src/tx/display/safe_screens.rs:619` and `secure/src/tx/display/safe_screens.rs:623`: add owner, swap owner and change threshold emit plain address or signer screens. A cue appears only when the new threshold is 1 or 0.
- `secure/src/tx/display/safe_screens.rs:634`: disable module passes `false`. Enable module, set guard and set fallback handler pass `true`.
- 16x4 pages: `secure/src/tx/display/safe_mgmt.rs:53` ("Add Safe owner"), `secure/src/tx/display/safe_mgmt.rs:74`, `secure/src/tx/display/safe_mgmt.rs:100` ("Swap Safe owner"), `secure/src/tx/display/safe_mgmt.rs:119` and `secure/src/tx/display/safe_mgmt.rs:148` ("Disable module") are plain heads. `secure/src/tx/display/safe_mgmt.rs:132` ("! ENABLE MODULE") and `secure/src/tx/display/safe_mgmt.rs:162` ("! CHANGE GUARD") are loud.
- 16x4 unlimited approve: `secure/src/tx/display/erc20_known.rs:94` and `secure/src/tx/display/safe_display.rs:1930` both print a lowercase "unlimited" with no `!` marker.
- `secure/src/tx/display/safe_screens.rs:249`: DELEGATECALL is loud ("! Op: DELEGATE"), so the pattern exists; it is just applied by hand.

## What is already tracked elsewhere

- #600 covers a ring of recent requests and a retry comparator. It does not cover per-page cues.
- #762 covers the pixel chrome mask being outside the transcript proofs. A cue added here should be checked against that gap, not assumed covered.
- #329 covers the forced-blind danger ceremony for that one route.
- #770 (closed) and the scroll-to-end rule settle screen order and the commit gesture. This issue changes neither.
- So this issue is only about a single classification and the cue gaps listed above.

## Proposed work

- [ ] Define one classification (danger or not, with a reason) computed from the decoded operation, in a pure workspace crate so host tests run it. Inputs: Safe management operation, DELEGATECALL, unlimited approve, the blind tiers.
- [ ] Decide the set. The research's candidates are: owner add, remove and swap; change threshold; disable module; a Safe-wrapped unlimited approve for known and unknown tokens. Marking too many pages trains users to ignore the cue, so the set needs a deliberate choice.
- [ ] Make both painters consume it: a `!` head on 16x4, `pulse` on the pixel UI. Use the existing orange pulse. No new glyph and no new colour (a new glyph changes the pinned atlas; red is reserved for failed or cancelled in the PQ-UI design).
- [ ] Add a `!` marker to the 16x4 "unlimited" row on the direct and the Safe-wrapped paths.
- [ ] Add a paired test: for every decoded operation, the 16x4 head carries `!` exactly when the pixel screen pulses, and both follow the classification.
- [ ] Do not add an interstitial page and do not change screen order in this issue. If a first-page interstitial is wanted later it needs an owner decision, a page reserved unconditionally in the multiSend page budget (which refuses to sign on overflow), and an honest label: with the same next-press gesture it is a salience cue, not a second confirmation.

## What it needs

Firmware only. Host tests cover the classification and the 16x4 pages. The pixel half can only be looked at on a unit with a panel (an enclosed engineering-validation unit); the bench board has no panel.

## Limits

- This is a salience cue. A user who is shown a malicious custody change as the first and only request, reads it and approves it, is not protected.
- The pixel UI is outside `make release` today (flash budget), so only the 16x4 half would ship now.
- The research's first draft claimed "! MULTISIG OFF" was the only custody banner. That was wrong and is corrected here: enable module, guard and fallback changes are already loud.
- No vendor ships a custody-change class (Trezor's danger screen covers unknown contracts only), so there is no reference design to copy.
- Nothing here was run on a device.

## Related

#600, #762, #329, #770, #700. Public sources: [NCC Group on the Bybit hack](https://www.nccgroup.com/research/in-depth-technical-analysis-of-the-bybit-hack/), [Hacken on the Radiant hack](https://hacken.io/insights/radiant-hack-review/).

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item CS-02, section 5). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

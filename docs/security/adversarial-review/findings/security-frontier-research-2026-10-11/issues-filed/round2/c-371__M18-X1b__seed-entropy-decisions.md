COMMENT_ON: 371
---
**Material for the decision this issue holds, from the 2026-10-11 security frontier research (item M18) and its independent review. Line numbers are at master `c2fab970`.**

Today the new-wallet seed is one draw from the three-source generator (`secure/src/main.rs:968`), passed straight to the mnemonic encoder (`secure/src/main.rs:976`). There is no user or host term.

The review found that this issue asks one question while two different designs are on the table, and one of them does not answer the question. It recommends recording two decisions.

**Decision A: mix user-supplied randomness into the seed (adopt or decline).**

- What it is: on the new-wallet path only, the user enters coin flips as short presses on the two buttons, and the seed becomes `SHA-256(tag || device_random_32 || length || user_bytes)`. The three-source draw stays mandatory and unchanged. Hash, not XOR.
- What it defends: a bug in the seed-draw call path, or all three sources failing at once. It gives the user no way to check anything, and it does nothing against malicious firmware, which can ignore the input.
- What already covers the motivating case: the Coldcard incident cited for this was a silent fall back to a software generator. This repository already fences that class. `scripts/rng_consumer_audit.py:19` bans software generators by name, `scripts/rng_consumer_audit.py:82` requires the three-source call in the wizard, and the gate runs in `make prod-feature-check` (`Makefile:2738`). So the added value is small. The research rates it P3.
- If adopted, the constraints the review found:
  - Button events are left or right, short or long, and nothing else. Both buttons inside 80 ms (`secure/src/hw/buttons.rs:189`) are turned into a long right press, which every wizard dialog treats as confirm (`secure/src/hw/buttons.rs:297`). The entry screen must count short presses only, must not finish early on a chord or a long press, and needs an undo.
  - The wizard copy must tell the user to flip a real coin. Tapping from memory is not one bit per press.
  - Keep the literal call that `scripts/rng_consumer_audit.py:82` pins, or update the gate in the same change. Otherwise `make prod-feature-check` fails.
  - Put the mix function in a workspace crate with a known-answer test. The wizard code is not built by the host test suite, so a test written there would never run.
  - Decide whether entered flips survive a cancelled or failed backup check, which sends the wizard round its loop again.
  - Do not add "check words" or a "the first word changes" demonstration. A rigged image fakes both, so they would be a false proof.
  - Treat the entry screen as seed-adjacent display content (the class of #784). A pixel-UI screen for it waits on the open flash-size decision; the legacy dialog path does not.
  - It can only be validated on a unit with a display panel (#700).

**Decision B: verifiability against a rigged generator (adopt or decline).** This is the question in the title.

- Trezor's mechanism (host entropy, a commitment, an interactive check) needs a host. On pq1 the wizard runs (`secure/src/main.rs:4012`) before USB is initialised (`secure/src/main.rs:4244`) and before the non-secure world starts (`secure/src/main.rs:4291`). There is no host channel while the seed is generated.
- A path that needs no new firmware already exists: generate a 24-word phrase offline from dice and enter it with Restore (`secure/src/ui/seed_wizard.rs:781`), which checks the phrase checksum (`bip39/src/full.rs:205`). The device's generator is then not involved in the seed at all, and the user can audit every step. What is missing is a written procedure. One catch for that procedure: the last word carries a checksum that needs a SHA-256 computation, so the user needs an offline tool or a table for it.
- Dropped by the review: a dice-only mode on the device (it removes the three-source draw from the seed and trips the gate above); an on-device commit-and-reveal ceremony (hand-copying 32-byte values from a 16x4 display, and it still gives no evidence against firmware that derives honestly and leaks the seed through signatures); a host-committed signature randomizer (`docs/security/vendor-signing-key-compromise.md:676` already records "do not fund one as mitigation").

**Proposed checklist for this issue**

- [ ] Record decision A (the additive mix) with its scope: generator-failure defence only.
- [ ] Record decision B (verifiability).
- [ ] If B is "no device mechanism": write the "generate offline from dice, then Restore" procedure in the user documentation, including how to compute the last word.

Related: #238 (the randomizer channel, documentation), #704, #641, #594, #700, #784, #783.

---

**One concrete shape for the "adopt" side of this decision, and one shape to decline on the record, from the 2026-10-11 security frontier research.** Nothing here should be built before the owner rules; it changes the setup ceremony (the #772 precedent). Lines are at master `c2fab970`.

Why it came up. The research looked at a passive tap on the display bus. On the create path the device generates the seed and shows all 24 words (`secure/src/main.rs:968` draws the entropy, `secure/src/main.rs:982` shows it), so such a tap reads the seed. pq1 has two output channels, the panel and USB, so a device-generated seed has to cross one of them.

**Candidate to adopt or decline: a two-share create mode (opt-in, default flow unchanged).**

- The user flips a real coin 256 times and enters the result as share U through a no-echo, masked button dialog (the restore dialog proposed in {{X1a}}). U is entered first.
- The device then draws its share D with the existing three-source call, unchanged. The panel shows D as an ordinary 24-word phrase and runs the existing three-word check on D.
- The seed is D XOR U. The combined phrase is never drawn. The user keeps two sheets, D and U.
- A display-only tap sees D and the mask, which say nothing about the seed while U has full entropy. As a side effect the device's random source alone no longer determines the seed, which is the concern of this issue. It is not a verifiable-entropy protocol: nothing lets the user check how the device chose D.

What the research's review says must be in scope if this is adopted, because the first proposal got these wrong:

- Restore from the two shares has to happen on the device. Combining them on paper does not give a valid phrase: the last word carries 8 checksum bits from a hash, and a phrase with a bad checksum is rejected (`bip39/src/full.rs:205`).
- U has no checksum. A wrong bit gives a different, valid wallet with no error, on create and on restore. So U must be entered twice in small chunks and compared chunk by chunk, and the wallet address must be confirmed after restore.
- U must survive a failed word check and be zeroized on every exit. Today a failed check restarts the whole wizard (`secure/src/main.rs:992`).
- Scope it to the 16x4 dialogs, or get a pixel-UI design first. Standalone cost is large.

What it does not give:

- A tap on the display plus the two button lines recovers everything. That second tap is two wires on the same board.
- A tapper who has D can test guesses of U offline against the public wallet address, so a user who types bits from their head instead of flipping a coin is not protected.
- Losing either sheet loses the wallet. There is no on-chain recovery.
- It protects the seed only. PIN entry still draws digits on the same bus, and it does nothing against malicious firmware.
- The existing `decoy-frames` feature (`secure/Cargo.toml:568`, off by default) is the only current measure aimed at this channel. It does not defeat a digital tap, which can separate frames by their timing.

**Shape to decline, with reasons, so it is not proposed again: sending a one-time pad or a share over USB.**

- In the normal boot flow the first-boot wizard runs (`secure/src/main.rs:4012`) before USB is initialised (`secure/src/main.rs:4244`) and before the non-secure world is started (`secure/src/main.rs:4291`). No host channel exists while the seed is created.
- USB belongs to the non-secure world. A pad or a share that leaves over USB is seed material outside the secure world, which invariant 4 forbids.
- It needs a new host protocol and companion support, and it puts part of the backup on a general-purpose computer.

Suggested boxes for this issue:

- [ ] Owner ruling: adopt, decline or defer the two-share create mode.
- [ ] Record the decline of the USB-pad shape with the reasons above.
- [ ] If the research's separate proposal to mix user dice rolls into the seed is taken up, decide both together: one entry dialog and one mixing function, in a workspace crate with test vectors. `scripts/rng_consumer_audit.py:82` pins the literal three-source call in `main.rs`, and both shapes keep it.

Public precedent, for the backup format only: [Coldcard Seed XOR](https://seedxor.com/) and [Coldcard dice rolls](https://coldcard.com/docs/verifying-dice-roll-math/). Neither withholds the seed from the display. The research found no vendor that does. The reviewer did not re-fetch the Seed XOR page.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report items M18 and X1b, sections 7 and 12). Report priority P3 for both is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

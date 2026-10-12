TITLE: Design-first: opt-in restore that never draws a seed letter, entering the phrase as button bits under an on-screen one-time mask (stops a display-only tap)
LABELS: enhancement,priority:low,surface:trusted-ui,surface:lifecycle,source:frontier-research-2026-10
---
## Summary

Every way of getting a seed into or out of pq1 today draws seed letters on the display, so a passive tap on the display bus reads them. The research proposed one firmware-only answer for the restore case: the user enters the 24 words as 264 bits, one button press per bit. Before each press the device draws a fresh random mask bit and shows only the mapping ("left means 1" or "left means 0"). The secret bit is the press combined with the mask, and nothing derived from it is ever drawn. The display bus then carries only the mask, and the button lines carry only the masked presses. A tap on the display alone learns nothing about the seed. A tap on the display plus both button lines still learns everything, so this is a complement to physical measures and not a replacement. It changes the setup ceremony, so it needs an owner decision before any code. No issue tracks a restore path that keeps the seed off the display.

## What the code does today

Lines at master `c2fab970`.

- `secure/src/ui/seed_wizard.rs:143`: setup offers exactly two options, "New Wallet" and "Restore".
- `secure/src/main.rs:1003`: restore is `enter_mnemonic` and nothing else. Each typed letter is drawn on the panel (`secure/src/ui/seed_wizard.rs:972` on the 16x4 path).
- `secure/src/main.rs:982`: a new wallet shows all 24 words.
- `bip39/src/full.rs:205`: a phrase is accepted only if its checksum is right, so a wrong bit is caught about 255 times in 256.
- `secure/src/hw/buttons.rs:183` and `secure/src/hw/buttons.rs:189`: a hold over 500 ms becomes a long press, and two buttons within 80 ms become a chord. A blind entry dialog has to be designed around both.
- `secure/src/board/pq1.rs:235` and `secure/src/board/pq1.rs:238`: the buttons are PA0 and PA1.
- `docs/hardware/evt-silicon-validation.md:470`: the buttons land on their own pad pairs (`J203` to `J206`) on the main board. `docs/hardware/evt-silicon-validation.md:279` names a separate `LCM+RGB` connector for the display module.
- The schematic agrees (`docs/hardware/schematics/AL_A66_MB_V10_20260826_1500.pdf`, read from rendered crops because the file has no text layer). Sheet 2 has a 40-pin display connector `J201` whose signal pins are the display reset, chip select, clock, data, data/command, tearing signal, the backlight pair, the RGB LED channels and supplies. Neither button net (`UP_KEY`, `DOWN_KEY`) is on it. Each button net goes through a 10 ohm resistor to its own pad, with a ground pad beside it, in a separate block. How those pads are wired to the physical buttons inside the enclosure is not in the repository.
- `docs/security/user-device-verification.md:163`: a logger on the display bus that captures the seed during the wizard is listed as an accepted residual.
- `secure/src/ui/pin_entry.rs:83`: the existing start-digit scrambler ignores a random-number failure and falls back to zeros. A mask must not do that.

## What is already tracked elsewhere

- #250 asks for an entry-based backup check ("never display-based"). It could reuse this dialog, and it does not address the bus.
- #784 and #858 make letter drawing constant-time on the processor side. The letters still go out on the bus.
- #237 is the display-emanation umbrella. It lists no bus-free flow.
- #860 covers the scrambler fallback mentioned above.
- #772 (closed) is the precedent that a seed-ceremony change needs an owner decision first.

So this issue is only the masked restore mode.

## Proposed work

- [ ] **First, and before anything else:** on an opened unit, confirm that the wires or flex from the button pads do not run with the display flex. On the main board the two are separate (see above). If they share a flex in the assembled unit, a display-side tap gets the buttons for free and this item should be closed.
- [ ] Owner decision: adopt or decline an opt-in third setup option, restore only.
- [ ] Dialog design:
  - one short press per bit, 24 words of 11 bits each;
  - a fresh mask bit per press, taken from one draw of the three-source random generator per attempt, and refusal (not a fallback) if that draw fails;
  - both labels always shown, symmetric ("L=1 R=0" or "L=0 R=1"), with a public word-and-bit counter;
  - the same repaint, on a fixed cadence, whichever button was pressed, because press timing is visible on the display bus;
  - only short presses count; long presses and the chord are ignored until the phrase is complete, with one defined way to cancel and one to undo;
  - each word entered twice under independent masks, showing only "match" or "mismatch", so an error is located to one word.
- [ ] After entry: validate with the existing checksum, then have the user confirm the wallet address they already know.
- [ ] Put the bit packing, mask handling and double-entry compare in a workspace crate with host tests, including a differential test against `from_indices`. Code under `secure/src/ui` is compiled out of host tests.
- [ ] Ship on the 16x4 path first. A pixel-UI version waits on that UI's flash budget.
- [ ] Publish a printable word-to-bits table and a one-page procedure, so the conversion is done by hand.
- [ ] Add a scoped row next to the residual in `docs/security/user-device-verification.md`. Do not delete the residual sentence.

## What it needs

Firmware only, after the owner decision. A usability trial needs a unit with a panel and buttons, which means an enclosed engineering-validation (EVT) unit (#700).

## Limits

- A tap on the display bus plus the two button lines recovers the whole seed. On the schematic the buttons are microcontroller pins 10 and 11 and the display lines are pins 14, 15, 17, 18, 19 and 20, so they sit close together on the 48-pin package and an implant built for pq1 needs two more wires. The claim is "defeats a display-only tap that was not adapted to pq1", nothing more.
- Restore only, and only for an existing valid phrase. A seed made by hand with dice or coins has no valid last word until a hash is computed, so this is not a way to create a wallet off the display.
- The phrase being restored has usually already been shown on the display of the device that created it.
- PIN entry still draws digits on the same bus.
- 264 blind presses are error-prone. At a 1 percent slip rate a single pass succeeds about 7 percent of the time, which is why double entry per word (528 presses) is in the design. That figure is arithmetic, not a trial.
- Press timing can correlate with the secret (one mapping needs an extra mental step). The fixed cadence reduces what the display bus shows of it and does not remove it.
- It does nothing against malicious firmware.
- Nothing here was built or run.

## Related

#250, #784, #858, #237, #860, #700, #772. Nearest public precedent, as an analogy only: [Trezor Model One advanced recovery](https://trezor.io/learn/a/advanced-recovery-on-trezor-model-one), which splits the secret between the device screen and host input.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item X1a, section 12). Report priority P3 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

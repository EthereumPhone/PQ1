TITLE: Bench go/no-go study: can firmware see a logger soldered to the display lines by timing how fast each line charges? Measure first, build no detector
LABELS: enhancement,priority:low,surface:hardware,surface:prodtest,surface:trusted-ui,source:frontier-research-2026-10
---
## Summary

The research found one publicly documented hardware-wallet implant (a teardown of a tampered Ledger Nano X): a small logger wired to the display bus, which read the screen content as it was drawn. pq1 cannot see such a tap: the panel is write-only, and the firmware measures nothing electrical. The research proposed a self-check in which the microcontroller briefly releases each display line and times how fast its internal pull-up charges it (an RC decay measurement). Extra capacitance from a soldered wire should slow the edge. Whether the effect is larger than normal unit-to-unit and temperature variation is unknown, and no published work shows a microcontroller detecting a passive tap this way. So this issue is only the measurement campaign that answers go or no-go. No detector, no refusal path and no factory baseline should be written before the numbers exist. Nothing in the tracker covers electrical sensing of any line.

## What the code does today

Lines at master `c2fab970`.

- `secure/src/board/pq1.rs:121`: the panel has no read-back line (`LCD_MISO_PIN` is `None`), so a paint can only be confirmed as "the bus finished", never as "the panel shows this".
- `secure/src/board/pq1.rs:117`, `secure/src/board/pq1.rs:118`, `secure/src/board/pq1.rs:119`, `secure/src/board/pq1.rs:125`: the display lines are PA4 (chip select), PA5 (clock), PA7 (data) and PB0 (data/command).
- `secure/src/board/pq1.rs:327`: PA6 is not connected on the board. It currently carries the consumption-mask timer output with no load (`secure/src/board/pq1.rs:333`). An unconnected pad is a usable reference: its charge time depends only on the pull-up and the pad itself.
- A search of `secure/src` and `fsbl/src` for ADC, comparator or touch-sensing use finds nothing.
- `docs/security/user-device-verification.md:163`: a logger on the display bus is recorded as an accepted residual, covered only by packaging and reference photos.
- `docs/hardware/evt-silicon-validation.md:471`: each button pad pair carries a 100 nF capacitor and an electrostatic-discharge (ESD) protection diode. With that much capacitance a few picofarads from a tap change the charge time by parts per million, so the button lines are excluded from this study.
- `proto/src/lib.rs:652`: the factory test command set starts here. A measurement command would join it and report raw counts over USB.
- `docs/hardware/evt-silicon-validation.md:1064`: an enclosed engineering-validation (EVT) unit has booted our firmware over USB (flashed with `tools/flash-evt-dfu.sh`), so enclosed units with a panel can run a test image.

## What is already tracked elsewhere

- #595 is the factory test runner and per-unit report that a measurement command would extend.
- #695 is the route for flashing enclosed EVT units.
- #249 is the signed per-unit factory record. A baseline value, if one is ever wanted, would ride there.
- #220 and the rollback design compete for the same one-time-programmable (OTP) memory words a stored baseline would need.
- #258, #260 and #784 are about what is drawn on the display. They detect nothing.

So this issue is only the bench measurement and its go/no-go rule.

## Proposed work

- [ ] Schematic read, done for this issue from rendered crops of `docs/hardware/schematics/AL_A66_MB_V10_20260826_1500.pdf` (the file has no text layer): the chip select, clock, data, data/command, reset and tearing lines are drawn straight from the microcontroller pins to the display connector `J201` with no series part in between, and PA6 (pin 16) has no net attached. I did not search both sheets for a pull resistor hung on one of those nets by name. Still to do: confirm on the copper plots that PA6 has no trace stub and that the display lines have no test pads, since either changes the method.
- [ ] Test-image measurement, per line, with the panel powered, chip select high, no frame in flight and the mask timer paused: drive the pad low as an open-drain output with the internal pull-up, release it, and time the input threshold crossing. Measure the falling edge through the pull-down too, to cancel threshold drift. Use timer input capture where the pin has a channel and cycle-counter polling where it does not. Decide a timing source for PB0.
- [ ] Do the same on PA6 and report each line as a ratio to it. Report absolute counts as well.
- [ ] Report raw counts through a factory test command over USB, because enclosed units have no debug port.
- [ ] Run on at least 5 enclosed EVT units with panel and flex fitted: repeatability on one unit, drift over temperature and after reseating the flex, and spread between units.
- [ ] On one opened unit, measure the change from a clipped probe and from a real soldered tap (a wire to a microcontroller input pin), on each line.
- [ ] Report whether measurement noise averages out the timer quantisation. The research reviewer estimated a floor of about 1 pF on every line from the short PA6 reference; that estimate is derived, not measured.
- [ ] Decision rule: GO only if worst-case drift plus unit spread is less than half the smallest soldered-tap change. Otherwise close this as an accepted residual, with the data attached.
- [ ] Either way, amend the residual text in `docs/security/user-device-verification.md` to say what was measured.

Not part of this issue, and only on a measured GO: a self-check in the updatable secure image (never in the bootloader, which is frozen at lock), refusing without wiping, and refusing when no baseline is present. An OTP word for a baseline would need an owner decision against the existing OTP plans. So would the use of PA6: a shipping image is required to run the consumption-mask output on that pad, so a self-check that borrows it as a reference needs a decision on what PA6 is for. A factory test image can pause the mask freely.

## What it needs

A bench campaign on existing units, no board change: at least 5 enclosed EVT units with a panel, flashed over USB; one sacrificial unit that can be opened and soldered to; a way to vary temperature. A reference capacitor on a free pad or an input-current monitor would need a new board and are not part of this issue.

## Limits

- No published work shows a runtime, on-chip detector of a passive tap. The published implant detectors use bench instruments, for example [PDNPulse](https://arxiv.org/abs/2204.02482), which is an offline measurement.
- Every number in the research is derived from datasheet values and assumed line capacitance (15 to 30 pF). None was measured on pq1.
- A tap buffered by a transistor or comparator adds about 1 pF or less and sits at the expected floor. The firmware is open source, so an attacker can build to pass the check. The most that could ever be claimed is "raises the cost of a directly soldered logger on the display lines".
- It cannot see a tap on the buttons, a swapped panel or flex with the logger inside it, a swapped board, or an implant fitted before a factory baseline is taken.
- The restore flow enters all 24 words through the buttons, which this method cannot cover.
- Nothing here was run on silicon.

## Related

#595, #695, #249, #220, [Ledger Nano X implant teardown (Grand)](https://grandideastudio.com/media/ledger_hardware_implant_slides.pdf).

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M10, section 1). Report priority P3 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

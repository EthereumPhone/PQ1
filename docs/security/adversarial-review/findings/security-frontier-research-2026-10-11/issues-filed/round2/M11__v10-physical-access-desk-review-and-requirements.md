TITLE: Desk review of the V10 artwork for where display and button lines can be tapped, plus anti-tamper requirement fixes, before the next board is specified
LABELS: documentation,priority:high,surface:hardware,surface:docs,source:frontier-research-2026-10
---
## Summary

An attacker who opens a unit and solders a logger to the display bus or the buttons gets the seed with the genuine firmware running. Firmware cannot see that, so the defence is physical: where the lines run, whether they have pads, and how the unit is closed. The research wrote a physical-access specification for the next board revision. Almost all of it needs a new board and is not asked for here. Three parts need no board change and are not tracked: reading the V10 copper plots that are already in the repository to learn where these lines are exposed today, correcting requirement rows that the research showed to be wrong or incomplete, and publishing reference material a buyer can compare a unit against. Doing them now means the next revision is specified against facts and not against rows that still say "board not started".

## What the repository says today

Lines at master `c2fab970`.

- `docs/hardware/pcb/README.md:7`: the six copper layers of the V10 board are in the repository as plots. `docs/hardware/pcb/README.md:32`: no tamper or side-channel review of that artwork has been done.
- `docs/hardware/schematics/README.md:30`: the cross-check of the schematic against the firmware pin table "has **not** been done". `docs/hardware/schematics/README.md:76`: there is no bill of materials in the repository.
- `docs/hardware/hardware_requirements.md:163`: no test pads or probe points on the display bus, the button lines or any secure-world peripheral. `docs/hardware/hardware_requirements.md:249`: that row is "board not started", although the V10 board exists.
- `docs/hardware/hardware_requirements.md:166`: the debug and reset pads "MUST stay accessible after assembly". The two rows do not say how they fit together.
- `docs/hardware/hardware_requirements.md:239`: a tamper mesh into an external tamper input is still a requirement row.
- `docs/security/user-device-verification.md:163`: a logger on the display bus, or a button injector, is the accepted residual. `docs/security/user-device-verification.md:166`: "published board photos for visual comparison" is named as a mitigating layer. The repository contains no board or unit photographs.
- `secure/src/ui/seed_wizard.rs:781`: restoring a wallet enters all 24 words through the two buttons. `secure/src/main.rs:1963`: after a wipe the device shows "restore from seed". So the button lines carry the whole seed on restore, not only the PIN.
- `secure/src/board/pq1.rs:363`: three microcontroller pads are free (PA10, PC13, PB4) and are not routed anywhere.

## What is already tracked elsewhere

- #850 holds the decision on how the debug port and reset are reached on a sealed unit. It is not repeated here.
- #866 holds the stale tamper-driver wording in the requirements document.
- #75 has the comment that the tamper status is cleared before it is read, which blocks any external tamper input.
- #695, #696 and #697 hold the questions for the board vendor about flashing, the boot pin and the secure-element part number.
- #598 is the same kind of desk review, for USB protection parts.
- {{H1}} holds what the same schematic shows on the backup supply pin and the two crystals, and the requirement rows that depend on it. They are left out here.

So this issue is only the desk review, the requirement corrections and the reference material.

## Proposed work

Desk review (no hardware):

- [ ] On the six layer plots, trace the display lines (chip select, clock, data, data/command, reset, tearing signal), the two button lines and the secure-element buses. Record which layers they use, where they come to the surface, and every test pad or via on them.
- [ ] From the schematic, list every pad, header and connector that exposes one of those lines. Already read for this issue, from rendered crops of sheet 2: the display lines go to a 40-pin connector (`J201`), and the two button nets are not on it; each goes through a 10 ohm resistor to its own pad pair (`J203` to `J206`).
- [ ] Write the result into `docs/hardware/evt-debug-pins.md` (existing document), marked as read from artwork and not measured.

Requirement corrections in `docs/hardware/hardware_requirements.md`:

- [ ] State that the button lines are as sensitive as the display lines, with the reason above.
- [ ] Make the "no test pads" rule and the "debug pads stay accessible" rule consistent: name the exemption, and point to #850 for the route.
- [ ] Re-evaluate the tamper-mesh row. The research concluded that on the 48-pin package an active mesh needs a tamper output that exists only on the two button pads and PC13, and dropped it. That was read from the datasheet by the research and not re-checked for this issue.
- [ ] Record the next-revision layout rules the research arrived at, clearly marked as not built: display and button lines between ground planes with no outer-layer vias near the display, no pads on those lines, no cavity behind the panel, potted display and button connectors. State in the same place that these raise cost and leave evidence and do not prevent a tap, because every line still surfaces at the chip, the connector and the panel.
- [ ] Owner decision, unticked: a shell that cannot be opened without visible damage, or a unit that can be opened for inspection. A welded shell and internal debug pads cannot both hold.
- [ ] Update the rows that say "board not started" for a board that exists.

Reference material:

- [ ] Ask the board vendor for the netlist and a bill of materials with exact passive values, and add them to the repository.
- [ ] Photograph a known-good unit (board both sides, assembled unit) and record its weight. Publish the photographs where the verification document says they exist. An X-ray is useful if one can be had.

## What it needs

Documentation and a desk read of files already in the repository. The photographs need one unit that may be opened. Everything that changes copper, parts or the shell waits for a new board revision.

## Limits

- Nothing here stops a tap. It finds out how easy one is on V10 and writes down what the next revision should do.
- Reference photographs help only a buyer who compares. An implant fitted at the factory is in the reference too.
- The plots are artwork without a netlist, so tracing a line across layers is manual and can be wrong. Findings should be marked accordingly.
- A case-open switch on the free tamper pad, and any response to it, need a new board and a separate design: today a wipe ends by asking the user to restore, which would mean typing the seed into a unit that was just opened.
- Nothing was measured or inspected for this issue.

## Related

#850, #866, #75, #695, #696, #697, #598, #391. Public reference for the implant class: [Ledger Nano X implant teardown (Grand)](https://grandideastudio.com/media/ledger_hardware_implant_slides.pdf).

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M11, section 1). Report priority P1 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

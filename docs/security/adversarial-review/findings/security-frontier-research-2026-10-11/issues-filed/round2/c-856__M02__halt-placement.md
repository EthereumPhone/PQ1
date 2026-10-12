COMMENT_ON: 856
---
**Where the halt can go (2026-10-11 security frontier research, item M02; a constraint the body does not state).**

The check sits at `secure/src/main.rs:1281`. In a build with both secure elements the first display init is at `secure/src/main.rs:1622`, and Phase A of the first-boot flow starts at `secure/src/main.rs:1633`. (The earlier display init is compiled only for builds without the SE050, see the `cfg` at `secure/src/main.rs:1297`.) A halt added at the current place would therefore:

- fire before the panel is up, so it cannot show the numbered fault screen the fix asks for;
- on a first boot with a wrong boot address, pre-empt Phase A, which already halts on the same field with a numbered code (`secure/src/first_boot/mod.rs:194`) and leaves the unit at RDP-0, as requirement R2.6 demands (`docs/provisioning/first-boot-requirements.md:65`).

The research's independent reviewer suggested: leave the pre-lock case to Phase A, and act on a mismatch only when the unit is already at RDP-2, after the display is up, and after two reads (the #835 lesson about halting on a single read). At RDP-2 the boot address cannot be rewritten (RM0456 Rev 7 section 7.6.2 excepts only SWAP_BANK), so this verdict is a tripwire for a fault-skipped Phase A or a glitched option-byte load, nothing more. That matches the "low" rating in the body.

- [ ] Move the verdict after the display init, or gate it on RDP level 2.
- [ ] Two reads before halting.

Evidence: code read at master. No production image was built (none can be built today).

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M02, section 6). Report priority P1 is a research rating, not an owner decision (the reviewer put this part at P3). Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

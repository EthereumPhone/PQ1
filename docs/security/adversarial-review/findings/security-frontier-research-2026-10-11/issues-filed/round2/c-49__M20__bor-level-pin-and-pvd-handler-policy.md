COMMENT_ON: 49
---
**Five things this issue does not say yet, from the 2026-10-11 security frontier research (item M20, the brown-out and voltage-detector part). The first one has a deadline: it must be settled before any unit runs the first-boot self-lock. Lines re-read at master `c2fab970`.**

Terms: BOR is the brown-out reset, whose level is the `BOR_LEV` option-byte field. PVD is the programmable voltage detector, an interrupt that fires at a threshold above the reset level.

**1. `BOR_LEV` is not part of the ship option-byte profile, so the self-lock would freeze whatever the factory left.** Readout protection level 2 (RDP-2), which the first-boot self-lock sets, freezes the option bytes for the life of the die.

- `shared/src/lockdown.rs:295`: the `ObField` list of checked fields has no brown-out entry.
- `shared/src/lockdown.rs:521`: `bor_lev()` only decodes the field. Its comment says it is "not yet a hard gate because the shipped BOR_LEV target is still being pinned".
- `secure/src/first_boot/mod.rs:247`: the burn path says "BOR is configured via the shipped option-byte profile", but the profile carries no such field.
- `Makefile:380`: the only recipe that sets it is the bench recipe (`BOR_LEV=3 SRAM2_RST=0`).
- The reference manual's production default decodes to `BOR_LEV` = 0, the 1.71 V floor (quoted in #848; not read from a pq1 die).

This is the same verifier change that #848 asks for the SRAM erase bits (profile field, Phase A check, bootloader tripwire, user-side read set). It would be cheapest to land both fields together.

- [ ] Add `BOR_LEV` to the ship profile, to `verify_ship_profile`, to the bootloader's read-only option-byte check and to the ship-profile files, as a hard gate before the RDP-2 burn. **This must land before the first unit is locked.**

**2. The level is an owner decision, and the documents disagree.** `docs/hardware/evt-silicon-validation.md:792` asks for level 4 or above, `docs/security/production-security.md:98` says "3 or 4", `docs/security/brownout-hardening.md:311` targets level 3 and labels it about 2.7 V. The research argues for level 3 with PVD level 5, not Trezor's level 4 with PVD level 5: by its reading of the datasheet, the level-4 reset threshold and the level-5 detector threshold coincide, so a PVD handler would race the reset and might never run, while level 3 (falling, typical 2.50 V) and PVD level 5 (falling, typical 2.78 V) are ordered at worst-case tolerances. **Those numbers come from a datasheet extract made early in the research. Neither the reviewer nor I re-read the datasheet.** A level frozen too low is permanently permissive; one frozen too high is a permanent source of nuisance resets on a USB-fed rail.

- [ ] Re-read the BOR and PVD threshold tables in the STM32U585 datasheet, choose the pair, and record the decision. Make the three documents agree.
- [ ] Before freezing it: measure the 3.3 V rail on existing engineering-validation (EVT) units across USB hosts and cables, including the transient when the secure-element rail is switched on. No issue tracks that measurement.

**3. The handler must touch RAM only.** This issue's body says to route the interrupt "to the zeroize/lockout path". The existing lockout and intrusion path is the wrong target for a supply event: `secure/src/hw/tzic.rs:228` (`trigger_intrusion_wipe`) writes a flash flag (`secure/src/hw/tzic.rs:246`) so that the next boot factory-resets both secure elements. Wired to a voltage detector, that is a flash write during a sag, and a marginal cable would erase wallets.

- [ ] PVD handler: zeroize secure RAM, then reset. No flash write, no secure-element traffic, never the intrusion wipe.

**4. Priority and masking.**

- [ ] Secure SysTick is already at the highest priority (`secure/src/main.rs:889`), so a PVD interrupt "at highest priority" ties with it and cannot preempt it. Under `tamp-wipe`, SysTick is where the tamper poll calls the intrusion wipe (`secure/src/hw/tamp.rs:108`). State the intended order.
- [ ] Mask the detector during the RDP-2 option-byte write and during the first-boot key-rotation steps, and rely on the brown-out reset there. A detector reset in the middle of those turns a sag the device would have survived into an interrupted irreversible write.

**5. Smaller notes.**

- No PVD code exists at master: a search of `secure/src`, `fsbl/src`, `shared/src` and `nonsecure/src` for `PVDE` and `PVDLS` finds nothing.
- The status table in `docs/security/brownout-hardening.md` is stale in the other direction for the watchdog: `docs/security/brownout-hardening.md:314` says it is disabled with no code, while `iwdg` is in the ship feature set (`Makefile:2662`).
- The detector's enable bits sit in the power controller, which the non-secure world can write until #269 lands. Until then non-secure code could switch the detector off.
- Do not add a detector to the first-stage bootloader. It holds no secrets and freezes at RDP-2; the read-only `BOR_LEV` compare is the only part that belongs there.
- Optional: the USB port-protection switch has a fault output routed to PB10 that no code reads (`secure/src/board/pq1.rs:310`). It could be read as a port-fault signal once its polarity is checked against the part's datasheet.

**Limits.** A voltage detector and a brown-out reset see slow sags. Published glitches last 100 to 400 ns and pass under both, so the double-compute and sentinel checks stay the defence against those. With no battery, an attacker can also cut power after a trip and try again. An earlier research note that a brown-out reset skips a needed RAM scrub was refuted on re-check: the runtime clears `.bss` and `.data` on every reset, and what survives is the stack, which is #848.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M20, section 11). Report priority P0 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; the datasheet thresholds were not re-read and nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

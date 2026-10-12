TITLE: Ship option-byte profile has no field for SRAM_RST (or SRAM2_RST / SRAM2_ECC / SRAM3_ECC): the first-boot self-lock would freeze the factory default, which never erases secure RAM on reset
LABELS: finding,ship-blocker,priority:high,surface:lockdown,source:frontier-research-2026-10
---
## Summary

RDP-2 freezes the option bytes for the life of the die. The verifier that decides whether a unit is in the ship state before that lock has no field for the four SRAM option bits. Whatever the factory leaves is what gets frozen. ST's production default leaves all four off, so by default the RAM that holds the wallet's secrets is never erased by hardware on a reset.

The bit that matters is `SRAM_RST`. The secure world runs entirely in SRAM1 (`secure/memory-stm32u585.x:31`), and `SRAM_RST` is the only hardware erase that covers it.

## Evidence

Line numbers at master `0feea78a` (2026-10-11). The research ran at `c75b0d9c`, an ancestor of master; the cited files were diffed against master before filing.

- `shared/src/lockdown.rs:295-312`: `ObField` has no SRAM variant. `:533-582`: `verify_ship_profile` checks none of the four bits.
- No field for them exists in `fsbl/src/optbytes.rs`, in `secure/src/first_boot/mod.rs`, or in either profile under `tools/ship-profiles/`.
- `Makefile:374-380`: the only recipe that sets a RAM-erase bit sets `BOR_LEV=3 SRAM2_RST=0`. SRAM2 is the **non-secure** world's RAM (`nonsecure/memory-stm32u585.x:9`).
- RM0456 Rev 7, section 7.9.13 (FLASH_OPTR): "Bit 15 SRAM_RST: All SRAMs (except SRAM2 and BKPSRAM) erase upon system reset. 0: erased when a system reset occurs. 1: not erased". `SRAM2_RST` is bit 25, `SRAM2_ECC` bit 24, `SRAM3_ECC` bit 23. All four are active-low.
- Same section: "ST production value: 0x1FEF F8AA". That decodes to all four bits = 1 (no erase on reset, ECC off) and `BOR_LEV` = 0.

## Why it matters

- Handler stack copies of secrets are not scrubbed on a halt or an abnormal reset. The boot scrub clears named statics, and the runtime's reset code clears `.bss` and `.data`. The stack and unused SRAM1 keep their contents across a reset, and the whole of SRAM1 is intact while the FSBL runs (about 7 s on pq1).
- The glitch-halt path parks without zeroizing ({{08}}). After the watchdog reset, only `SRAM_RST=0` would clear what it left.
- Raising the brown-out level, which other issues ask for, creates more resets and so more of these windows.

## Severity and evidence level

- Severity: **high once the self-lock ships** (irreversible per die); none today, because nothing has shipped and no production image can be built.
- Evidence: code read, plus the reference manual text, which I re-read myself. The production default is the manual's value and has **not** been read from a pq1 die. Bit position and polarity should be confirmed on a sacrificial part.
- The ECC half is nearly moot for the secure world: SRAM1 has no ECC (RM0456 Table 46), `SRAM2_ECC` covers non-secure RAM and SRAM3 is unused. It matters only if the secure world is moved to an ECC bank.

## Fix directions

- [ ] Add `SRAM_RST = 0` to the ship profile, to `verify_ship_profile` (Phase A), to the FSBL tripwire and to the user-side read set.
- [ ] Set it in the factory recipe before the RDP-2 burn. `Makefile:374-380` sets the wrong bank for this purpose.
- [ ] Decide the SRAM ECC bits with the secure-RAM-bank question (keep SRAM1, or move secrets to SRAM2 as Trezor does so that a hardware tamper also erases them), then pin them.
- [ ] Confirm bit position, polarity and the erase behaviour with a canary-plus-reset test on a sacrificial die.

## Related

#82 (covers the bench recipe only), #48, #46, #248, #595, #270.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M21 / M04 / M20, defect row C4 (and the stack-residue part of A19)). Re-checked before filing by an independent read at `c75b0d9c` (verdict: partly; corrections applied here: the verifier lines are `:533-582`, and the ECC half is moot for the secure world). The brown-out half of row A19 was refuted on that re-check and is not filed. The full report is `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`; it was not committed when this issue was filed, so this body is written to stand alone.</sub>

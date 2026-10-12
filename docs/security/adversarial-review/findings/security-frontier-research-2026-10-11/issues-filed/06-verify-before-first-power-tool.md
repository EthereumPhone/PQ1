TITLE: The verify-before-first-power check that invariant 10(a) depends on cannot be run by a buyer: tools/verify_ship_state.py hashes zero bytes of flash, has only a bench profile, and no sealed unit exposes SWD
LABELS: finding,priority:critical,surface:lockdown,surface:hardware,surface:release,source:frontier-research-2026-10
---
## Summary

Invariant 10(a) says a unit ships at RDP-0 so that anyone can read flash, option bytes and OTP over SWD before first power and compare them with the reproducible build. That check is the only control in the design that does not depend on the factory being honest. Today it cannot be performed:

1. The tool compares 16 option-byte fields and **hashes no flash at all**.
2. The only runnable profile is a bench profile. The ship template is refused.
3. Its write guard is a deny-list, although its docstring and the Makefile call it an allow-list.
4. The sealed EVT unit has no reachable SWD.

## Evidence

Line numbers at master `0feea78a` (2026-10-11). The research ran at `c75b0d9c`, an ancestor of master; the cited files were diffed against master before filing.

- `tools/verify_ship_state.py:34-38`: the docstring says every programmer invocation is "checked against an allow-list of read verbs". `:53-75`: the code is `WRITE_VERBS = {...}`, a deny-list.
- `tools/ship-profiles/bench-rdp0-tzen.json` has no `flash` key. `tools/ship-profiles/ship-option-b.template.json` has `"flash": []`. `:119-126` refuses the template.
- `:84-104`, `:133-155`: the read set. It has no OTP, no device UID, no IDCODE, no OEM-lock bits, and no per-device pages 123 to 127. Neither profile lists `BOR_LEV`, any SRAM bit, WRP2A/2B or the OEM locks.
- `tools/verify_ship_state.py:112-115`: default `--mode UR` (connect under reset), which needs NRST.
- `docs/hardware/evt-silicon-validation.md:661-663`: "No SWD — the enclosed unit's 10-pin connector is removed and the pads are inside the case."
- `docs/security/user-device-verification.md:184-186` proposes SWD on the USB-C sideband pins with "No NRST needed (vector catch)". That conflicts with the tool's connect-under-reset default and with invariant 10(a)'s "before first power": without NRST, resident firmware runs until the probe halts it.

## What an attacker needs

Access to a unit in transit, which ships at RDP-0 by design. Without a working check, a reflash, an option-byte change, a planted OEM regression key or a read of the OTP transport master is not detectable by the buyer.

## Severity and evidence level

- Severity: **high for the invariant 10 claim**. The report ranks this leg P0, anchored on the hardware access decision and not on tool packaging.
- Evidence: code read; re-checked independently (confirmed, and stronger than the report said: zero bytes of flash are hashed). The tool was not run. Whether the production enclosure will expose SWD is a hardware decision not visible in the repository.

## Fix directions

- [ ] **Owner and board vendor decision first:** how SWD, NRST and ground are reached on a sealed unit (USB-C sideband with the two pins split, or a pogo-pad window), and whether NRST is included.
- [ ] A real ship profile: both flash banks hashed against the reproducible build, every option-byte register (including NSBOOTADD0/1, the WRP UNLOCK bits, SECWMxR2, `BOR_LEV`, the SRAM bits), the OEM-lock bits at `FLASH_NSSR` 18 and 19, an OTP programmed-word map, the UID at `0x0BFA_0700`, IDCODE, and pages 123 to 127 blank.
- [ ] Replace the deny-list with an allow-list of read commands, as documented.
- [ ] State in the user documentation what the check proves (firmware and configuration) and what it does not (a board-level implant, a transplanted chip).
- [ ] Package it so a buyer can run it.

## Related

#595 (per-unit factory record), #46, #695 (sealed-unit access), #226, #249.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M09 leg 1, defect row D1). Re-checked before filing by an independent read at `c75b0d9c` (verdict: confirmed and stronger than written). The full report is `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`; it was not committed when this issue was filed, so this body is written to stand alone.</sub>

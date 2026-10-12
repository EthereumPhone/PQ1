TITLE: RDP-2 burn routine is inert: OPTSTRT / OBL_LAUNCH / OPTLOCK are written to FLASH_SECCR, where they do not exist, and the routine returns Ok (split out of #268)
LABELS: bug,finding,ship-blocker,priority:high,surface:lockdown,source:frontier-research-2026-10
---
## Summary

`program_rdp_level2_and_launch` stages `RDP = 0xCC` and then writes the commit bit to the wrong register. Per the SVD, `OPTSTRT` (bit 17), `OBL_LAUNCH` (bit 27) and `OPTLOCK` (bit 30) exist only in `FLASH_NSCR` (offset 0x28). `FLASH_SECCR` (0x2C) implements none of them. The commit therefore does nothing, the `OPTLOCK` check can never fire, and the function reports success. A unit that ran this flow would believe it is locked while staying at RDP-0.

The defect is already documented in place, in a comment block in the source, and is mentioned inside #268. It has no issue of its own. This issue exists so that it cannot be lost when #268 is closed or re-scoped.

## Evidence

Line numbers at master `0feea78a` (2026-10-11). The research ran at `c75b0d9c`, an ancestor of master; the cited files were diffed against master before filing.

- `secure/src/hw/flash.rs:384-394`: the in-source "KNOWN DEFECT #268" block, which states the above and says it was left unfixed deliberately because the path is irreversible and wants an owner decision plus a sacrificial-silicon plan.
- `secure/src/hw/flash.rs:549`: `if REG.seccr.read() & OPTLOCK != 0` (reads a bit that is not implemented there).
- `secure/src/hw/flash.rs:558`: `REG.seccr.write(OPTSTRT);` (the inert commit).
- `secure/src/hw/flash.rs:560-565`: the error check uses `ERR_MASK` only. The comment says `OPTWERR` "lives in a separate bit that is a runbook pin" and calls a missed `OPTWERR` non-fatal. RM0456 Rev 7 section 7.9.7 places `OPTWERR` at `FLASH_NSSR` bit 13.

https://github.com/EthereumPhone/PQ1/blob/0feea78a1b8bd5ecaa99c3346a5a69480fd13cbc/secure/src/hw/flash.rs#L384-L394

## Preconditions

None. This is not an attack; it is a lock step that does not lock. The code has never been executed: `rdp2-self-lock` is production-quarantined. It becomes a shipping defect the moment a production build exists, because `mode-production` forces `rdp2-self-lock` on.

## Severity and evidence level

- Severity: **high for the invariant 10 claim** (a device that reports "locked" at RDP-0).
- Evidence: code read, re-opened by the filer; the source itself documents the defect. Never executed on silicon.

## Fix directions

- [ ] Move the three option-byte control accesses to `REG.nscr` (already bound and correct per the in-source note).
- [ ] Pin the `OPTWERR` bit and treat an option-write error as a hard failure of the burn, not as "retry next boot".
- [ ] Mask PVD for the duration of the option-byte write (brown-out interaction, see #49).
- [ ] Overwrite the OEM1 and OEM2 keys in the same ceremony, and halt first if a lock bit is already set (ties to #46 and #387).
- [ ] Prove on a sacrificial STM32U585 that the routine actually reaches RDP-2 and that a read-back confirms it, before any ceremony uses it.
- [ ] Keep `negative_optbyte_commit_defect_268_is_marked_or_fixed` green by switching it from "marked" to "fixed".

## Related

#268 (parent tracker), #46, #387, #40, #45 (sacrificial part), #49.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M09, defect row B1). Source lines re-opened by the filer at master `0feea78a`; the `OPTWERR` bit position was read from the local RM0456 Rev 7 text. The full report is `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`; it was not committed when this issue was filed, so this body is written to stand alone.</sub>

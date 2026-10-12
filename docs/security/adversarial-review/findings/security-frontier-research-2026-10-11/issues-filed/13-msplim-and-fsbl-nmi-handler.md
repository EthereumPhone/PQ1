TITLE: No stack limit register (MSPLIM) is set in any image, and the FSBL has no NMI or ECC handler; the FSBL half can never be added after the freeze
LABELS: finding,priority:high,surface:runtime,surface:lockdown,source:frontier-research-2026-10
---
## Summary

Two fail-stop gaps in memory integrity.

1. **No stack limit.** No image sets `MSPLIM` or `PSPLIM`. Statics sit below the stack, so a secure stack overflow would run into `.bss` and `.data` silently instead of faulting.
2. **No NMI or ECC handler in the FSBL.** A persistent double-bit ECC error in a flash word the FSBL reads would halt every boot, even when the other slot is good.

The FSBL becomes permanent at the WRP plus RDP-2 freeze (invariant 10), so its half of both items has a deadline.

## Evidence

Line numbers at master `0feea78a` (2026-10-11). The research ran at `c75b0d9c`, an ancestor of master; the cited files were diffed against master before filing.

- A search for `msplim` / `psplim` over `fsbl/`, `secure/`, `nonsecure/`, `shared/`, `geometry/`, `pqsigner-fi/` and `hal/` finds two comments only: `fsbl/src/main.rs:172` and `fsbl/src/manifest.rs:30`. The first one reads "peaked main's frame at ~24.7 KB against a 16 KB RAM budget with no MSPLIM — a silent stack overflow".
- The locked `cortex-m-rt` (0.7.5) has no stack-limit feature. There is no `flip-link` and no MPU setup in `secure/src` or `fsbl/src`.
- `fsbl/src/main.rs:76-78`: no `#[exception]` anywhere in `fsbl/src`, so NMI and HardFault fall to the runtime's default infinite loops. `:197-198`: both manifests are read before a slot is picked, so one bad word blocks both.
- RM0456 Rev 7, section 7.3.2: "When two errors are detected, the ECCD flag (ECC detection) is set in FLASH_ECCR. In this case, an NMI is generated."
- Secure world: `secure/src/main.rs:4705-4725` (the NMI handler) zeroizes and resets without reading `FLASH_ECCR`, so a torn word in page 123 or 124 could become a reset loop. That half is tracked in #94.

## Preconditions

- Stack: an input that drives stack depth past the bound. Whether any input can do that is unproven (#374).
- ECC: a power cut during a slot or manifest program that leaves a word reading as a two-bit error. Whether a torn write does that on this part is unmeasured. The same manual section notes that an erased line supports no two-error detection.

## Severity and evidence level

- Stack limit: **medium, unproven** (skeptic); low for the FSBL alone.
- FSBL handler: **medium (availability), conditional** on the silicon behaviour.
- Evidence: code read; re-checked independently (both confirmed). Nothing measured on silicon.

## Fix directions

- [ ] Set `MSPLIM` in the secure reset path and in the FSBL, with a fault path that re-bases the stack before it runs.
- [ ] FSBL: an NMI handler that reads `FLASH_ECCR`, records the failing address, and lets slot selection fall back to the other slot when the bad word is in one slot's range.
- [ ] Secure world: decode `FLASH_ECCR` in the NMI handler before deciding to reset (#94).
- [ ] Confirm on a sacrificial die whether a torn flash quad-word raises NMI.
- [ ] Both FSBL changes must land before the geometry freeze and fit the FSBL size budget (#540).

## Related

#94, #374, #540, #544.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M21 / M05 / M08, defect row A18 and C12). Re-checked before filing by an independent read at `c75b0d9c` (both confirmed). The full report is `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`; it was not committed when this issue was filed, so this body is written to stand alone.</sub>

TITLE: The secure-world SECBOOTADD0 check does nothing in production: its mismatch branch contains only secure_log!, which compiles to nothing without debug-log
LABELS: finding,priority:low,surface:lockdown,source:frontier-research-2026-10
---
## Summary

At boot the secure world reads `FLASH_SECBOOTADD0R` and tests whether it selects the FSBL base. On a mismatch the only statement in the branch is a `secure_log!`. That macro expands to nothing unless `debug-log` is enabled, and `debug-log` must be off in a shipping image. So in production the check has no effect: no halt, no screen, no state change.

## Evidence

Line numbers at master `0feea78a` (2026-10-11). The research ran at `c75b0d9c`, an ancestor of master; the cited files were diffed against master before filing.

- `secure/src/main.rs:1280-1292`: `let secboot = hw::flash::secboot_add0_reg(); if !lockdown::secboot_selects(secboot, hw::flash::FSBL_BASE_ADDR) { secure_log!("[S][lockdown] WARNING: SECBOOTADD0R=... does NOT select the FSBL base ..."); }`.
- `secure/src/main.rs:62-64`: the `secure_log!` definition (empty without `debug-log`).

https://github.com/EthereumPhone/PQ1/blob/0feea78a1b8bd5ecaa99c3346a5a69480fd13cbc/secure/src/main.rs#L1280-L1292

## Why the impact is limited

`SECBOOTADD0` is frozen at RDP-2, and Phase A of the first-boot candidate halts on it before the burn. No option-byte write can reach the mismatch state after the lock. The check only matters if Phase A itself was skipped by a fault.

## Severity and evidence level

- Severity: **low-medium** (cluster merger); **low** (skeptic, final value).
- Evidence: code read, re-opened by the filer. Not link-verified (I did not confirm in a production ELF that the branch is empty; no production ELF can be built today).

## Fix directions

- [ ] Make the mismatch a verdict that does something in production: halt with a numbered fault screen, consistent with the FSBL option-byte tripwire (#270).
- [ ] Add a source-invariant test that rejects any security verdict whose only consequence is a log macro, so the next instance is caught by a test and not by review.

## Related

#270 (FSBL option-byte verifier), #46, #753.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M02, defect row A21). Source lines re-opened by the filer at master `0feea78a`. The full report is `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`; it was not committed when this issue was filed, so this body is written to stand alone.</sub>

COMMENT_ON: 75
---
**A hard blocker for this issue: `tamp::init` clears the tamper status before anything reads it (2026-10-11 security frontier research, defect A16).**

At master `0feea78a`, `secure/src/hw/tamp.rs:270-272`:

```rust
// Clear any pending tamper flags from a prior power cycle (backup
// domain survives reset, so we may see stale flags at first boot).
REG.tamp_scr.write(0x0007_FFFF);
```

This write is the first TAMP register access of the boot. The first read of `TAMP_SR` is later, in `poll` (`:86`). So a tamper that latched before the reset is erased with no wipe and no record. Escalating the handler to a wipe, which is what this issue asks for, does not help for those events until this is fixed.

Details from an independent re-check of the claim:

- The mask `0x0007_FFFF` covers the eight external tamper flags plus internal tampers 1, 2 and 3. Tamper 3 (LSE monitor) cannot fire here, so the live sources inside the mask are internal tampers 1 and 2 (backup-domain voltage and temperature), plus any external input added later.
- The exposed window is larger than "about 1 ms". `TAMP_SR`, `TAMP_CR1` and `PWR_BDCR1.MONEN` are all unaffected by a system reset (RM0456 Rev 7, section 64.7), so tampers 1 and 2 stay armed through reset hold, the whole FSBL (about 7 s on pq1) and secure boot up to `secure/src/main.rs:1403`. Any event in that window is erased the same way.
- For internal tampers 5 to 13, which are outside the mask: the boot hardware key is loaded (`secure/src/main.rs:1532`) before SysTick starts polling (`:1647`). The manual says device secrets are not accessible while a tamper flag is set, so the likely outcome of a latched flag is the panic at `:1548` and a parked core, not a wipe. This is a reading of the manual. The tamper stack has never run on silicon (#391).

Suggested checklist additions:

- [ ] Read and act on `TAMP_SR` before the first `TAMP_SCR` write.
- [ ] Decide what a tamper that latched while the secure world was not running should do (wipe at boot, or a persistent "tamper seen" state).
- [ ] Order the hardware-key load after the first tamper evaluation, or handle the "secrets inaccessible" case explicitly.

Severity as rated by the research: medium (cluster merger), low-medium (skeptic, final); blocking for any external tamper input. Evidence: code read plus reference manual; nothing run on silicon.

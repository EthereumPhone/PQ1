TITLE: halt_on_glitch parks in a bare wfe loop without zeroizing on a genuinely detected glitch (the part of #835 H4 that survives removing the TRNG-failure sink)
LABELS: finding,priority:medium,surface:sca-fi,surface:runtime,source:frontier-research-2026-10
---
## Summary

When a fault-injection sentinel trips, `pqsigner_fi::halt_on_glitch` parks the core in `loop { wfe() }`. It does not zeroize, does not mask interrupts and does not reset. If the trip happens inside an unlocked gateway handler, `master_secret`, the slot entropy and the cached slot key stay in secure SRAM for as long as the core is parked. HardFault, NMI and panic all zeroize first. This is the only park that does not.

#835 (H4) describes the same code for the path `halt_countermeasure_unavailable` → `halt_on_glitch` (the TRNG-failure sink). The proposed resolution of #835 is to stop halting on a TRNG failure and propagate an error instead. That removes one caller. It does **not** change the two call sites where a real glitch is detected, which is the case that matters most: a detected glitch means someone is physically attacking the device. This issue tracks those sites so they are not closed by accident with #835.

## Evidence

Line numbers at master `0feea78a` (2026-10-11). The research ran at `c75b0d9c`, an ancestor of master; the cited files were diffed against master before filing.

- `pqsigner-fi/src/lib.rs:263-271`: `fn halt_on_glitch() -> ! { loop { cortex_m::asm::wfe(); } }`.
- `pqsigner-fi/src/lib.rs:143-145` and `:152-154`: the two genuine-detection callers inside `wait_random_loop` (the `i + j != wait` invariant and the loop-completion double check).
- `pqsigner-fi/src/lib.rs:256-261`: the doc comment justifies the silence with the #484 rule that a glitch halt must not touch a peripheral the attacker may control. That rule is about the display bus. It says nothing against wiping SRAM (the point #835 H4 also makes).
- `secure/src/main.rs:4413`: the SysTick idle wipe is skipped while `nsc::handler_is_busy()`, so it does not rescue this case.
- `secure/src/hw/iwdg.rs:137`, `:287-303`: the watchdog eventually resets the device. By source read the window is about 32 s from thread context (30,000 busy ticks plus the watchdog period) and about 2 s from SysTick context.

https://github.com/EthereumPhone/PQ1/blob/0feea78a1b8bd5ecaa99c3346a5a69480fd13cbc/pqsigner-fi/src/lib.rs#L263-L271

## What an attacker needs

A detected glitch during signing or unlock, then a second physical capability to read secure SRAM while the core is parked (or residue after the watchdog reset, see {{04}}).

## Severity and evidence level

- Severity: **medium-high** (cluster merger); **medium** (skeptic, final value).
- Evidence: code read, re-opened by the filer. The window lengths are from source, not measured.

## Fix directions

- [ ] Pass a diverging `on_glitch` action into `wait_random_loop`: mask interrupts, zeroize sensitive state, then request a system reset. No display or bus access, which keeps the #484 rule.
- [ ] `pqsigner-fi` is a workspace crate shared with the FSBL, so the action must be injected by the caller. The FSBL holds no secrets and can keep the bare park.
- [ ] Record, with a source test, that a detected fault does not consume a PIN attempt outside the PIN gate.
- [ ] Stack residue is not closed by zeroizing statics. That needs the `SRAM_RST` option byte (#82), staged before the RDP-2 burn.

## Related

#835 (H4, H5), #834, #484, #82.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M04, defect row A6). Source lines re-opened by the filer at master `0feea78a`. The full report is `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`; it was not committed when this issue was filed, so this body is written to stand alone.</sub>

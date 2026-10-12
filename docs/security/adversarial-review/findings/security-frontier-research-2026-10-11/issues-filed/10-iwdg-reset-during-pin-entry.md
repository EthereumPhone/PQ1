TITLE: PIN entry does not hold TrustedUiWaitGuard while iwdg is in the ship set: by source read, an ordinary slow PIN entry ends in a watchdog reset
LABELS: finding,priority:medium,surface:trusted-ui,surface:runtime,source:frontier-research-2026-10
---
## Summary

The confirm dialog takes `TrustedUiWaitGuard` so the watchdog keeps being fed while the device waits for a human. The PIN dialog does not. `iwdg` is in the shipping feature set. By reading the source, a user who takes longer than the budget to type the PIN gets a device reset in the middle of entry.

## Evidence

Line numbers at master `0feea78a` (2026-10-11). The research ran at `c75b0d9c`, an ancestor of master; the cited files were diffed against master before filing.

- `secure/src/nsc/cmd_request_unlock.rs:35`: the USB unlock handler takes `HandlerGuard` only.
- `secure/src/ui/pin_entry.rs:102-103`: `let event = match input().wait_button(&mut idle)` with no guard.
- The guard is taken at `secure/src/ui/confirm.rs:194` (and at the pixel-UI confirm sites, which are not in the ship set).
- `secure/src/hw/iwdg.rs:287-303`: the handler-busy branch feeds only while `b < MAX_BUSY_TICKS` (`:126`, `:137`). `:305-322`: the non-secure stall limit.
- Budgets by source read: USB unlock about 30 s from veneer entry (about 32 s including the hardware timeout); the PendSV idle re-unlock (`secure/src/main.rs:4559-4697`) about 4 s of stall budget (about 6 s in total).
- The boot-time prompt is not affected: `iwdg::init()` is at `secure/src/main.rs:4268`, after the boot unlock loop.

## Consequence

Availability only. A reset during digit entry consumes no attempt. A reset that lands during the secure-element verify, after the page-124 pre-commit (`secure/src/nsc/mod.rs:1494`), does consume one.

## Severity and evidence level

- Severity: **medium (availability)**.
- Evidence: **code read only**. Never built or run with `iwdg` on. Button PIN entry has never run on pq1 silicon (#700). `shared/src/lockdown.rs` does not pin the `IWDG_SW` option bit, so the hardware-watchdog behaviour at boot is unchecked.

## Fix directions

- [ ] Run one `iwdg`-on build with a deliberately slow PIN entry first, to confirm or refute this on hardware.
- [ ] Take `TrustedUiWaitGuard` around `enter_pin()`, as the confirm dialog does.
- [ ] Add a source test that every trusted-UI wait loop holds the guard.

## Related

#700, #729, #637.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M12, defect row A14). Re-checked before filing by an independent read at `c75b0d9c` (verdict: confirmed by source read). The full report is `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`; it was not committed when this issue was filed, so this body is written to stand alone.</sub>

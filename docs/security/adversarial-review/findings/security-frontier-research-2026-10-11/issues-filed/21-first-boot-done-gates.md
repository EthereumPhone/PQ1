TITLE: First-boot journal: ALL_DONE is committed without requiring the earlier step bits, and all_done() tests that one bit, so a step skipped by one fault is never re-run
LABELS: finding,priority:medium,surface:lifecycle,surface:sca-fi,source:frontier-research-2026-10
---
## Summary

The first-boot candidate (`rdp2-self-lock`) runs a journaled sequence: burn RDP-2, write the boot hardware key, rotate the SE050 and OPTIGA credentials from transport to final. Each step is skipped when its "done" bit is set. Those skip gates are single unhardened branches. The last step commits `ALL_DONE` without checking that the earlier bits are set, and later boots return early on that one bit. A single fault that skips one step therefore leaves a device that considers first boot complete with that step never done.

`rdp2-self-lock` is forced on for `mode-production`, so this is ship-set code once a production image can be built.

## Evidence

Line numbers at master `0feea78a` (2026-10-11). The research ran at `c75b0d9c`, an ancestor of master; the cited files were diffed against master before filing.

- `secure/src/first_boot/state.rs:306`, `:323`, `:333`, `:345`: the per-step gates `if done & DONE_x == 0 { ... }`.
- `secure/src/first_boot/state.rs:375-378`: `if done & DONE_ALL == 0 { hw.commit_step(STEP_ALL_DONE) }` with no check of the other bits.
- `secure/src/first_boot/journal.rs:102-104`: `pub fn all_done(&self) -> bool { self.has(DONE_ALL) }`.
- `secure/src/first_boot/mod.rs:419-421`: later boots return early on it.

## Consequences traced so far

- OPTIGA salt step skipped: `FinalPbsSaltMissing` (`secure/src/hw/secret_keys.rs:533`), fails closed.
- SE050 SCP03 rotation skipped: fails closed, because transport keys are used only by first-boot code (`secure/src/se050/mod.rs:421`, `:538`).
- Boot-key first write skipped: the anti-pre-plant erase is skipped and the next boot likely panics (`secure/src/main.rs:1519`).
- **Admin re-key skipped: not traced.** It may leave a device that works but whose lockout wipe cannot authenticate. This is the case that could raise the severity.

## Severity and evidence level

- Severity: **low-medium, untraced**. The step records themselves are CRC-framed; the weakness is in the gates.
- Evidence: code read; re-checked independently (confirmed, and stronger than the report said). The flow has never run on silicon and is production-quarantined.

## Fix directions

- [ ] Route each `done` gate through `fi::check_true_into_sentinel`.
- [ ] Make `ALL_DONE` require every earlier bit, and make `all_done()` test the full mask.
- [ ] Trace the admin re-key case and record the result here.

## Related

#268, #712, {{05}}.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M04, defect row B5). Re-checked before filing by an independent read at `c75b0d9c` (confirmed). The full report is `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`; it was not committed when this issue was filed, so this body is written to stand alone.</sub>

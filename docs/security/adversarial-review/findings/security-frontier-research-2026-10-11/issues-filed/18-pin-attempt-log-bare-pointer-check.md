TITLE: cmd_pin_attempt_log guards its write to a non-secure pointer with one bare branch (no FI sentinel), unlike its sibling handlers
LABELS: finding,priority:low,surface:trustzone,surface:sca-fi,source:frontier-research-2026-10
---
## Summary

`cmd_pin_attempt_log` writes 36 bytes to an address supplied by the non-secure world. The pointer check is a single `if !validate_ns_write_ptr(...)`. One skipped instruction turns it into a 36-byte write to a secure address chosen by the caller. The sibling handler `cmd_fw_status` documents this exact shape as a known single-fault failure and uses the sentinel gate instead.

## Evidence

Line numbers at master `0feea78a` (2026-10-11). The research ran at `c75b0d9c`, an ancestor of master; the cited files were diffed against master before filing.

- `secure/src/nsc/cmd_pin_attempt_log.rs:23-25`: `if !validate_ns_write_ptr(args.arg1, OUT_LEN) { return NscStatus::InvalidPointer as u32; }`. `:29-33`: 36 volatile writes.
- `secure/src/nsc/mod.rs:2072-2083`: the veneer has no `cfg`, so it is in every image.
- `secure/src/nsc/cmd_fw_status.rs:41-42`: "HIGH-1 (audit fault-injection 20260611): sentinel-gate the NS write pointer (bare if !validate is single-fault FAIL-OUT → OOB write)."

## Limits

- The attacker needs non-secure code execution to supply the pointer, plus one instruction-skip glitch.
- The payload is log codes, not attacker-chosen bytes: `[0x01, count <= 16, dropped_be16, (reason, pre_count)...]`, so the first byte is fixed.
- "No PIN gate" on this command is a recorded owner question (#719) and is not part of this issue. The missing `HandlerGuard` is harmless here, because the handler touches no state that the idle wipe clears.

## Severity and evidence level

- Severity: **low** (one lens), **low-medium** (the other).
- Evidence: code read; re-checked independently (confirmed). Not disassembled, so "one instruction" is a source-level reading. The fault was not demonstrated.

## Fix directions

- [ ] Convert the check to the `fi::check_true_into_sentinel` gate used by `cmd_fw_status`.
- [ ] Finish #84 and add a lint that bans `validate_ns_*_ptr(` outside the validation modules, so the next handler cannot repeat it.

## Related

#84, #140 (the same pattern in the prodtest handlers), #719, #152.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item USB-06, defect row A27). Re-checked before filing by an independent read at `c75b0d9c` (confirmed; only the bare branch is the defect). The full report is `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`; it was not committed when this issue was filed, so this body is written to stand alone.</sub>

TITLE: Lockout response differs by unlock arm: only the USB arm wipes on PinLocked, and a lockout raised by a secure element at the boot or idle prompt has no wipe trigger at all
LABELS: finding,priority:medium,surface:secure-element,surface:lifecycle,surface:docs,source:frontier-research-2026-10
---
## Summary

There are three places a PIN is entered: the boot prompt, the idle re-unlock (PendSV) and the USB unlock command. Only the USB arm runs the dual-SE wipe when the result is `PinLocked`. The other two show a status and stop. The difference is deliberate and commented (it came from #715), and for ten wrong PINs the next boot does wipe, because page 124 at its maximum is a durable trigger. Two gaps remain, and three documents describe a behaviour the code does not have.

## Evidence

Line numbers at master `0feea78a` (2026-10-11). The research ran at `c75b0d9c`, an ancestor of master; the cited files were diffed against master before filing.

- Boot arm, `secure/src/main.rs:4209-4218`: `ui::show_status("PIN locked", "power cycle")`, a log line "PIN locked out (no wipe performed on this path)", then `break`. The tenth wrong PIN shows "Wrong PIN" / "try again" (`:4219-4222`).
- PendSV arm, `secure/src/main.rs:4656-4667`: the same.
- USB arm, `secure/src/nsc/cmd_request_unlock.rs:146-151`, `:159-164`, `:190-211`: wipes on the tenth wrong PIN and on `PinLocked`.
- Next-boot wipe when page 124 is at the maximum: `secure/src/main.rs:1945-1963`.

## The two gaps

1. After ten wrong PINs at the boot or idle prompt, both seed halves stay on the chips until the next powered boot, and the screen says "try again".
2. A lockout that comes from a secure element while page 124 is below 10 has no boot-time trigger at all. It needs the OPTIGA to accept while the SE050 is blocked, because OPTIGA errors take precedence (`secure/src/dual_se.rs:384-391`).

## Documentation that says otherwise

- `CLAUDE.md:23` (invariant 2): "`AuthMethodBlocked` still maps to `PinLocked` and the wipe path."
- `secure/src/nsc/mod.rs:1667-1668`: "maps `AuthMethodBlocked` to the wipe path".
- `secure/src/nsc/mod.rs:1382-1384`: "Caller is responsible for running `trigger_lockout_wipe` on that signal." Two of the three callers do not.
- `secure/src/se050/mod.rs:2857-2862`: accurate for the gateway, but its cross-reference to `cmd_request_unlock.rs:117-122` is stale (the arm is at `:159-164`).

## Severity and evidence level

- Severity: **low to medium** (one review lens), **medium** (the other).
- Evidence: code read; re-checked independently (confirmed).

## Fix directions

- [ ] Decide the intended behaviour once, for all three arms, and record it in invariant 2.
- [ ] If the answer is "always wipe": move `trigger_lockout_wipe` into `nsc/mod.rs`, port the post-bump count check to the boot and PendSV arms, and on a secure-element lockout arm the page-125 flag that the boot check already honours.
- [ ] Do this together with #104. A forged bare status word from the SE050 already forces a wipe on the USB arm. Widening the wipe to the other arms widens that too unless the verdict is authenticated first.
- [ ] Correct the four comments and the invariant text.

## Related

#715, #104, #120, #168.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item pin-05, defect row A15 and E10). Re-checked before filing by an independent read at `c75b0d9c` (A15 confirmed; E10 partly: the comment that matches the claim is `nsc/mod.rs:1667-1668`, and nothing says "unconditionally"). The full report is `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`; it was not committed when this issue was filed, so this body is written to stand alone.</sub>

COMMENT_ON: 715
---
A small diagnostics addition from the 2026-10 security research (item M04, part E). It would make the still-open question here ("what consumed ten attempts") answerable the next time it happens. It is diagnostics only: nothing in it charges an attempt, escalates, or wipes.

**What the log cannot tell apart today** (lines at master `c2fab970`)

- `secure/src/pin_attempt_log.rs:80`: one reason code, `NoVerdict = 0x06`, covers every burn where the PIN was never judged. Its own comment at `secure/src/pin_attempt_log.rs:77` lists three different causes: transport, session, or a failed fault-injection gate.
- `secure/src/nsc/mod.rs:1638`: the fault-injection inconsistency arm (the two reads of the unlock result disagree) records `NoVerdict`.
- `secure/src/nsc/mod.rs:1650`: every secure-element error that is not a PIN verdict or a lockout also records `NoVerdict`.
- So a run of `NoVerdict` entries cannot separate "the I2C bus dropped", "the secure channel died", "a secure element returned an unexpected status" and "a glitch gate tripped". The cap added in 255a9554 (`secure/src/main.rs:4535`) bounds the damage for all of them alike, which is right, but it does not say which one fired.
- The secure-element drivers keep no counters of their own retries. The SE050 link allows up to 500 waiting-time extensions per exchange (`secure/src/se050/t1oi2c.rs:47`) and nothing records how many were used or how often a session was re-established.

**Proposed**

- [ ] Split `NoVerdict` into at least three codes: transport or session failure, unexpected secure-element status, and fault-injection gate. Keep `0x06` readable by the existing host tool, or version the record.
- [ ] Keep per-session counters in secure RAM (no flash) for SE050 waiting-time-extension and read-retry exhaustion and for OPTIGA and SE050 session re-initialisation, and return them through the existing attempt-log command.
- [ ] Keep it diagnostics only. A source test should pin that no new code path calls `pin_attempts_bump`. The research considered and rejected charging attempts or wiping on these events: before unlock the gate already precharges, and after unlock the next correct PIN resets the counter, so a charge adds nothing, and a wipe on such events would let whoever can cause them destroy the wallet.

**Depends on**

- #719: whether these reason codes and counters may be read without the PIN on a locked device. More detail in the log is exactly what that decision is about.
- The codes are a wire format decoded by a host tool, so the tool changes with them.

Firmware only. Not checked: the flash cost, and whether the secure-element error types carry enough information at the `gated_unlock` level to make the split without changing the driver interfaces.

Related: #692, #109, #719, #851.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M04, section 3). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

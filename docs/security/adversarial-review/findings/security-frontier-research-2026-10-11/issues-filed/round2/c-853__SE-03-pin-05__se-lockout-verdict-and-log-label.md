COMMENT_ON: 853
---
**Input to the decision this issue asks for, from the 2026-10-11 security frontier research (item SE-03). Line numbers are at master `c2fab970`.**

The research first proposed confirming a bare SE050 status word with an authenticated probe before wiping. Its own review refuted that proposal. The reason also closes one of the two routes this issue offers: "always wipe" on every arm, done "together with #104" so that the verdict is authenticated first. For the SE050 there is no way to authenticate that verdict today.

**Why an SE050 lockout verdict cannot be authenticated**

- A 2-byte response is accepted with no response MAC at `secure/src/se050/scp03.rs:615`, and the host counter still advances at `secure/src/se050/scp03.rs:633`. This follows the GlobalPlatform SCP03 rule the file quotes: an error status word carries no MAC.
- `0x6986` on session creation becomes `AuthMethodBlocked` (`secure/src/se050/apdu.rs:768`), then `PinLocked` (`secure/src/se050/mod.rs:2868`), and the USB arm wipes (`secure/src/nsc/cmd_request_unlock.rs:163`).
- An interposer on the SE050 bus can pass the command to the chip and replace only the response. The chip and the host have both advanced their counters, so the session stays in step and every later authenticated command succeeds. A chip that really is locked produces the same transcript. So a follow-up probe cannot tell the forged case from the real one, and neither can the fix proposed in #104 (repeat after `reinit()` and a fresh session): an interposer that stays on the bus forges the second answer as well. This is reasoned from the protocol and the code. It was not run.
- The only authenticated source would be a successful, MAC-protected read of the UserID attempt attribute. The production policy denies that read (invariant 2).
- The same limit probably applies to the fix in #105 ("only authenticated `0x63Cx` is a PIN failure"). The wrong-PIN arm at `secure/src/se050/apdu.rs:824` accepts `0x6985`, which is an error status and therefore arrives bare. Whether this part ever answers a wrong UserID with a MAC-protected `0x63Cx` was not checked against the applet documentation or on silicon. If it does not, that fix would make every wrong PIN inconclusive.

**What survives, as a proposal for the decision here**

- [ ] Make flash page 124 the only authority for the PIN-lockout wipe. The other wipes are not affected: the boot-time rollback wipe when the OPTIGA counter is ahead of page 124, the tamper wipe and the duress wipe stay as they are. `gated_unlock` returns the same `PinLocked` for "page 124 is at its maximum" (`secure/src/nsc/mod.rs:1475`) and for a lockout reported by a secure element. Split the two (a separate error variant or a flag), so that the USB arm wipes only on the first.
- [ ] For a lockout reported by the SE050 (`AuthMethodBlocked`) while page 124 is below its maximum, give the USB arm the same non-wiping state the boot and idle arms already show (`secure/src/main.rs:4215`, `secure/src/main.rs:4664`). This is the opposite of the "always wipe" option. It removes the forged-status wipe instead of extending it to two more arms.
- [ ] If a wipe from that state is wanted, offer it only behind an explicit confirmation on the trusted display. That is an owner decision.
- [ ] Give the 2-byte arm of `unwrap_response` a typed "not authenticated" result, so that no caller can treat a bare status as a verdict by accident. #104 proposes rejecting three specific values only.
- [ ] Keep the page-124 charge on these results. A refund triggered by a frame an attacker can forge would be a free PIN-test oracle.
- [ ] Update the invariant 2 text and the comment at `secure/src/se050/apdu.rs:89`, which lists these status results as authoritative because the chip answered.

**Open design question, not a defect.** The cap on consecutive results with no PIN verdict (`secure/src/main.rs:4535`, added for the idle loop under #715) has no equivalent on the boot and USB arms. On those arms each attempt costs a human PIN entry, so a fault cannot burn the budget unattended. If a durable cap is wanted, it belongs in the page-124 format, not in a second counter that can drift from it.

**Limits**

- Ten induced faults still exhaust page 124, and that still ends in a wipe. This removes the one-frame wipe, not the ten-frame one.
- An SE050 that really is locked while page 124 is below its maximum (gap 2 in this issue's body) then never wipes by itself. The device stays locked with both seed halves in place until the user confirms a wipe, if that option is built, or restores on another unit. That is the price of not trusting a verdict that cannot be authenticated.
- In the dual-chip shape the SE050 is called only when the OPTIGA accepted or answered "wrong PIN" (`secure/src/dual_se.rs:373`), and an OPTIGA error takes precedence. So the forged wipe needs the correct PIN to have been entered, on the USB arm.
- The OPTIGA case is different, and the argument above does not cover it. On the ship profile its lockout verdict is the E120 limit compare at `secure/src/optiga/mod.rs:2431`, and that counter is read through the tunnel after `secure/src/optiga/mod.rs:2390`, so the value is authenticated. Its weakness is replay of a recorded session, which is #117. Whether an OPTIGA-reported lockout should wipe is part of the decision here, but not for the reason given for the SE050.
- The global status mapping that #120 cites no longer exists: the comment at `secure/src/optiga/apdu.rs:310` says those arms were dead code on real silicon. #120 should be re-read against current code before anyone acts on it.
- An authenticated lockout verdict would need a different SE050 UserID policy, re-provisioning, and a silicon decision.
- No forged-status run exists on silicon. One needs an active interposer on the SE050 bus (I2C4, PB6 and PB7 on pq1), which means a hand-modified unit.

---

**One item from the same research finding that this issue's body does not carry (report item pin-05). Line numbers are at master `c2fab970`.**

The attempt log cannot tell a lockout raised by a secure element from the "counter already at maximum" short-circuit. `secure/src/nsc/mod.rs:1649` records every `PinLocked` that comes back from the secure-element call as `AlreadyAtMax`. That reason is documented as "Nothing was burned and nothing was wiped on this path" (`secure/src/pin_attempt_log.rs:72`). For a lockout that a secure element raised, the page-124 attempt had already been charged by the time the call was made, so the log entry says the opposite of what happened. The same line also labels the wipe-on-duress return (`secure/src/nsc/mod.rs:1568`). A dedicated reason, `DuressWipe = 0x08`, is defined and pinned by a test (`secure/src/pin_attempt_log.rs:84`), but a search of `secure/src`, `nonsecure/src` and `tools` finds nothing that records it. Recording it would also reveal a duress wipe to anyone who can read the log on a locked device (#719), so this is a decide-and-document item: either record it or remove the code and say why.

This matters for gap 2 above. A lockout raised by a secure element while page 124 is below ten is the case with no wipe trigger, and it is the case the #715 diagnostic log would be used to recognise.

- [ ] Give a lockout raised by a secure element its own reason code. The codes are a wire format read by a host tool, so add a value, do not renumber.
- [ ] When the wipe helper is shared, have the hand-copied wipe sequence in the hardware end-to-end test (`secure/src/main.rs:3573`) call it.

Two limits the research recorded for the "always wipe" direction, for whoever implements it: how long the wipe takes inside the idle re-unlock handler has not been measured against the watchdog, and on the open bench board the wipe screens cannot be evidence because it has no display panel, so a test has to read secure-element state and pages 124 and 125.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item SE-03, section 7; status "redesign needed", so only the surviving narrower form is given here). Report priority P1 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

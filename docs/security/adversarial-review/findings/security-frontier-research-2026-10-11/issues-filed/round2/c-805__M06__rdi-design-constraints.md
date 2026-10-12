COMMENT_ON: 805
---
The 2026-10 security research looked at this question again (its item M06) and had the proposal reviewed against the code. It did not settle whether to build the random delay interrupt (RDI). It did produce design constraints and one unanswered objection that are not in this thread yet. Recording them so they are in hand if the owner moves this from research to build. Lines are at master `c2fab970`.

**1. The recorded "do not build" verdict has not been answered here**

`docs/archive/work-todo-retired-2026-07-19.md:1940` reads "RE-SCOPED 2026-05-28: NOT MOTIVATED for the non-sign secret paths. Do NOT build the subsystem." This issue does not cite it. Its three arguments fare differently:

- TrustZone and USB (`docs/archive/work-todo-retired-2026-07-19.md:1944`: "Trezor runs USB + crypto + RDI in one secure context"). This no longer matches Trezor's tree. In a local Trezor checkout (`6ab39e95`) `random_delays.c` is built for secure mode, `usb.c` for kernel mode, and the secure monitor starts the RDI on the model that has one. So Trezor does run a secure-world RDI across a non-secure USB stack. That removes the argument; it does not show that our USB and secure-element timing tolerate it.
- Side channels: the archived argument still stands. The three non-sign secret paths run once per unlock with no attacker-chosen input, so there are no repeated traces for an RDI to misalign.
- Fault injection: "marginal benefit" mostly stands. An RDI helps against a glitch timed blind from an early anchor. It does nothing against an attacker who re-arms on a display, I2C or power edge within about a millisecond of the target, and the PIN verdict follows an I2C response, so it is in that class.

If this is built, an explicit owner reversal of the 2026-05-28 verdict should be recorded here first.

**2. Constraints the design has to meet (from the carve-out in `CLAUDE.md:364`)**

- Host: the existing 1 kHz secure SysTick, which is already the highest priority (`secure/src/main.rs:889`). Not TIM2 or TIM3: those drive the consumption mask.
- Generator: used only by the interrupt handler, nothing else (condition c). A single consumer in a single context needs no lock, so there is no "return a constant on contention" arm of the kind Trezor has.
- The handler must never touch the driver of the true random number generator (TRNG), the HASH or SAES peripherals, or secure-element I2C. Seed material is drawn in thread mode and handed over through a mailbox.
- Condition (a) asks for a bounded reseed policy. Reseeding only at gateway calls and button presses has no bound while the device idles or during a multi-second signature. A tick-count bound is needed as well.
- Condition (b) asks for zeroize on lock. An always-on RDI then needs a defined state after lock: reseed at once, or enter the refuse state. Neither is specified anywhere.
- Reseed failure must be loud and counted, never a constant and never a halt (#835).
- No masking windows. A flag that switches the delay off is itself a fault target.
- It must be compiled out wherever `wait_random` is (the `e2e-test` case), with a fence so that state cannot ship.
- The mean has to float per session as well as per tick. A design that only adds an independent random delay per tick averages out over a multi-second signature.

**3. What has to be measured before it ships**

- [ ] Signing time on pq1 with the RDI on (`make test-key-speed BOARD=pq1`).
- [ ] USB HID signing soak and SE050 and OPTIGA stress with the RDI on. This is the whole rebuttal of the 2026-05-28 timing concern, so it cannot be skipped.
- [ ] Panel tearing margin re-measured (the bound from #780, which is closed).
- [ ] Flash and CPU cost of the handler and generator. `secure/Cargo.toml` names no ChaCha crate today, so a generator is new code and its flash cost is unmeasured.
- [ ] A before and after number from the glitch bench (#301). Without it the benefit is recorded as unmeasured.

**4. Order**

The delay source itself comes first. Master still has the reuse arm (`secure/src/fi.rs:58`), and the fix lives on `perf/flash-opt-level-z`, which is now 24 commits ahead of and 55 behind master. That is tracked in #865 (item 3), #834 and #835. Jitter immediately before the first gate of each gateway entry is tracked in #861. The RDI is third, and the research reviewer rated it P2 at most, arguably P3 until the bench can measure a difference.

**5. Label**

This issue carries `surface:clear-signing`. `surface:sca-fi` fits.

Needs: firmware only for the build; the measurements need the open bench board, a unit with a panel for the tearing check, and the glitch rig for the benefit number.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M06, section 3). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

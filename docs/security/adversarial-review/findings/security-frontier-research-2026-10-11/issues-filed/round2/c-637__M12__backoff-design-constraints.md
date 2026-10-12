COMMENT_ON: 637
---
**Design constraints for the "implement" branch of this issue, from the 2026-10-11 security frontier research (report item M12). Line numbers are at master `c2fab970`.**

Still true at master: `gated_unlock` (`secure/src/nsc/mod.rs:1415`) has no delay that grows with the failure count. The only delays are the microsecond jitter calls. The proposal text is at `docs/security/HARDENING.md:280` (the body cites line 170, which has moved), and `docs/security/threat-model.md:431` still lists "button entry without echo" and an "eventual progressive delay" as mitigations.

**What the delay would and would not buy.** The research review lowered this to its lowest priority. Attempts are already paced by the two-button dialog (eight positions, a 500 ms long press each, `secure/src/hw/buttons.rs:183`) and capped at ten, and the PIN compare is inside the secure elements. Whoever can reset page 124 also resets the delay, because the delay is computed from that page. The value is: the documents become true, parity with Trezor, and a slower walk to the wipe when attempts are being consumed by a fault (#715, #119).

**If it is implemented, the review found these constraints.**

- [ ] **First fix #852.** The PIN dialog does not hold the watchdog wait guard today, so a wait added on top of it would be reset by the watchdog. The back-off wait needs the guard as well. The guard's contract is "waiting for a physical button" (`secure/src/timeout.rs:194`), so using it for a countdown is a deliberate widening that its tests must follow.
- [ ] **Schedule:** `min(2^n - 1, 60)` seconds from the page-124 count `n`. Trezor's uncapped schedule would wait 511 s before attempt ten. A 60 s cap stays under the 120 s idle timeout (`secure/src/timeout.rs:27`).
- [ ] **Placement:** inside `gated_unlock`, after the double read of the counter (`secure/src/nsc/mod.rs:1450`, `secure/src/nsc/mod.rs:1452`) and before the pre-commit bump (`secure/src/nsc/mod.rs:1494`), so all three entry points get it and a skipped delay never skips the bump. The alternative is a helper called before `enter_pin` at the three sites, which avoids holding the typed PIN on the stack for up to 60 s. Pick one.
- [ ] **It can only count powered time.** The device has no battery and no clock while unpowered. The delay is recomputed from the stored count on every call, so a power cycle cannot shorten or clear it. It also cannot credit time spent switched off: after a reboot the full wait runs again before the next attempt.
- [ ] **Tick source:** the secure SysTick, which starts early on hardware (`secure/src/main.rs:1647`). On QEMU it starts late (`secure/src/main.rs:4261`), so the wait must be compiled for `stm32u585` only or it hangs there. Compile it out of `e2e-test` and bench images.
- [ ] **Cancel needs a new `UnlockError` variant** (`secure/src/secure_element.rs:20`). `PinLocked` would start the lockout wipe on the USB entry point, and `InternalError` counts toward the three-strikes "SE fault" guard in the idle re-unlock loop (`secure/src/main.rs:4535`).
- [ ] **A fixed countdown screen, separate from the PIN row.** Varying text was removed from the PIN screen on purpose (`secure/src/main.rs:4610`). This needs an owner decision on wording.
- [ ] **The schedule function goes in a workspace crate** with a host test, because modules under `secure/src/nsc` and `secure/src/hw` are not compiled into host tests.
- [ ] Do not refresh the inactivity timer during the wait. The submit press already did, and 60 s is under the 120 s window.

**If it is declined,** the deliverable is the one this issue already names, plus `docs/security/threat-model.md:431`: remove "without echo" (the dialog shows the active digit) and move the delay to an explicit residual.

Not checked: nothing was built or run. A countdown on a real unit needs a device with a panel and a non-test image (#700). The research review of this item had one reviewer, not two.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M12, section 8). Report priority P3 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and Trezor's public source (`storage/storage.c` in https://github.com/trezor/trezor-firmware, read in a local clone); nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

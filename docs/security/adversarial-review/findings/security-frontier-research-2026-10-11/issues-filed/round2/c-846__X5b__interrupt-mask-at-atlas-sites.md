COMMENT_ON: 846
---
**On the open box "Decide whether veneers also raise `BASEPRI_S` to 0x80": a follow-up item in the same research (X5b) looked at that mask on its own. Its conclusion is that a mask taken only at veneer entry misses one dialog, and that the test for it needs a negative control. Details below, re-read at master `c2fab970`.**

Background for a reader who has not seen the report. The try-enter in this issue refuses a second gateway call. It does not stop a non-secure (NS) exception handler from running while the secure thread is parked in a dialog. Under the pixel UI (`ui-px`) that matters for a second reason: the glyph atlas lives in NS flash, and the secure world hashes it before a dialog and again after it. Raising the secure base-priority mask (`BASEPRI_S`) for that window is the cheap way to keep NS handlers from running inside it. Nobody has shown that an NS handler can change what the atlas window reads between the two hashes. This is hardening, not a demonstrated attack.

**What the code does today**

- No `BASEPRI` write exists in `secure/src`. The one interrupt-masked section in gateway state code is the install in `mark_unlocked`, `secure/src/nsc/state.rs:542`.
- The hash-paint-hash bracket: `secure/src/nsc/mod.rs:1106` (`verify_atlas` before the dialog) and `secure/src/nsc/mod.rs:1125` (`atlas_root_proof` after it). The same pair in `px_confirm_plain`: `secure/src/nsc/mod.rs:1147` and `secure/src/nsc/mod.rs:1167`.
- Paint paths that take an atlas outside those two functions: `secure/src/ui/px/screens.rs:111`, `secure/src/ui/px/screens.rs:157`, `secure/src/ui/px/screens.rs:183`, `secure/src/ui/px/screens.rs:208`, `secure/src/ui/px/lcd.rs:847`, `secure/src/ui/px/lcd.rs:964`, `secure/src/ui/px/lcd.rs:1011`, `secure/src/ui/px/lcd.rs:1109`.
- **One dialog runs outside every veneer.** The idle re-unlock runs PIN entry from the secure PendSV handler: `secure/src/main.rs:4559` (`fn PendSV()`), `secure/src/main.rs:4622` (`enter_pin()`). Under `ui-px` the PIN row is painted through the atlas: `secure/src/ui/pin_entry.rs:184`. A guard placed only in the veneers never covers this path.
- Secure PendSV is programmed to the lowest priority and secure SysTick to the highest: `secure/src/main.rs:888`, `secure/src/main.rs:889`. If the architecture works as the research assumes (see the first box below), an NS SysTick outranks the secure PendSV handler that is running the PIN dialog.
- The comment at `secure/src/sau.rs:716` is already on this issue's list.

**Suggested additions to the checklist**

- [ ] **Precondition, not yet done by anyone:** confirm in the ARMv8-M Architecture Reference Manual (ARM DDI 0553) that with `AIRCR.PRIS = 1` every NS exception priority lands at 0x80 or lower urgency as seen by the secure side, and that `BASEPRI_S = 0x80` masks all of them. The research and its reviewer both worked from memory and from one QEMU patch note. Do not rewrite the `sau.rs` comment to claim this until it is checked.
- [ ] Hold the mask where the atlas is used: a scope guard from before `verify_atlas` until after `atlas_root_proof`, and around the paint paths listed above. Take it in the PendSV re-unlock path too. A veneer-level mask is a fine addition, since NS polls USB and has no interrupt of its own to starve, but it is not a replacement.
- [ ] The guard restores the saved value on every exit path. Add an assertion that `BASEPRI_S` is 0 when a veneer returns: if it is left at 0x80, every NS exception stays masked.
- [ ] Add a source test that no secure interrupt is ever given a priority of 0x80 or lower urgency, because the mask would silence it. My search of `secure/src` for `ITNS`, `NVIC_IPR` and `set_priority` found no priority write today, so the illegal-access and tamper interrupts appear to sit at the reset priority. I did not open their enable code to confirm.
- [ ] Add a source test that every caller of `verify_atlas` and `atlas_verified` holds the guard. Put it in a file the host build compiles: `secure/src/ui` and `secure/src/nsc` are compiled out under `cfg(test)`.
- [ ] Silicon test with a negative control. As first proposed it would have passed without testing anything, for three reasons: `e2e-test` short-circuits the pixel confirm (`secure/src/ui/px/confirm_px.rs:91`), so the window is near zero; one pended NS tick always fires the moment the mask drops, so a check made from the NS side is off by one; and there was no build that shows the counter advancing without the guard. What it needs: a fixture that holds the bracket open for a known time with no buttons and no panel, a secure-side snapshot of an NS-RAM counter at bracket entry and exit, and a second build with the guard compiled out in which the counter does advance. Runs on the open bench board (debug port, no display needed).

**Limits**

- The mask does nothing against a write made through direct memory access (DMA) or against a fault on the flash read. It must not be described as closing an atlas swap. The research has a separate item for painting only from bytes that went through the hasher and for locking the DMA channel attribution (item X5a).
- Deferring secure PendSV is not a new cost for guarded handlers: SysTick only pends it when no handler is busy (`secure/src/main.rs:4413`). It matters only for the handlers that still have no guard (#152).
- Nothing here was run on silicon. The research rated this P2, cost M, as a sub-item of this issue.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item X5b, section 12). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

COMMENT_ON: 860
---
**Review notes on the "bound host-raised prompts" fix direction, from the 2026-10-11 security frontier research (report item M12). Line numbers are at master `c2fab970`.**

The fix list names two options: one prompt per physical button press, or a minimum interval. The research proposed a version of each and its own review dropped both. The reasons are recorded here so neither is built without answering them. The research ended with no design it would recommend for this item and rated it nuisance class.

**The minimum interval** (a cooldown held in secure RAM: after a host-raised prompt is cancelled or ignored, refuse the next one for 1, 2, 4 and up to 60 seconds).

- It does not bound the thing it names. An ignored prompt stays on the screen until the idle timeout (120 s, `secure/src/timeout.rs:27`) or until the watchdog reset described in #852. With a 60 s cooldown the prompt is still up for about two thirds of the time, and the first prompt, at a moment the host chooses, is untouched.
- Refusing silently changes the meaning of a status code. The proposal returned the existing "user rejected" status for a prompt that was never painted. The companion would report that the user cancelled when the user did nothing, and a user who dismissed a prompt by mistake would be refused for up to a minute with nothing on the screen.
- The cooldown state would be lost on a power cycle.

**The button press** (a passive "press to unlock" screen before the keypad).

- It adds a press to every unlock, and the user who is being conditioned presses it and types the PIN anyway. The PIN is typed on the trusted display, so the host gains nothing from the prompt itself, and no attempt is consumed without a physical submit.

**Two facts for whoever picks this up.**

- The host can put the device in the locked state whenever it likes: `nonsecure/src/usb/commands.rs:287` routes a host lock command with no gate, and `nonsecure/src/usb/commands.rs:286` routes unlock. Lock followed by unlock re-raises the prompt at will, which is how the fix in #148 (unlocked case only) is side-stepped.
- By code search: the callers of the PIN dialog in `secure/src` (test modules left out) are the setup wizard and its duress step, a bench-only display test, the boot prompt, the idle re-unlock, and the USB unlock handler (`secure/src/nsc/cmd_request_unlock.rs:54`). So among gateway commands only unlock raises it; the firmware-update and forced-blind handlers do not call it.

Not checked: nothing was run.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M12, section 8). Report priority P3 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

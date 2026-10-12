COMMENT_ON: 831
---
A constraint on suggested fix 2 ("retry on the next tick"), from the review of the 2026-10 security research (item M15). Lines are at master `c2fab970`.

The reseed runs inside the SysTick handler, which is the highest-priority exception. `secure/src/hw/consumption_mask.rs:200` calls `crate::rng::fill` there. The follow-up comment above measured what one successful reseed costs in that handler: about 257 microseconds on average, up to about 514, out of a 1 millisecond tick. #802 measured what happens when a hardened draw from the true random number generator (TRNG) runs on every tick: about 356 microseconds per tick, render time up 55 percent.

So an uncapped retry on every tick is fine for the case this issue describes (a lost acquire returns early and is cheap), but under a persistent TRNG error it would repeat a failing fill every millisecond for as long as the error lasts. Nobody has measured what a failing fill costs in the handler.

- [ ] Count the skip, as proposed.
- [ ] Retry sooner than a full window, but bounded: for example at most N attempts at a short interval, then back to the normal period. Keep the lost-acquire path cheap.
- [ ] Measure the skip rate under a real signing workload before choosing N. The bench that produced the numbers above never signs.

One note for any later redesign of the mask, recorded here so it is not lost:

- The timer period is fixed (`secure/src/hw/consumption_mask.rs:382`) and only the compare value is randomised, so in pulse-width modulation (PWM) mode 1 the rising edge sits on a fixed 10 kHz grid and only the falling edge moves. A design that wants to resist filtering has to randomise the period as well as the duty.

Firmware only. The skip-rate measurement needs a unit that can sign (any bench unit with a debug or USB readout of the counter).

**A second point about the same generator, which no issue carries.** The contract now states the conditions under which the mask's duty may come from a seeded generator at all (`CLAUDE.md:364`, the carve-out added on 2026-10-08). Condition (b) asks for an effective internal state of at least 246 bits, treated as a secret and zeroized on lock, tamper and brown-out. The generator here is a 32-bit xorshift (`secure/src/hw/consumption_mask.rs:138`, `static mut PRNG_STATE: u32`), and a search of `secure/src` finds no reference to that state outside the driver, so nothing zeroizes it on lock. This thread and #805 discuss condition (d) only.

- [ ] Either bring the generator inside condition (b) (wider state, zeroize with the other secrets), or record why the mask is exempt from it.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M15, section 4). Report priority P3 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

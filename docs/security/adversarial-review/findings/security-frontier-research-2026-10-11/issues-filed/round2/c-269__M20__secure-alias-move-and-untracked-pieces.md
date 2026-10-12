COMMENT_ON: 269
---
**Implementation notes for securing the clock, power and system-config blocks, from the 2026-10-11 security frontier research (item M20). One of them will break the boot if it is missed. Lines re-read at master `c2fab970`.**

For the register address see the comment on #80 (`RCC_SECCFGR` is at offset `0x110`, not `0x10`), which also covers the flash wait-state register that stays writable from the non-secure (NS) world.

**1. The secure world itself still uses the NS alias of RCC. Move it first.** Once `RCC_SECCFGR` marks the clock tree secure, an access through the NS alias reads as zero and writes are ignored.

- `secure/src/hw/rcc.rs:10`: `const RCC: u32 = 0x4602_0C00;` (NS alias).
- `secure/src/reset_cause.rs:19`: the same NS alias, used to read the reset flags and to clear them. If the reset-flag bit is secured as well, this access has to move too.
- Two host tests pin that literal and will fail when it moves: `secure/src/hw_platform_under_test/pure_tests.rs:286` and `secure/src/main_sau_pure_tests.rs:407`. They need updating in the same change.
- The research first argued that the clock bring-up itself would fail. That is wrong: the clock is configured at `secure/src/main.rs:1196`, before the attribution code runs at `secure/src/main.rs:1354`. The move is needed for every access after that point.

- [ ] Move `rcc.rs` and `reset_cause.rs` to the secure alias (`0x5602_0C00`) and update the two tests, before or with the `SECCFGR` write.

**2. The third box of this issue points at old lines.** The NS read of RCC is now at `nonsecure/src/main.rs:190`, behind a debugger-attached check (`nonsecure/src/main.rs:188`). It is not compiled out. After this issue lands it becomes an illegal access, and with `tzic-wipe` in the ship set an illegal access leads to a wipe. It has to be removed at compile time, not left behind a runtime check.

**3. What the open gap allows today, as a concrete case.** The 120 s idle lock counts secure SysTick ticks (`secure/src/timeout.rs:3`), and SysTick runs from the processor clock (`secure/src/main.rs:896`). Non-secure code that slows the core clock therefore stretches the idle window in wall-clock time. It still cannot sign without the physical button press, so the research rates this low to medium: it extends how long secrets stay in RAM for a later physical attacker. It also means two statements in `CLAUDE.md` are not accurate as written: `CLAUDE.md:287` calls the timer "S-only TIM-driven" (it is SysTick on the core clock), and `CLAUDE.md:372` says NS does not control the inactivity timer (true for resets of the timer, not for its rate until this issue lands).

- [ ] Correct the two `CLAUDE.md` lines, or note next to them that the rate claim depends on this issue.

**4. Pieces no issue names.**

- [ ] `SCB_SCR.SLEEPDEEPS` and the low-power bits of `PWR_SECCFGR`, so that NS cannot put the device into Stop mode. The research notes a possible interaction with the planned `IWDG_STOP` option bit in #248: if that bit freezes the watchdog in Stop mode, an NS-entered Stop would have no watchdog bound. I did not check the bit's polarity in the reference manual; please check it before choosing the value.
- [ ] `RTC_SECCFGR`. The tamper block is covered by #81 and #50; the real-time clock's own attribution register is named by neither.
- [ ] Extend `make gtzc-enforcement-hw` with NS-alias probes for RCC, PWR and SYSCFG, so the new attribution has a silicon receipt like the existing seven peripherals.
- [ ] Audit the NS image for any other access to these blocks before enabling the attribution in a `tzic-wipe` build.

**Limits.** Trezor secures RCC, PWR and SYSCFG on the same chip family, so this part is parity. `SLEEPDEEPS` and the tamper attribution go beyond what Trezor does. None of this stops a physical attacker, and nothing detects injection on the internal oscillator. Whether NS writes to PWR are really accepted at reset on this silicon was not measured; the comment at the top of `rcc.rs` claims they are ignored, and #80 already asks for that check.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M20, section 11). Report priority P0 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and the reference manual as quoted in the research; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

COMMENT_ON: 861
---
Three additions from the follow-up pass of the same research, on two of the items above.

### First checkbox: the per-entry random delay must not be able to block a lock

One constraint for the first checkbox (a random delay before the first gate of each gateway entry), from the review of the same research item (M06). Lines are at master `c2fab970`.

At master a delay cannot fail: `secure/src/fi.rs:58` falls back to the last good byte. On the unmerged branch that fixes the delay source (`perf/flash-opt-level-z`, read at `73287916`; landing it is #865 item 3), a delay that cannot get a fresh length sets a poison flag, and its doc comment says every operation boundary then refuses: the RNG fill returns an error, the gateway returns a status, and no signature is released. Once that lands, a delay added at the entry of `nsc_lock` (`secure/src/nsc/mod.rs:2007`), `nsc_is_unlocked` (`secure/src/nsc/mod.rs:1997`) or `nsc_fw_abort` (`secure/src/nsc/mod.rs:2322`) must not be able to make locking, zeroizing or aborting refusable. A broken random number generator must still allow the device to be locked.

- [ ] When adding the per-entry delay, state for each entry whether a failed delay may refuse the call. Lock, status and abort entries must proceed.
- [ ] Take the list of entries for the source-grep gate from the `cmse-nonsecure-entry` functions in `secure/src/nsc/mod.rs` that are not gated on `prodtest` or `e2e-test`. There is no shared entry point to hook; each one calls its own handler.

Not checked: the branch behaviour beyond reading the doc comment of the poison flag in its copy of the delay module. Which entries consult the flag was not traced.

### Fourth checkbox: the internal tampers with nothing behind them

**Internal tamper 3 (LSE monitor).** The item says it needs a running 32 kHz crystal and that firmware uses none. The second half is right. On the first half: the V10 schematic does show a 32.768 kHz crystal on the MCU (`X102`, on `OSC32_IN` / `OSC32_OUT`), so if it is fitted the monitor could be made real in firmware. Whether it is fitted, and whether to use it, is in {{H1}}. Until that is decided, the enable at `secure/src/hw/tamp.rs:290` is inert and can be removed.

**Internal tampers 7, 12 and 13 (ADC4 analog watchdogs).** If the "small secure ADC4 driver on the internal channels" option is taken, three things belong in its design:

- [ ] ADC4 has to be made a secure peripheral first. It is bit 8 (`ADC4SEC`) of `GTZC2_TZSC_SECCFGR1` (RM0456 Rev 7, section 5.9.2), in the second TrustZone controller block, which this firmware does not configure (`secure/src/sau.rs:672-673`). Without that, non-secure code can disarm the monitor or trip it on purpose. This is the same block as the tamper attribution in #81.
- [ ] The useful channels need no pin: the internal reference (which gives the supply voltage), the core voltage and the temperature sensor. A window on the reference channel also catches over-voltage, which the brown-out and voltage detectors do not.
- [ ] It sees slow excursions and long glitches only, not nanosecond pulses. Start log-only: a false trip in confirmed mode erases the hardware key that roots the SE050 credentials (#712).

This would replace the resistor divider on PA6 that an earlier draft of the research proposed for supply sensing. That divider needs a board change. This does not.

<sub>**Provenance.** Security frontier research, 2026-10-11, follow-up pass of 2026-10-12 (items M06, N1 and N2). Code lines re-read at master `c2fab970`; the register bit was read in RM0456 Rev 7. The unmerged delay-source branch was read at `73287916`. Nothing was run on silicon.</sub>

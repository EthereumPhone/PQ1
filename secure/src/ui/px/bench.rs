//! Isolated interactive pixel-UI bench (`ui-px-bench`, PROD_FORBIDDEN).
//!
//! WHY THIS EXISTS. The interactive presenter — `Anim` stepping, the springs,
//! `present_frame_ex` and `blit_strip` — has no automated coverage (#779): every
//! `make e2e-px` transcript takes the `e2e-test` auto-confirm fast path, and the
//! `ui-px-frametime` overlay only renders inside the sign-dialog frame loop. So
//! the only way to see or measure the real presenter was to reach a sign dialog
//! on a panel, which needs a provisioned wallet and an unlocked session — and
//! that route is blocked by #778 plus the 120 s idle lock plus the PendSV
//! re-unlock loop. The published frame-time baseline was, in practice,
//! unreproducible.
//!
//! This harness runs BEFORE measured boot, so there is **no wallet, no PIN, no
//! keygen and no idle timer**. Flash it and watch; no operator ceremony.
//!
//! It deliberately shows the two things under investigation:
//!
//!   A. the endless ambient record (`Kind::Hero`), animated against the real
//!      buttons via `Ambient` + `wait_button_ticking`. This was the #783
//!      REPRO — it called `play_screen`, whose only exit for a screen that
//!      never rests is the 3 s `PLAY_CAP_MS`, so it stopped 40% into a 5 s
//!      sweep with the disc stranded. Since the fix it is the
//!      DEMONSTRATION: the motion should continue for as long as you watch
//!      it, and a tap should be picked up promptly. Press either button for B.
//!
//!   B. the same record as the hero of a short transcript through
//!      `lcd::run_flow` — the real interactive dialog, which is where the
//!      `ui-px-frametime` overlay paints `<render>/<blit>/<period>` in ms.
//!      Build with `ui-px-frametime` to read the numbers.
//!
//! Drive B with the physical buttons; it loops back to A on any outcome.

use pqsigner_ui_px::{Icon, ScreenBuilder, Screens, Side};

/// Core clock, for turning DWT cycles into microseconds.
#[cfg(feature = "ui-px-te-probe")]
const CPU_HZ_PER_US: u32 = 160;

/// Right-align `v` into `dst`, blank-padded. Returns nothing; `dst` is wholly
/// overwritten, so a shorter number never leaves a previous run's digits.
#[cfg(feature = "ui-px-te-probe")]
fn num_right(dst: &mut [u8], mut v: u32) {
    for b in dst.iter_mut() {
        *b = b' ';
    }
    let mut i = dst.len();
    loop {
        i -= 1;
        dst[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 || i == 0 {
            break;
        }
    }
}

/// Copy `src` into `dst` from column 0, leaving the rest untouched.
#[cfg(feature = "ui-px-te-probe")]
fn put(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d = *s;
    }
}

/// Measure the panel's tearing-effect line and hold the result on the glass.
///
/// This is the measurement that decides the shape of the #780 fix. A blit is
/// tear-free when it either stays ahead of the scan-out for a whole refresh,
/// or is slow enough to land entirely between two passes of every row — the
/// condition for the latter being `write_time < 2 x refresh_period`. A full
/// repaint is 24.3 ms on the wire, so the answer depends on a number nobody
/// has ever read off this panel: its refresh rate. Near 41 Hz the write and
/// the beam run at the same speed and interleave, which is the one case that
/// tears no matter what we do.
///
/// Output is deliberately STATIC and then parks. The owner reported that the
/// moving frame-time digits were unreadable; a held frame is readable, and a
/// still screen also cannot itself tear.
#[cfg(feature = "ui-px-te-probe")]
pub fn te_probe() -> ! {
    crate::hw::lcd_te::cyccnt_enable();
    crate::hw::lcd_te::init();

    // Up to 64 edges or 1 s, whichever comes first. At any plausible refresh
    // 64 edges is well under a second, so the budget only binds when TE is
    // dead — and then it bounds the whole probe rather than hanging it.
    let m = crate::hw::lcd_te::measure(64, 160_000_000);

    let mut rows = [[b' '; crate::ui::DISPLAY_COLS]; crate::ui::DISPLAY_ROWS];

    if !crate::hw::lcd_te::present() {
        put(&mut rows[0], b"TE: NO PIN");
    } else if m.edges == 0 {
        put(&mut rows[0], b"TE DEAD");
        put(&mut rows[1], b"0 EDGES SEEN");
        put(&mut rows[2], b"PIN READS LOW");
    } else {
        // Row 0: edge count. Proves the pin moves at all, which no one has
        // ever observed on this hardware.
        put(&mut rows[0], b"TE  EDGES");
        num_right(&mut rows[0][11..16], m.edges);

        if m.period_cyc > 0 {
            // Row 1: refresh in tenths of a hertz. This is the number the
            // whole #780 design hangs on: a full repaint is 24.3 ms on the
            // wire, so it is tear-free either well below ~41 Hz (outrunning
            // the scan) or between ~41 and ~81 Hz (trailing it and never
            // being lapped) -- and it tears at the ~41 Hz crossover and above
            // ~81 Hz. The datasheet states 60 Hz exactly once, as the test
            // CONDITION of a TE timing table, and our init shortens the
            // porches (inter_vbp 12->4, inter_vfp 8->4) which pushes the real
            // rate up from whatever the default is.
            let period_us = m.period_cyc / CPU_HZ_PER_US;
            let hz_tenths = if period_us > 0 { 10_000_000 / period_us } else { 0 };
            put(&mut rows[1], b"HZ");
            num_right(&mut rows[1][7..13], hz_tenths / 10);
            rows[1][13] = b'.';
            rows[1][14] = b'0' + (hz_tenths % 10) as u8;

            // Row 2: TE high time. Datasheet Table 5-4-2 guarantees
            // Tvdh >= 1000 us, but our shortened porches imply only ~0.35 ms
            // of blanking at 60 Hz. Both cannot be true. This reading says
            // which, and it sizes the window a "start inside the blank"
            // design would have to fit into.
            put(&mut rows[2], b"HIGH");
            num_right(&mut rows[2][5..12], m.high_cyc / CPU_HZ_PER_US);
            put(&mut rows[2][13..], b"us");

            // Row 3: period spread. Near zero means a stable panel clock we
            // can phase-lock to; wide means TE is not a usable reference and
            // every design above is off the table.
            let spread_us = (m.period_max_cyc.saturating_sub(m.period_min_cyc)) / CPU_HZ_PER_US;
            put(&mut rows[3], b"JIT");
            num_right(&mut rows[3][5..12], spread_us);
            put(&mut rows[3][13..], b"us");
        } else {
            put(&mut rows[1], b"ONE EDGE ONLY");
        }
    }

    let _ = super::lcd::paint_legacy(&rows);
    park();
}

/// Park the CPU. A bench image has nothing to fall back to.
fn park() -> ! {
    loop {
        cortex_m::asm::wfe();
    }
}

/// The hero both halves share: the record the owner photographed frozen.
fn hero() -> pqsigner_ui_px::Screen {
    super::status_map::choice(b"", b"Create new wallet")
}

/// Run the bench forever. Never returns.
pub fn run() -> ! {
    #[cfg(feature = "ui-px-te-probe")]
    te_probe();

    // The atlas is a WYSIWYS input: without a verified one the pixel path
    // refuses rather than painting with an unknown font, and so does this.
    let Ok(atlas) = super::assets::verify_atlas() else {
        park();
    };

    // ---- #805 condition (d): MEASURE the fallback rate, once, at boot ----
    //
    // The claim under test is structural and precise: ONE top-level
    // `fi::wait_random()` triggers N requests to `rng::byte_nonsecret`, of
    // which F lose the non-blocking `DriverGuard` race and replay
    // `FI_DELAY_LAST_GOOD` instead of drawing a fresh TRNG byte. Two
    // independent reviews read the structure as N ~ 28, F ~ 27 — i.e. the
    // delay is one fresh length plus 27 identical replays, which is a far
    // weaker jitter than a "fresh TRNG byte per delay" design implies, and a
    // pattern an attacker can trigger on.
    //
    // That was INFERRED, never measured, and `CLAUDE.md`'s countermeasure
    // carve-out requires a measured rate before anything is built on it. The
    // #802 fix also removed the 1 kHz SysTick caller, which changed the
    // contention pattern, so any earlier figure would be stale anyway.
    //
    // Self-contained: thread mode, nothing else running, no wallet needed.
    // One call in, two counters out.
    //
    // POST-#832 READING. The pre-drawn pool now serves the inner delays, so
    // they never reach `byte_nonsecret` at all. Expected `hits = 31` and
    // `fallbacks = 0` — the fallbacks going to zero IS the fix, and a nonzero
    // `hits` is what proves the new path actually ran rather than being
    // compiled out.
    //
    // Inside `interrupt::free`: otherwise an ISR that drew from the RNG during
    // the window would add its own calls and the claim "all K fallbacks are
    // this fill's fan-out" would be an assumption rather than a measurement.
    #[cfg(feature = "ui-px-frametime")]
    let (one_shot_hits, one_shot_fallbacks) = cortex_m::interrupt::free(|_| {
        use core::sync::atomic::Ordering::Relaxed;
        crate::rng::NONSECRET_CALLS.store(0, Relaxed);
        crate::rng::NONSECRET_FALLBACKS.store(0, Relaxed);
        crate::fi_delay_pool::HITS.store(0, Relaxed);
        crate::fi::wait_random();
        (
            crate::fi_delay_pool::HITS.load(Relaxed),
            crate::rng::NONSECRET_FALLBACKS.load(Relaxed),
        )
    });
    // ---- #832 sizing: sweep the fill LENGTH, not just the 1-byte case ----
    //
    // The one-shot above exercises the delay draw, which is a 1-byte fill: one
    // pass of the per-word loop. But the fan-out scales with length (~3 delays
    // before the loop, ~28 inside it) and `rng_strong::fill` passes the
    // caller's whole buffer straight through, so a 32-byte secret draw runs
    // ~8 iterations and a far bigger fan-out. `POOL_LEN`/`REFILL_BELOW` were
    // chosen to be covered by the per-output-word top-up — which is a DESIGN
    // argument, and "designed, not measured" is the exact error that started
    // this thread. So measure it: the largest hits-per-fill over the sweep is
    // the true worst-case fan-out, and any miss is the pool running dry.
    //
    // 64 bytes is the largest `rng::fill` the tree issues (BIP-39 entropy and
    // the SE folds are 32).
    #[cfg(feature = "ui-px-frametime")]
    let (max_hits, sweep_fallbacks, sweep_misses) = cortex_m::interrupt::free(|_| {
        use core::sync::atomic::Ordering::Relaxed;
        let mut buf = [0u8; 64];
        let mut max_hits = one_shot_hits;
        crate::rng::NONSECRET_FALLBACKS.store(0, Relaxed);
        crate::fi_delay_pool::MISSES.store(0, Relaxed);
        for len in [1usize, 4, 16, 32, 64] {
            crate::fi_delay_pool::HITS.store(0, Relaxed);
            let _ = crate::rng::fill(&mut buf[..len]);
            let hits = crate::fi_delay_pool::HITS.load(Relaxed);
            if hits > max_hits {
                max_hits = hits;
            }
        }
        // Not secret material, but it came from the TRNG — do not leave it on
        // the bench stack.
        buf.fill(0);
        (
            max_hits,
            crate::rng::NONSECRET_FALLBACKS.load(Relaxed),
            crate::fi_delay_pool::MISSES.load(Relaxed),
        )
    });
    // ---- #835: does the POISON BOUNDARY actually work on silicon? ----
    //
    // Option 2 replaced #833/#834's device halt with a per-operation poison:
    // a delay that cannot be given a fresh length performs no delay, raises
    // the flag, and the OPERATION refuses at its boundary. Every claim about
    // that so far is a source-text assertion. This exercises it for real.
    //
    // Four sub-checks, one bit each, because a single pass/fail cannot
    // distinguish "it works" from "it never ran":
    //
    //   bit 0  the flag reads POISONED after `poison_delay_source()`
    //   bit 1  `rng::fill` REFUSES while poisoned          <- the boundary
    //   bit 2  the flag reads CLEAN after `clear_delay_poison()`
    //   bit 3  `rng::fill` SUCCEEDS again afterwards       <- not stuck
    //
    // Bit 3 is the one that distinguishes option 2 from the halt it replaced:
    // under #833/#834 the device would already be dead in a `wfe` loop and
    // this screen would never paint. Here the operation failed and the device
    // carried on.
    //
    // Deliberately NOT exercising `pin_attempts_bump`: its poison check is the
    // C3 fix, but if that check were ever missing the call would commit a
    // flash write and durably spend one of this unit's ten PIN attempts. A
    // probe must not be able to damage the device it is measuring, so that one
    // stays covered by source tests only.
    #[cfg(feature = "ui-px-frametime")]
    let poison_selftest = cortex_m::interrupt::free(|_| {
        let mut bits = 0u32;
        let mut scratch = [0u8; 4];

        crate::fi::poison_delay_source();
        if crate::fi::delay_source_failed() {
            bits |= 1 << 0;
        }
        if crate::rng::fill(&mut scratch).is_err() {
            bits |= 1 << 1;
        }

        crate::fi::clear_delay_poison();
        if !crate::fi::delay_source_failed() {
            bits |= 1 << 2;
        }
        if crate::rng::fill(&mut scratch).is_ok() {
            bits |= 1 << 3;
        }

        scratch.fill(0);
        bits
    });

    // Baseline AFTER the self-test, so the overlay's second field counts only
    // poisonings that happen in ordinary running. It must stay 0: a device
    // doing nothing unusual should never fail to source a delay.
    #[cfg(feature = "ui-px-frametime")]
    let poison_baseline = crate::fi::DELAY_POISONINGS.load(core::sync::atomic::Ordering::Relaxed);

    #[cfg(feature = "ui-px-frametime")]
    super::lcd::set_fallback_probe(poison_selftest, poison_baseline, sweep_misses);
    #[cfg(feature = "ui-px-frametime")]
    let _ = (max_hits, one_shot_hits, one_shot_fallbacks, sweep_fallbacks);

    loop {
        // ---- A. the endless ambient record, animated against real input.
        //
        // This CALLED `play_screen` until #783 was fixed, and froze after
        // PLAY_CAP_MS — 1 s of still image, 2 s of a 5 s sweep, then a hard
        // stop mid-swing. That was the repro. It is now the demonstration:
        // the same screen on the same driver, animated for as long as the
        // wait lasts, so a human watching this image sees whether the fix
        // holds. Press either button to move on to B.
        //
        // Deliberately NOT `play_screen` any more: that function now refuses
        // to play a `plays_forever` screen at all (it paints the opening
        // frame and returns), so calling it here would show a still and look
        // like a regression.
        {
            let mut idle = || false; // watched by a human; no idle wipe here
            let mut amb = super::lcd::Ambient::new(&hero(), &atlas);
            let _ = crate::ui::input().wait_button_ticking(&mut idle, &mut || amb.tick(&atlas));
        }

        // ---- B. the same record as hero of a transcript, through the real
        // interactive dialog. `FlowDriver::new` only requires screen 0 to be
        // `Kind::Hero`, which `status_map::choice` is.
        let mut screens = Screens::blank();
        let _ = screens.push(&hero());
        for (i, label) in [&b"RENDER COST"[..], b"BLIT COST", b"FRAME PERIOD", b"SWEEP", b"HOLD", b"CHEVRONS"]
            .iter()
            .enumerate()
        {
            let side = if i % 2 == 0 { Side::Left } else { Side::Right };
            if let Ok(s) = ScreenBuilder::detail(b"BENCH", Icon::Eth, side, label).finish() {
                let _ = screens.push(&s);
            }
        }

        // No deadline: the bench is watched by a human, not a timeout.
        let mut never_expires = || false;
        let _ = super::lcd::run_flow(&screens, &atlas, &mut never_expires);
    }
}

/// Keeps the boot fixed-delay total reachable for the log without widening the
/// three-slot overlay. The overlay now carries window COUNT instead, because
/// the total alone cannot separate many windows from few windows with
/// interrupt-context delays landing inside them.
#[cfg(feature = "ui-px-frametime")]
fn boot_fixed_unused() -> u32 {
    use core::sync::atomic::Ordering::Relaxed;
    crate::fi::BOOTSTRAP_DELAYS.load(Relaxed) + crate::fi::DELAY_RETRIES.load(Relaxed)
}

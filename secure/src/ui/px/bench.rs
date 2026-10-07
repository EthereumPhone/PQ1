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

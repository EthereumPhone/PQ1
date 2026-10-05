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
//!   A. `status_map::choice` through `lcd::play_screen` — the #778 repro. A
//!      record whose layout sets an ambient cycle never returns `!moving` from
//!      `Anim::step`, so `play_screen`'s only exit is its 3 s `PLAY_CAP_MS` cap:
//!      it abandons the animation mid-cycle and leaves the frame on the glass.
//!      Every input is time-based, so the stop PHASE is identical at any frame
//!      rate — confirmed on silicon at both 20 MHz and 40 MHz SPI.
//!
//!   B. the same record as the hero of a short transcript through
//!      `lcd::run_flow` — the real interactive dialog, which is where the
//!      `ui-px-frametime` overlay paints `<render>/<blit>/<period>` in ms.
//!      Build with `ui-px-frametime` to read the numbers.
//!
//! Drive B with the physical buttons; it loops back to A on any outcome.

use pqsigner_ui_px::{Icon, ScreenBuilder, Screens, Side};

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
    // The atlas is a WYSIWYS input: without a verified one the pixel path
    // refuses rather than painting with an unknown font, and so does this.
    let Ok(atlas) = super::assets::verify_atlas() else {
        park();
    };

    loop {
        // ---- A. ambient record via play_screen: freezes after PLAY_CAP_MS.
        super::lcd::play_screen(&hero(), &atlas, &[]);

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

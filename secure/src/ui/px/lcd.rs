//! The NV3007 pixel presenter: frame loop, strip blit, SysTick button
//! sampling and the design's confirm runtime on real glass.
//!
//! * **Strips.** A full RGB565 frame (121 KB) does not fit secure SRAM, so
//!   each frame is rendered as nine 428 × 16 strips into one 13.7 KB BSS
//!   buffer and streamed to the panel per strip. The panel is mounted
//!   portrait and rotated in software (`FLIP = (true, false)`, see
//!   `ui/lcd.rs`): landscape `(x, y)` is native `(141 − y, x)`, so a
//!   landscape row band is a native **column** band, streamed with
//!   landscape-x outer and landscape-y inner (descending).
//! * **Input.** `systick_sample` runs from the 1 kHz SysTick while a flow is
//!   live and records button edges with their exact millisecond into a
//!   lock-free ring; the frame loop drains it into the pure `InputFsm`, so a
//!   tap is timed exactly even while the CPU is inside a 50 ms blit.
//! * **The loop.** `run_flow` mirrors `confirm_px`'s text loop point for
//!   point (guard, idle, deadline, single sentinel site) but animates: the
//!   disc springs between screens, the trail follows, the hold floods the
//!   disc, the returning ask sweeps and hints.
//!
//! Nothing here touches the transcript's bytes: it reads the proven
//! `Screens` and paints.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use super::assets;
use super::PxOutcome;
use crate::hw::lcd_nv3007 as lcd;
use crate::timeout;
use pqsigner_ui_px::driver::{Btn, FlowDriver, Gesture as NavGesture, NavResult};
use pqsigner_ui_px::input::{Gesture, InputCtx, InputFsm};
use pqsigner_ui_px::raster::{render_strip, Frame, Strip, H, W};
use pqsigner_ui_px::scene::{Anim, Ending};
use pqsigner_ui_px::{Screen, Screens};

/// Rows per strip: 9 strips per frame, 13,696 B of BSS.
const STRIP_H: i32 = 16;
const STRIP_PX: usize = (W * STRIP_H) as usize;

/// The one strip buffer. Single-threaded secure world; only the frame loop
/// touches it (the SysTick sampler never renders).
static mut STRIP: [u16; STRIP_PX] = [0; STRIP_PX];

// ---- SysTick edge ring ------------------------------------------------------

/// Sampling is enabled only inside a live flow.
static PX_SAMPLING: AtomicBool = AtomicBool::new(false);
const RING_LEN: usize = 8;
/// `(time, bits)` pairs; bit 0 = left down, bit 1 = right down.
static RING_T: [AtomicU32; RING_LEN] = [const { AtomicU32::new(0) }; RING_LEN];
static RING_B: [AtomicU32; RING_LEN] = [const { AtomicU32::new(0) }; RING_LEN];
static RING_HEAD: AtomicUsize = AtomicUsize::new(0);
static RING_TAIL: AtomicUsize = AtomicUsize::new(0);
static LAST_BITS: AtomicU32 = AtomicU32::new(0);

fn read_bits() -> u32 {
    u32::from(crate::hw::buttons::left_pressed()) | (u32::from(crate::hw::buttons::right_pressed()) << 1)
}

/// Called from `SysTick` (1 kHz): record a button edge with its time.
pub fn systick_sample() {
    if !PX_SAMPLING.load(Ordering::Relaxed) {
        return;
    }
    let bits = read_bits();
    if bits == LAST_BITS.load(Ordering::Relaxed) {
        return;
    }
    LAST_BITS.store(bits, Ordering::Relaxed);
    let head = RING_HEAD.load(Ordering::Relaxed);
    let tail = RING_TAIL.load(Ordering::Acquire);
    if head.wrapping_sub(tail) >= RING_LEN {
        return; // full: the level poll in the frame loop still catches up
    }
    RING_T[head % RING_LEN].store(timeout::now(), Ordering::Relaxed);
    RING_B[head % RING_LEN].store(bits, Ordering::Relaxed);
    RING_HEAD.store(head.wrapping_add(1), Ordering::Release);
}

fn sampling_enable() {
    LAST_BITS.store(read_bits(), Ordering::Relaxed);
    RING_TAIL.store(RING_HEAD.load(Ordering::Acquire), Ordering::Release);
    PX_SAMPLING.store(true, Ordering::Release);
}

fn sampling_disable() {
    PX_SAMPLING.store(false, Ordering::Release);
}

/// Up to 8 gestures per frame after draining the ring and the live level.
struct Gestures {
    buf: [Option<Gesture>; 8],
    n: usize,
    /// A real edge was seen (resets the inactivity timer).
    edge: bool,
}

fn drain(fsm: &mut InputFsm, now: u32) -> Gestures {
    let mut g = Gestures {
        buf: [None; 8],
        n: 0,
        edge: false,
    };
    let mut push = |ev: pqsigner_ui_px::input::Events| {
        for e in ev.iter() {
            if matches!(e, Gesture::Press(_) | Gesture::Release(_)) {
                g.edge = true;
            }
            if g.n < g.buf.len() {
                g.buf[g.n] = Some(e);
                g.n += 1;
            }
        }
    };
    loop {
        let tail = RING_TAIL.load(Ordering::Relaxed);
        let head = RING_HEAD.load(Ordering::Acquire);
        if tail == head {
            break;
        }
        let t = RING_T[tail % RING_LEN].load(Ordering::Relaxed);
        let b = RING_B[tail % RING_LEN].load(Ordering::Relaxed);
        RING_TAIL.store(tail.wrapping_add(1), Ordering::Release);
        push(fsm.poll(t, b & 1 != 0, b & 2 != 0));
    }
    let b = read_bits();
    push(fsm.poll(now, b & 1 != 0, b & 2 != 0));
    g
}

// ---- rendering ---------------------------------------------------------------

/// Render `frame` strip by strip and stream each to the panel.
fn present_frame(frame: &Frame<'_>) {
    let font = assets::font();
    // SAFETY: single-threaded frame loop; the SysTick sampler never touches
    // the strip buffer (same discipline as `splash_test::FB`).
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(STRIP) };
    let mut y0 = 0;
    while y0 < H {
        let h = STRIP_H.min(H - y0);
        let Some(mut strip) = Strip::new(y0, h, &mut buf[..]) else { return };
        render_strip(frame, &font, &mut strip);
        blit_strip(y0, h, &buf[..(W * h) as usize]);
        y0 += h;
    }
}

/// Stream a landscape row band `[y0, y0 + h)` as the native column band
/// `nx ∈ [141 − (y0 + h − 1), 141 − y0]` over all 428 native rows.
fn blit_strip(y0: i32, h: i32, buf: &[u16]) {
    let nx0 = (H - 1) - (y0 + h - 1);
    let nx1 = (H - 1) - y0;
    lcd::set_window(nx0 as u16, 0, nx1 as u16, (W - 1) as u16);
    // Native rows (ny = landscape x) outer, native columns (nx) inner: nx
    // ascending means landscape y descending within the band.
    let mut ny = 0i32; // landscape x
    let mut k = 0i32; // 0..h, landscape y = y0 + (h − 1 − k)
    let n = (W * h) as u32;
    lcd::write_pixels_with(n, || {
        let ly = h - 1 - k;
        let px = buf[(ly * W + ny) as usize];
        k += 1;
        if k == h {
            k = 0;
            ny += 1;
        }
        px
    });
}

fn build_and_present(anim: &Anim) {
    let marks = assets::marks();
    let font = assets::font();
    let mut frame = Frame::new();
    anim.build(&marks, &font, &mut frame);
    present_frame(&frame);
}

/// Paint a legacy 16×4 page through the pixel engine (the `Display::flush`
/// path under `ui-px`, so every status / progress / PIN screen shares the
/// design's typography).
pub fn paint_legacy(rows: &[[u8; crate::ui::DISPLAY_COLS]; crate::ui::DISPLAY_ROWS]) {
    let s = Screen::legacy(rows);
    let anim = Anim::new(&s, 0, timeout::now());
    build_and_present(&anim);
}

/// Clear the panel (before the legacy glyph blitter paints again).
pub fn clear() {
    lcd::fill_screen(0);
}

/// Play an ending over ~1.3 s and leave its resting frame on the glass.
pub fn show_ending(e: Ending) {
    let hero = Screen::BLANK;
    let now = timeout::now();
    let mut anim = Anim::new(&hero, 0, now);
    anim.ending(e, now);
    let start = now;
    loop {
        let t = timeout::now();
        anim.step(t);
        build_and_present(&anim);
        if t.wrapping_sub(start) > 1300 {
            break;
        }
    }
}

/// The busy look while the device computes (split/join film pending: a
/// resting disc with the caption). `pct` throttles nothing yet.
pub fn show_busy(caption: &[u8]) {
    let s = pqsigner_ui_px::ScreenBuilder::status(b"BUSY", pqsigner_ui_px::Icon::Safe, caption, pqsigner_ui_px::State::Awaiting, pqsigner_ui_px::ResultMark::None)
        .finish()
        .unwrap_or(Screen::BLANK);
    let anim = Anim::new(&s, 0, timeout::now());
    build_and_present(&anim);
}

// ---- the flow ------------------------------------------------------------------

/// Run the design's confirm loop over a proven transcript on the panel.
/// Returns the outcome and the FI gate (`OK_SENTINEL` only for `Signed`).
pub fn run_flow(screens: &Screens, deadline_expired: &mut dyn FnMut() -> bool) -> (PxOutcome, u32) {
    let visible = screens.as_slice();
    let Some(mut driver) = FlowDriver::new(visible) else {
        return (PxOutcome::Cancelled, crate::fi::FAIL_SENTINEL);
    };
    if deadline_expired() {
        return (PxOutcome::DeadlineExpired, crate::fi::FAIL_SENTINEL);
    }
    let mut fsm = InputFsm::new(InputCtx::NAV);
    let now = timeout::now();
    let mut anim = Anim::new(&visible[0], 0, now);
    // F14/SCAFI-2: FI-hardened arming flag (complement pair + double read).
    let mut commit_armed = crate::fih::FihBool::new_false();
    sampling_enable();
    // The whole navigation phase is "waiting on physical input" for the
    // watchdog; it does NOT reset the inactivity timer (confirm.rs HIGH-13).
    let _trusted_ui_wait = timeout::TrustedUiWaitGuard::enter();

    let mut painted_idx = usize::MAX;
    let result = loop {
        if deadline_expired() {
            break (PxOutcome::DeadlineExpired, crate::fi::FAIL_SENTINEL);
        }
        if timeout::is_idle() {
            break (PxOutcome::IdleWipe, crate::fi::FAIL_SENTINEL);
        }
        let now = timeout::now();
        // Arming follows the screen currently shown (kind ∈ {hero, confirm},
        // commit byte double-read, and the consent policy).
        let armed = driver.armed(visible);
        let sign_ok = armed.sign && (!super::PX_COMMIT_REQUIRES_SEEN_LAST || driver.seen_last());
        if sign_ok {
            commit_armed.set_true();
        } else {
            commit_armed.set_false();
        }

        // ---- input ----
        let g = drain(&mut fsm, now);
        if g.edge {
            // A button event IS real user activity — the only reset site.
            timeout::reset_activity();
        }
        let mut decided: Option<(PxOutcome, u32)> = None;
        for ev in g.buf[..g.n].iter().flatten() {
            match *ev {
                Gesture::Press(side) => anim.press(side, now),
                Gesture::HoldCancel(_) => anim.hold_release(now),
                Gesture::HoldCommit(side) => {
                    anim.hold_commit(now);
                    match driver.apply(visible, NavGesture::HoldCommit(side)) {
                        NavResult::Decline => {
                            decided = Some((PxOutcome::Declined, crate::fi::FAIL_SENTINEL));
                        }
                        NavResult::Sign => {
                            // The ONE affirmative site.
                            let gate = commit_armed.check_sentinel();
                            if gate == crate::fi::OK_SENTINEL && !deadline_expired() {
                                decided = Some((PxOutcome::Signed, gate));
                            }
                        }
                        _ => anim.hold_release(now),
                    }
                }
                Gesture::Tap(side) => match driver.apply(visible, NavGesture::Tap(side)) {
                    NavResult::Moved => {
                        let (i, p) = (driver.index(), driver.page());
                        anim.go_to(&visible[i], p, now);
                    }
                    NavResult::PageTurned => anim.flip_page(driver.page(), now),
                    _ => {}
                },
                Gesture::HoldStart(_) | Gesture::Release(_) | Gesture::DoubleTap(_) | Gesture::Chord => {}
            }
        }
        if let Some(d) = decided {
            break d;
        }
        // Hold fill: only on an armed side ("nothing draws on an unarmed side").
        if let Some((side, held)) = fsm.hold_progress(now) {
            let show = match side {
                Btn::Left => armed.decline,
                Btn::Right => sign_ok,
            };
            if show {
                anim.hold(side, held, now);
            }
        }

        // ---- frame ----
        let animating = anim.step(now);
        build_and_present(&anim);
        if driver.index() != painted_idx {
            painted_idx = driver.index();
            driver.mark_rendered();
            super::text::present(&visible[painted_idx], driver.page(), painted_idx, visible.len());
        }

        // ---- sleep until the next frame or an edge ----
        if !animating && anim.next_wake(now).is_none() && read_bits() == 0 {
            // Detail screens: nothing moves without a press. Wait for an edge
            // (the sampler records it with its exact time), an idle wipe or
            // the deadline.
            loop {
                cortex_m::asm::wfi();
                if RING_HEAD.load(Ordering::Acquire) != RING_TAIL.load(Ordering::Relaxed)
                    || read_bits() != 0
                    || timeout::is_idle()
                    || deadline_expired()
                {
                    break;
                }
            }
        } else {
            // Ambient / animating: pace at ~30 fps at most (the blit itself
            // takes ~48 ms at 20 MHz, so this only matters when it gets faster).
            let t0 = timeout::now();
            while timeout::now().wrapping_sub(t0) < 8 {
                cortex_m::asm::wfi();
            }
        }
    };
    sampling_disable();
    result
}

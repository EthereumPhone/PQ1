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
//!   live. It debounces each side in the ISR (the first raw edge is accepted
//!   at its exact millisecond, further changes on that side are ignored for
//!   `DEBOUNCE_MS`, a change that outlives the lockout is accepted when it
//!   ends) and records every accepted edge with its time into a lock-free
//!   ring; the frame loop drains the ring into the pure `InputFsm` and then
//!   polls the debounced level with a clock read *after* the drain, so the
//!   FSM never sees time run backwards and a tap is timed exactly even while
//!   the CPU is inside a 25–50 ms blit. (2026-09-22 EVT: raw edges from a
//!   bouncing switch overflowed the ring during a slow frame and the FSM's
//!   own lockout had a release-side hole — taps were swallowed.)
//! * **The loop.** `run_flow` mirrors `confirm_px`'s text loop point for
//!   point (guard, idle, deadline, single sentinel site) but animates: the
//!   disc springs between screens, the trail follows, the chord floods the
//!   disc, the returning ask sweeps and hints. Signing is the two-button
//!   chord click on a commit-armed screen; hold-left declines; hold-right
//!   does nothing.
//!
//! Nothing here touches the transcript's bytes: it reads the proven
//! `Screens` and paints.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use super::assets;
use super::PxOutcome;
use crate::hw::lcd_nv3007 as lcd;
use crate::timeout;
use pqsigner_ui_px::driver::{Btn, FlowDriver, Gesture as NavGesture, NavResult};
use pqsigner_ui_px::font::Font;
use pqsigner_ui_px::input::{Gesture, InputCtx, InputFsm, DEBOUNCE_MS};
use pqsigner_ui_px::raster::{render_strip, Frame, Strip, H, W};
use pqsigner_ui_px::scene::{Anim, Ending, Marks};
use pqsigner_ui_px::{Screen, Screens};

/// Frame pacing while something animates (~60 fps cap); a frame that already
/// took longer starts the next one immediately.
const FRAME_PERIOD_MS: u32 = 16;

/// Rows per strip: 9 strips per frame, 13,696 B of BSS.
const STRIP_H: i32 = 16;
const STRIP_PX: usize = (W * STRIP_H) as usize;

/// The one strip buffer. Single-threaded secure world; only the frame loop
/// touches it (the SysTick sampler never renders).
static mut STRIP: [u16; STRIP_PX] = [0; STRIP_PX];

/// Number of strips per frame.
const N_STRIPS: usize = ((H + STRIP_H - 1) / STRIP_H) as usize;

/// Per-strip 64-bit digest of what the panel currently shows, so a strip
/// whose pixels did not change is not streamed again (the blit dominates
/// the frame: ~24 ms at 40 MHz for all nine strips). `None` = unknown —
/// every other painter (legacy glyph blitter, `fill_screen`, the ending /
/// busy / legacy paints) invalidates it, and a flow starts invalidated, so
/// the first frame of a flow always writes the whole panel.
static mut SHOWN: [Option<u64>; N_STRIPS] = [None; N_STRIPS];

/// Forget what the panel shows: the next frame streams every strip.
fn invalidate_shown() {
    // SAFETY: single-threaded frame loop bookkeeping (never touched by the
    // SysTick sampler).
    let shown = unsafe { &mut *core::ptr::addr_of_mut!(SHOWN) };
    for s in shown.iter_mut() {
        *s = None;
    }
}

/// Two independent 32-bit FNV-1a lanes over the strip's pixels (a 64-bit
/// digest; a collision would leave one stale strip on the glass, so the
/// width is chosen to make that ≈ 2⁻⁶⁴ per changed strip).
fn strip_digest(buf: &[u16]) -> u64 {
    let mut a: u32 = 0x811C_9DC5;
    let mut b: u32 = 0x2545_F491;
    // Two pixels per step; an odd trailing pixel is folded in on its own.
    let mut pairs = buf.chunks_exact(2);
    for pr in &mut pairs {
        let w = u32::from(pr[0]) | (u32::from(pr[1]) << 16);
        a = (a ^ w).wrapping_mul(0x0100_0193);
        b = (b ^ w.rotate_left(13)).wrapping_mul(0x01B8_73E9);
    }
    for &p in pairs.remainder() {
        a = (a ^ u32::from(p)).wrapping_mul(0x0100_0193);
        b = (b ^ u32::from(p).rotate_left(13)).wrapping_mul(0x01B8_73E9);
    }
    (u64::from(a) << 32) | u64::from(b)
}

// ---- SysTick edge ring ------------------------------------------------------

/// Sampling is enabled only inside a live flow.
static PX_SAMPLING: AtomicBool = AtomicBool::new(false);
/// Accepted (debounced) edges only: ≤ 40 per second per side, so 16 entries
/// cover > 200 ms of the fastest possible pressing on both sides.
const RING_LEN: usize = 16;
/// `(time, bits)` pairs; bit 0 = left down, bit 1 = right down.
static RING_T: [AtomicU32; RING_LEN] = [const { AtomicU32::new(0) }; RING_LEN];
static RING_B: [AtomicU32; RING_LEN] = [const { AtomicU32::new(0) }; RING_LEN];
static RING_HEAD: AtomicUsize = AtomicUsize::new(0);
static RING_TAIL: AtomicUsize = AtomicUsize::new(0);
/// The debounced level of both sides, as the sampler last accepted it. The
/// frame loop polls THIS, never the raw pins, so it agrees with the ring.
static STABLE_BITS: AtomicU32 = AtomicU32::new(0);
/// Per side: time of the last accepted edge (the lockout origin).
static LAST_EDGE_T: [AtomicU32; 2] = [const { AtomicU32::new(0) }; 2];

fn read_bits() -> u32 {
    u32::from(crate::hw::buttons::left_pressed()) | (u32::from(crate::hw::buttons::right_pressed()) << 1)
}

/// Called from `SysTick` (1 kHz): debounce each side and record an accepted
/// edge with its time.
pub fn systick_sample() {
    if !PX_SAMPLING.load(Ordering::Relaxed) {
        return;
    }
    let raw = read_bits();
    let mut stable = STABLE_BITS.load(Ordering::Relaxed);
    if raw == stable {
        return;
    }
    let now = timeout::now();
    let mut changed = false;
    for side in 0..2 {
        let m = 1u32 << side;
        if (raw ^ stable) & m != 0 && now.wrapping_sub(LAST_EDGE_T[side].load(Ordering::Relaxed)) >= DEBOUNCE_MS {
            stable ^= m;
            changed = true;
            LAST_EDGE_T[side].store(now, Ordering::Relaxed);
        }
    }
    if !changed {
        return; // inside a lockout; re-evaluated next tick
    }
    STABLE_BITS.store(stable, Ordering::Release);
    let head = RING_HEAD.load(Ordering::Relaxed);
    let tail = RING_TAIL.load(Ordering::Acquire);
    if head.wrapping_sub(tail) >= RING_LEN {
        return; // full: the level poll of STABLE_BITS still converges
    }
    RING_T[head % RING_LEN].store(now, Ordering::Relaxed);
    RING_B[head % RING_LEN].store(stable, Ordering::Relaxed);
    RING_HEAD.store(head.wrapping_add(1), Ordering::Release);
}

fn sampling_enable() {
    let now = timeout::now();
    STABLE_BITS.store(read_bits(), Ordering::Relaxed);
    for t in &LAST_EDGE_T {
        // The first edge is accepted immediately.
        t.store(now.wrapping_sub(DEBOUNCE_MS), Ordering::Relaxed);
    }
    RING_TAIL.store(RING_HEAD.load(Ordering::Acquire), Ordering::Release);
    PX_SAMPLING.store(true, Ordering::Release);
}

fn sampling_disable() {
    PX_SAMPLING.store(false, Ordering::Release);
}

#[inline]
fn stable_bits() -> u32 {
    STABLE_BITS.load(Ordering::Acquire)
}

#[inline]
fn ring_has_edges() -> bool {
    RING_HEAD.load(Ordering::Acquire) != RING_TAIL.load(Ordering::Relaxed)
}

/// Up to 8 gestures per frame after draining the ring and the live level.
struct Gestures {
    buf: [Option<Gesture>; 8],
    n: usize,
    /// A real edge was seen (resets the inactivity timer).
    edge: bool,
}

/// Replay the ring's timestamped edges, then poll the debounced level at a
/// clock read AFTER the replay. Returns the gestures and that `now`, which
/// the caller uses for the rest of the frame (≥ every replayed time).
fn drain(fsm: &mut InputFsm) -> (Gestures, u32) {
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
    let now = timeout::now();
    let b = stable_bits();
    push(fsm.poll(now, b & 1 != 0, b & 2 != 0));
    (g, now)
}

// ---- frame-time overlay (bench only) -----------------------------------------

#[cfg(feature = "ui-px-frametime")]
mod frametime {
    //! DWT cycle counter → "<render>/<blit>/<period>" in ms, drawn into the
    //! next frame. Bench instrumentation (`ui-px-frametime`, in
    //! `PROD_FORBIDDEN`).
    use crate::hw::mmio::Reg32;

    // SAFETY: core debug block registers (ARMv8-M): DEMCR, DWT_CTRL,
    // DWT_CYCCNT, DWT_LAR — real, aligned, single-threaded bench use.
    const DEMCR: Reg32 = unsafe { Reg32::new(0xE000_EDFC) };
    const DWT_CTRL: Reg32 = unsafe { Reg32::new(0xE000_1000) };
    const DWT_CYCCNT: Reg32 = unsafe { Reg32::new(0xE000_1004) };
    const DWT_LAR: Reg32 = unsafe { Reg32::new(0xE000_1FB0) };
    const CPU_HZ_PER_MS: u32 = 160_000;

    pub fn enable() {
        DEMCR.modify(|v| v | (1 << 24)); // TRCENA
        DWT_LAR.write(0xC5AC_CE55);
        DWT_CYCCNT.write(0);
        DWT_CTRL.modify(|v| v | 1); // CYCCNTENA
    }

    #[inline]
    pub fn cycles() -> u32 {
        DWT_CYCCNT.read()
    }

    /// Format `<render>/<blit>/<period>` (ms, ≤ 3 digits each) into `out`;
    /// returns the used length.
    pub fn format(out: &mut [u8; 24], render_cyc: u32, blit_cyc: u32, period_ms: u32) -> usize {
        let mut n = 0;
        let mut put = |b: u8| {
            if n < out.len() {
                out[n] = b;
                n += 1;
            }
        };
        let num = |mut v: u32, put: &mut dyn FnMut(u8)| {
            v = v.min(999);
            if v >= 100 {
                put(b'0' + (v / 100) as u8);
            }
            if v >= 10 {
                put(b'0' + ((v / 10) % 10) as u8);
            }
            put(b'0' + (v % 10) as u8);
        };
        // `render/blit/period`: the 16 px tier's trimmed charset has digits
        // and the pager's '/', no letters.
        num(render_cyc / CPU_HZ_PER_MS, &mut put);
        put(b'/');
        num(blit_cyc / CPU_HZ_PER_MS, &mut put);
        put(b'/');
        num(period_ms, &mut put);
        n
    }
}

/// Cycle split of one presented frame (bench overlay); zeros otherwise.
#[derive(Clone, Copy, Default)]
#[allow(dead_code)]
struct FrameCost {
    render: u32,
    blit: u32,
}

// ---- rendering ---------------------------------------------------------------

/// Render `frame` strip by strip and stream each strip that changed since
/// the panel last received it.
fn present_frame(frame: &Frame<'_>, font: &Font<'_>) -> FrameCost {
    let mut cost = FrameCost::default();
    // SAFETY: single-threaded frame loop; the SysTick sampler never touches
    // the strip buffer or the digest table (same discipline as
    // `splash_test::FB`).
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(STRIP) };
    let shown = unsafe { &mut *core::ptr::addr_of_mut!(SHOWN) };
    let mut y0 = 0;
    let mut i = 0usize;
    while y0 < H {
        let h = STRIP_H.min(H - y0);
        let Some(mut strip) = Strip::new(y0, h, &mut buf[..]) else { return cost };
        #[cfg(feature = "ui-px-frametime")]
        let t0 = frametime::cycles();
        render_strip(frame, font, &mut strip);
        let d = strip_digest(&buf[..(W * h) as usize]);
        #[cfg(feature = "ui-px-frametime")]
        let t1 = frametime::cycles();
        if shown.get(i).copied().flatten() != Some(d) {
            blit_strip(y0, h, &buf[..(W * h) as usize]);
            if let Some(slot) = shown.get_mut(i) {
                *slot = Some(d);
            }
        }
        #[cfg(feature = "ui-px-frametime")]
        {
            let t2 = frametime::cycles();
            cost.render = cost.render.wrapping_add(t1.wrapping_sub(t0));
            cost.blit = cost.blit.wrapping_add(t2.wrapping_sub(t1));
        }
        y0 += h;
        i += 1;
    }
    cost
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

/// Build the display list for `anim` and present it. `overlay` is the bench
/// frame-time text (top-left, 16 px), `None` in every non-bench build.
fn build_and_present(anim: &Anim, marks: &Marks<'_>, font: &Font<'_>, overlay: Option<&[u8]>) -> FrameCost {
    let mut frame = Frame::new();
    #[cfg(feature = "ui-px-frametime")]
    let t0 = frametime::cycles();
    anim.build(marks, font, &mut frame);
    if let Some(text) = overlay {
        use pqsigner_ui_px::font::{Align, TextRun, TierId};
        use pqsigner_ui_px::raster::{Item, Rgb};
        frame.push(Item::Text {
            run: TextRun {
                text,
                tier: TierId::regular(16),
                x: 40,
                y: 16,
                align: Align::Left,
                baseline: true,
                ls_q6: 0,
                alpha: 255,
            },
            color: Rgb::YELLOW,
        });
    }
    #[cfg(feature = "ui-px-frametime")]
    let build_cyc = frametime::cycles().wrapping_sub(t0);
    let mut cost = present_frame(&frame, font);
    #[cfg(feature = "ui-px-frametime")]
    {
        cost.render = cost.render.wrapping_add(build_cyc);
    }
    #[cfg(not(feature = "ui-px-frametime"))]
    {
        cost = FrameCost::default();
    }
    cost
}

/// Paint a legacy 16×4 page through the pixel engine (the `Display::flush`
/// path under `ui-px`, so every status / progress / PIN screen shares the
/// design's typography).
pub fn paint_legacy(rows: &[[u8; crate::ui::DISPLAY_COLS]; crate::ui::DISPLAY_ROWS]) {
    // The legacy glyph blitter may have painted between calls.
    invalidate_shown();
    let s = Screen::legacy(rows);
    let anim = Anim::new(&s, 0, timeout::now());
    let _ = build_and_present(&anim, &assets::marks(), &assets::font(), None);
}

/// Clear the panel (before the legacy glyph blitter paints again).
pub fn clear() {
    invalidate_shown();
    lcd::fill_screen(0);
}

/// Play an ending over ~1.3 s and leave its resting frame on the glass.
pub fn show_ending(e: Ending) {
    let hero = Screen::BLANK;
    let now = timeout::now();
    let mut anim = Anim::new(&hero, 0, now);
    anim.ending(e, now);
    let start = now;
    let marks = assets::marks();
    let font = assets::font();
    invalidate_shown();
    loop {
        let t = timeout::now();
        anim.step(t);
        let _ = build_and_present(&anim, &marks, &font, None);
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
    invalidate_shown();
    let anim = Anim::new(&s, 0, timeout::now());
    let _ = build_and_present(&anim, &assets::marks(), &assets::font(), None);
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
    // Parsed once per flow: the atlas header walk is cheap but it is per
    // frame otherwise, and the marks likewise.
    let marks = assets::marks();
    let font = assets::font();
    let mut fsm = InputFsm::new(InputCtx::NAV);
    let now = timeout::now();
    let mut anim = Anim::new(&visible[0], 0, now);
    // F14/SCAFI-2: FI-hardened arming flag (complement pair + double read).
    let mut commit_armed = crate::fih::FihBool::new_false();
    // Whatever the panel shows now, the flow's first frame repaints it all.
    invalidate_shown();
    sampling_enable();
    // The whole navigation phase is "waiting on physical input" for the
    // watchdog; it does NOT reset the inactivity timer (confirm.rs HIGH-13).
    let _trusted_ui_wait = timeout::TrustedUiWaitGuard::enter();

    #[cfg(feature = "ui-px-frametime")]
    frametime::enable();
    #[allow(unused_mut)]
    let mut overlay_buf = [0u8; 24];
    #[allow(unused_mut)]
    let mut overlay_len = 0usize;
    #[allow(unused_mut, unused_variables)]
    let mut last_frame_at = now;

    let mut painted_idx = usize::MAX;
    let result = loop {
        if deadline_expired() {
            break (PxOutcome::DeadlineExpired, crate::fi::FAIL_SENTINEL);
        }
        if timeout::is_idle() {
            break (PxOutcome::IdleWipe, crate::fi::FAIL_SENTINEL);
        }
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
        // `now` is read after the ring replay so it is ≥ every edge time the
        // FSM just consumed (see the module docs).
        let (g, now) = drain(&mut fsm);
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
                        // Hold-right never signs on this path (the chord does).
                        _ => anim.hold_release(now),
                    }
                }
                // Both buttons down together: flood the disc as feedback while
                // the chord is held (only where a sign is armed).
                Gesture::Chord => {
                    if sign_ok {
                        anim.hold(Btn::Right, pqsigner_ui_px::motion::HOLD_COMMIT_MS, now);
                    }
                }
                // Both released: the sign gesture (owner decision 2026-09-22).
                Gesture::ChordClick => {
                    match driver.apply(visible, NavGesture::Chord) {
                        NavResult::Sign => {
                            anim.hold_commit(now);
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
                Gesture::HoldStart(_) | Gesture::Release(_) | Gesture::DoubleTap(_) => {}
            }
        }
        if let Some(d) = decided {
            break d;
        }
        // Hold fill: only on an armed side ("nothing draws on an unarmed
        // side") — hold-left declines; hold-right is armed nowhere.
        if let Some((side, held)) = fsm.hold_progress(now) {
            let show = match side {
                Btn::Left => armed.decline,
                Btn::Right => false,
            };
            if show {
                anim.hold(side, held, now);
            }
        }

        // ---- frame ----
        let animating = anim.step(now);
        let overlay = if overlay_len > 0 { Some(&overlay_buf[..overlay_len]) } else { None };
        let cost = build_and_present(&anim, &marks, &font, overlay);
        #[cfg(feature = "ui-px-frametime")]
        {
            let t = timeout::now();
            overlay_len = frametime::format(&mut overlay_buf, cost.render, cost.blit, t.wrapping_sub(last_frame_at));
            last_frame_at = t;
        }
        #[cfg(not(feature = "ui-px-frametime"))]
        let _ = cost;
        if driver.index() != painted_idx {
            painted_idx = driver.index();
            driver.mark_rendered();
            super::text::present(&visible[painted_idx], driver.page(), painted_idx, visible.len());
        }

        // ---- sleep until the next frame or an edge ----
        if !animating && anim.next_wake(now).is_none() && stable_bits() == 0 {
            // Detail screens: nothing moves without a press. Wait for an edge
            // (the sampler records it with its exact time), an idle wipe or
            // the deadline.
            loop {
                cortex_m::asm::wfi();
                if ring_has_edges() || stable_bits() != 0 || timeout::is_idle() || deadline_expired() {
                    break;
                }
            }
        } else {
            // Ambient / animating: pace to ~30 fps measured from the frame's
            // input sample, never adding idle time after a slow frame; an
            // accepted edge ends the wait early so a tap mid-animation is
            // handled on the very next frame.
            while now.wrapping_add(FRAME_PERIOD_MS).wrapping_sub(timeout::now()) < (1 << 31) {
                if ring_has_edges() {
                    break;
                }
                cortex_m::asm::wfi();
            }
        }
    };
    sampling_disable();
    result
}

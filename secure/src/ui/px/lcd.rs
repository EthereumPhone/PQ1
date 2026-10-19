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

use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use super::assets;
use super::PxOutcome;
use crate::hw::lcd_nv3007 as lcd;
use crate::timeout;
use pqsigner_ui_px::driver::{Btn, FlowDriver, Gesture as NavGesture, NavResult};
use pqsigner_ui_px::font::Font;
use pqsigner_ui_px::input::{EntryEvent, EntryGrammar, Gesture, InputCtx, InputFsm, DEBOUNCE_MS};
use pqsigner_ui_px::raster::{render_strip, Frame, Strip, H, W};
use zeroize::Zeroize;
use pqsigner_ui_px::scene::{Anim, Ending, Marks};
use pqsigner_ui_px::{Screen, Screens};

/// Frame pacing while something animates (~60 fps cap); a frame that already
/// took longer starts the next one immediately.
const FRAME_PERIOD_MS: u32 = 16;

/// Landscape COLUMNS per band: 9 bands per frame, 13,632 B per band buffer.
///
/// Bands are vertical since #780. The panel scans native rows `ny`, and
/// `ny = x`, so a band of landscape x is a contiguous run of scan rows that
/// can be streamed in the beam's own order; the old horizontal bands were
/// native COLUMN bands spanning all 428 scan rows, so each one re-crossed the
/// beam and no amount of TE synchronisation could help. See `raster::Strip`.
const BAND_W: i32 = 48;
const STRIP_PX: usize = (BAND_W * H) as usize;

/// Number of bands per frame.
const N_STRIPS: usize = ((W + BAND_W - 1) / BAND_W) as usize;

/// One band of the frame, in the panel's wire order, NATIVE pixel endianness.
///
/// `#[repr(align(4))]` is load-bearing, not hygiene: GPDMA streams this with
/// WORD beats (`gpdma::TR1_VAL`), and "a source address must be aligned with
/// the programmed data width of a source burst … Else, a user setting error is
/// reported and no transfer is issued" (RM0456 §17.8.14). A bare
/// `[u16; STRIP_PX]` is only guaranteed 2-byte aligned, so without this the
/// channel would raise `USEF` and paint nothing — loudly, but only on
/// hardware. `STRIP_PX * 2` = 13,632 is a multiple of 4, so every element of
/// the array below stays aligned too.
#[repr(align(4))]
struct Band([u16; STRIP_PX]);

// The OTHER half of the word-beat precondition, and the one that is a property
// of the panel rather than of a type: `GPDMA_CxBR1.BNDT` must be a multiple of
// the 4-byte source data width (RM0456 §17.8.14), and `BNDT` for a band is
// `w * H * 2`. That is a multiple of 4 for every `w` exactly when `H` is even.
// H = 142 today; a panel with an odd pixel height would make every band
// transfer raise `USEF` and paint nothing, so fail the BUILD instead.
const _: () = assert!(
    H % 2 == 0,
    "word-width GPDMA beats need an even pixel count per band; see gpdma::start_px"
);
// And `Band` must itself be a whole number of words, or `BANDS[1]` would start
// at a 2-byte-aligned address however the type is aligned.
const _: () = assert!(
    (STRIP_PX * 2) % 4 == 0,
    "every band buffer must be word-sized so the second one stays word-aligned"
);

/// How many band buffers the frame loop ping-pongs between.
///
/// TWO when the blit is DMA'd, because the whole point is to render band k+1
/// while band k is still on the wire — the DMA must own a buffer the
/// rasteriser is not writing. ONE otherwise: the polled `stream_chunk`
/// returns only when the band is fully clocked out, so there is nothing to
/// overlap and nothing to protect.
///
/// This REPLACES the old `STRIP` + `TXBUF` pair, at identical BSS (2 ×
/// 13,632 B). `TXBUF` existed to do two jobs — byte-swap each pixel for the
/// wire, and give the DMA a buffer stable across the next render. 16-bit SPI
/// frames (`lcd::spi_begin_px`) do the byte ordering in the shift register for
/// free, so only the second job was left, and a second buffer does that
/// without a copy. The 2.7 ms endian pass measured on glass is not optimised
/// here, it is deleted (#790).
///
/// THREE under DMA since #934 stage 2: the busy film renders a partial
/// frame's bands ahead of the wire and returns while the last ones stream in
/// the background (`present_bg`), so rendered bands wait their turn. Three
/// lets the render run 144 columns ahead of the wire: a 240-column window
/// (the setup film's mean) then costs ~0.4 ms more than four would, and the
/// signing film's ~100-column windows fit outright. Not four: with four the
/// real sign path (unlock, address, sign) left only 27,300 B of the 85,244 B
/// stack untouched (EVT, `stack-hwm`, 2026-10-19), too thin for paths not
/// yet measured; the polled path just cycles through them. 3 x 13,632 B.
#[cfg(feature = "ui-px-dma")]
const N_BANDBUF: usize = 3;
#[cfg(not(feature = "ui-px-dma"))]
const N_BANDBUF: usize = 1;

/// The band buffers. Single-threaded secure world; only the frame loop
/// touches them (the SysTick sampler never renders).
static mut BANDS: [Band; N_BANDBUF] = [const { Band([0; STRIP_PX]) }; N_BANDBUF];

// The per-band content DIGEST and its `SHOWN` table were deleted here by
// #780. They existed so an unchanged band was not streamed again, which was
// worth ~10 ms of a ~24 ms blit. A TE-synchronised frame cannot use them:
// the whole frame goes out under ONE `set_window` and the panel
// auto-increments, so skipping a band would place every later band at the
// wrong offset. Three things follow, and two are improvements:
//
//   * blit duration is now CONSTANT. That is the F-24 stage-E property --
//     "on a secret frame the SPI timing must not reveal which bands
//     changed" -- satisfied by construction rather than by remembering to
//     pass `force`, which is why `present_frame_ex` now ignores it. It also
//     removes the 64-bit digest of secret pixels that used to outlive the
//     frame in a `static`.
//   * `strip_digest` hashed all 60,776 pixels of every frame. Not computing
//     it is a render saving, not just a deletion.
//   * every frame now streams 121,552 B (24.31 ms) where a partial repaint
//     was ~13.7 ms. Invisible here: the frame is paced to two refresh
//     periods (32.0 ms) either way.

// ---- SysTick edge ring ------------------------------------------------------

/// Set for the duration of `present_frame_ex`. See the latch there.
static FRAME_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

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

    /// `DWT_CTRL.CYCCNTENA`.
    const CTRL_CYCCNTENA: u32 = 1;

    /// Arm the cycle counter. Idempotent apart from zeroing `CYCCNT`, which
    /// only costs one bad delta.
    pub fn enable() {
        DEMCR.modify(|v| v | (1 << 24)); // TRCENA
        DWT_LAR.write(0xC5AC_CE55);
        DWT_CYCCNT.write(0);
        DWT_CTRL.modify(|v| v | CTRL_CYCCNTENA);
    }

    /// The cycle counter, ARMING IT IF IT IS NOT RUNNING.
    ///
    /// SELF-ARMING ON PURPOSE. `enable()` used to be called from exactly one
    /// place — `run_flow` — so every other path that measured anything read a
    /// dead `CYCCNT` and reported **0**. That is what the ambient chooser's
    /// new overlay did on its first flash: `0/0/0`, with the frame times
    /// perfectly fine and simply unmeasured.
    ///
    /// This is the third time in one day that a helper which MUST be called
    /// was defined and then not called on a new path — after `Strip::x_hits`
    /// (defined, never called, 9x the raster work) and `lcd_te::init()`
    /// (called only from the bench probe, so every ordinary image skipped the
    /// TE wait forever). The first two were SUBTLY wrong and cost a flash
    /// each to find. So the fix here is structural rather than one more call
    /// site: a reader cannot obtain a cycle count from a stopped counter,
    /// because asking for one starts it.
    ///
    /// Costs one extra MMIO read per call, in `PROD_FORBIDDEN` bench code.
    #[inline]
    pub fn cycles() -> u32 {
        if DWT_CTRL.read() & CTRL_CYCCNTENA == 0 {
            enable();
        }
        DWT_CYCCNT.read()
    }

    /// The counter with NO arming check — for the ISR path only (#802), where
    /// the extra read would distort the measurement and the frame loop has
    /// already armed it.
    #[inline]
    pub fn cycles_raw() -> u32 {
        DWT_CYCCNT.read()
    }

    /// Format three cycle counts as TENTHS of a millisecond into `out`
    /// (`<a>/<b>/<c>`), returning the used length.
    ///
    /// The render split needs finer resolution than whole milliseconds: the
    /// whole render is ~11 ms, so a glyph share of 2 ms would print as "2" and
    /// a share of 0.4 ms as "0" — neither distinguishable enough to decide
    /// whether a DMA2D driver is worth building. Tenths give 0.1 ms steps and
    /// still fit the 3-digit cap up to 99.9 ms.
    pub fn format_tenths(out: &mut [u8; 24], a: u32, b: u32, c: u32) -> usize {
        format(out, a * 10, b * 10, c / (CPU_HZ_PER_MS / 10))
    }

    /// Format three PLAIN integers as `<a>/<b>/<c>` (≤ 3 digits each, clamped
    /// at 999). For counts and seconds, which are not cycle measurements and
    /// must not be divided by anything.
    pub fn format_raw(out: &mut [u8; 24], a: u32, b: u32, c: u32) -> usize {
        format(out, a.saturating_mul(CPU_HZ_PER_MS), b.saturating_mul(CPU_HZ_PER_MS), c)
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

/// The cycle counter, for the SysTick ISR's own accounting (#802).
///
/// Separate from `frametime::cycles()` because that one self-arms, and an
/// `if` plus an extra debug-block read on every ISR entry and exit would
/// itself distort the thing being measured. By the time SysTick is counting,
/// the frame loop has already armed the counter.
#[cfg(all(feature = "ui-px-frametime", feature = "stm32u585"))]
#[inline]
pub fn isr_cycles_now() -> u32 {
    frametime::cycles_raw()
}

/// Cycle split of one presented frame (bench overlay); zeros otherwise.
#[derive(Clone, Copy, Default)]
#[allow(dead_code)]
struct FrameCost {
    /// The frame reached the glass IN FULL. **Not instrumentation** — this is
    /// ungated and load-bearing, because #780 streams the whole frame under
    /// ONE `set_window` and the panel auto-increments through it. A band that
    /// stops short therefore does not lose one band: every LATER band lands
    /// at the wrong offset, so the glass shows a shifted, garbled frame.
    ///
    /// Before #790's bounded waits, those paths HUNG, and a hang is fail-safe
    /// — nothing gets signed off a frame nobody saw. Bounding them turned a
    /// hang into "one dropped frame", which is only safe if the caller
    /// actually knows the frame was dropped: otherwise `run_flow`'s
    /// present-before-arm latch (`presented_at`) counts a garbled `Confirm?`
    /// or returning ask as SHOWN, and those two screens sign from the moment
    /// they are shown (decision 2026-10-13, `HARDENING.md` §2.4) — arming the
    /// sign chord on something never legibly displayed.
    complete: bool,
    /// Every band the frame asked for reached the panel (full or partial).
    /// Ungated: the busy film's partial redraw (#934) trusts the glass to
    /// hold its last frame only when this was true.
    streamed: bool,
    render: u32,
    blit: u32,
    /// Per-class render breakdown (bench only) — see `RenderSplit`.
    #[cfg(feature = "ui-px-frametime")]
    split: pqsigner_ui_px::raster::RenderSplit,
    /// Cycles spent in `stream_dma_finish` INSIDE the band loop, i.e. the wire
    /// time the CPU could not hide behind a render. If the DMA ran at the full
    /// 40 MHz this should be 9 x (2.73 - 1.84) = ~8 ms; materially more means
    /// the transfer is not achieving line rate. Compare against `wire_last`,
    /// which isolates one band's wire with nothing overlapping it.
    #[cfg(feature = "ui-px-frametime")]
    dma_wait: u32,
    /// Cycles from the TE edge to the last pixel of the frame reaching TXDR —
    /// `T_write`, the quantity #780's tear-free bound is stated over
    /// (`< 31.40 ms`). Nothing else in this struct is that number: `blit` is
    /// CPU time in the blit section, `dma_wait` is only the part the CPU
    /// could not hide, and `period` includes the TE slack.
    #[cfg(feature = "ui-px-frametime")]
    stream: u32,
    /// Cycles of the LAST band's DMA alone. Nothing renders behind it, so this
    /// is one band's wire time uncontaminated by overlap.
    ///
    /// Its floor is **2.50 ms**, not 2.73: the last band is 44 columns wide,
    /// not `BAND_W` — `W` = 428 and 8 x 48 = 384 — so it is 12,496 B at
    /// 40 MHz. Reading it against the full-band figure would score a 2.73 ms
    /// result as "at line rate" when the wire is in fact 8% slow.
    ///
    /// Wire efficiency is therefore `2.50 / wire_last`, and the frame it
    /// predicts is `stream ~= 24.31 / efficiency` (24.31 ms being the whole
    /// 121,552 B frame at 40 MHz). So: 30 tenths = 83% = `stream` ~29.2;
    /// 35 = 71% = ~34.0, which is over #780's 31.40 ms tear bound.
    ///
    /// AND THE FLOOR PRINTS AS **24**, NOT 25. `frametime::format_tenths`
    /// TRUNCATES — `(cycles * 10) / 160_000` — and 2.4992 ms is 399,872
    /// cycles, which comes out 24.99 and prints 24. So a reading of 24 means
    /// `wire_last` is somewhere in [2.40, 2.50) ms, i.e. at line rate within
    /// the overlay's own 0.1 ms resolution; it is NOT below the floor.
    /// MEASURED on the EVT unit 2026-10-07: 24, with `stream` = 27.9 ms.
    #[cfg(feature = "ui-px-frametime")]
    wire_last: u32,
    /// Cycles blocked on the TE rising edge. This is the SLACK: large means
    /// the frame finished early and is waiting for the panel (good, and the
    /// period is refresh-bound), ~0 means we are right at the edge of the
    /// window and any extra work costs a whole refresh period.
    #[cfg(feature = "ui-px-frametime")]
    te_wait: u32,
    /// Cycles spinning after the TE edge until the beam has passed a partial
    /// window's first column (0 for a full frame).
    #[cfg(feature = "ui-px-frametime")]
    beam_wait: u32,
    /// Columns the frame streamed (`xend - xa`).
    #[cfg(feature = "ui-px-frametime")]
    cols: u32,
}

// ---- rendering ---------------------------------------------------------------

/// Render `frame` strip by strip and stream each strip that changed since
/// the panel last received it.
fn present_frame(frame: &Frame<'_>, font: &Font<'_>) -> FrameCost {
    present_frame_ex(frame, font, false)
}

/// [`present_frame`]; `force` streams every strip and records none (a frame
/// carrying secret cells: no strip is skipped on a digest of secret pixels,
/// and no such digest outlives the frame).
fn present_frame_ex(frame: &Frame<'_>, font: &Font<'_>, force: bool) -> FrameCost {
    present_frame_cols(frame, font, force, None, false)
}

// The panel's tear scanline (DCS 0x44 in `lcd_nv3007`): the beam's row at
// the TE edge.
use pqsigner_ui_px::stream::phase::TE_SCANLINE;

// ---- Starting a partial film frame from the TE stamps (#934 stage 1) -------
//
// The arithmetic (the start range, the wait for it) is
// `pqsigner_ui_px::stream::phase`, host-checked over every window and time
// since an edge, overflow included.
use pqsigner_ui_px::stream::phase::{start_window, REFRESH_CYC, STAMP_STALE_CYC};

/// Spin until the beam is inside [xa, xend)'s start range, from the TE
/// stamps. `false` (nothing waited for) when there is no fresh stamp or the
/// range is empty; the caller then synchronises on the edge as before.
/// Bounded: a stamp that goes stale while waiting ends it.
///
/// While the range is more than a band's render away, `work` may use the
/// wait (a background frame renders its next bands there, #934 stage 2); it
/// returns whether it did anything.
fn phase_start(xa: i32, xend: i32, work: &mut dyn FnMut() -> bool) -> bool {
    let Some((lo, hi)) = start_window(xa, xend) else { return false };
    loop {
        let Some(edge) = crate::hw::lcd_te::last_edge() else { return false };
        let since = crate::hw::lcd_te::cycles().wrapping_sub(edge);
        if since > STAMP_STALE_CYC {
            return false;
        }
        // Until the range opens, in this refresh or the next.
        let Some(wait) = pqsigner_ui_px::stream::phase::wait(since, lo, hi) else {
            return true;
        };
        if wait > BAND_RENDER_CYC && work() {
            continue;
        }
        core::hint::spin_loop();
    }
}

/// A band's render with margin (~1.0-1.2 ms measured on the EVT), so work
/// done while waiting for the start range never pushes the start past it.
const BAND_RENDER_CYC: u32 = 240_000;

/// [`present_frame_ex`] over only the bands covering landscape columns
/// `cols` (inclusive), when given: the busy film's partial redraw (#934,
/// scoped to `film_tick`, owner 2026-10-16). Everything outside those bands
/// stays as the glass already shows it, so the caller must know it is
/// unchanged ([`pqsigner_ui_px::damage`]). A partial frame is never
/// `complete`: it does not count as "this screen was presented".
fn present_frame_cols(frame: &Frame<'_>, font: &Font<'_>, _force: bool, cols: Option<(i32, i32)>, bg: bool) -> FrameCost {
    // `complete` stays false through every early exit below: the latch, the
    // band-0 `Strip::new` failure, and the mid-loop `break`.
    let mut cost = FrameCost::default();

    // RE-ENTRANCY LATCH. The band loop below holds `&mut BANDS` across a
    // render that runs while GPDMA is streaming, and `[profile.release]`
    // keeps `overflow-checks = true`, so a panic inside that window is live in
    // shipping images. The #484 panic handler paints a fatal screen, which
    // under `ui-px` reaches `paint_legacy` and back into here — taking a
    // SECOND `&mut` to the same static while a DMA channel reads it. The
    // latch turns that into an early return; the panic handler's own
    // `paint_legacy` then falls through to the glyph blitter, which touches
    // neither this static nor the DMA.
    //
    // A busy-film frame still streaming in the background holds the latch
    // and the band buffers on purpose (`present_bg`): collect it first —
    // waiting for its stream, or aborting it — so nothing is skipped behind
    // it. A panic inside a frame's own render (no background frame yet)
    // still finds the latch set and returns, as before.
    film_reap(true);
    if FRAME_IN_FLIGHT.swap(true, Ordering::Acquire) {
        return cost;
    }
    // Clears the latch AND zeroizes the band buffers on EVERY exit, including
    // the `return` in the band-0 branch below and any future one. The wipe
    // used to be a statement at the end of the function, which the band-0
    // `Strip::new` failure skipped — unreachable, but positional rather than
    // structural, and the sibling branch inside the loop needs a comment
    // saying "MUST NOT return" precisely because of that asymmetry.
    struct FrameGuard;
    impl Drop for FrameGuard {
        fn drop(&mut self) {
            wipe_scratch();
            FRAME_IN_FLIGHT.store(false, Ordering::Release);
        }
    }
    let _guard = FrameGuard;

    // SAFETY: single-threaded frame loop; the SysTick sampler never touches
    // the band buffers (same discipline as `splash_test::FB`), and the latch
    // above excludes the one re-entrant caller (the panic handler).
    let bands = unsafe { &mut *core::ptr::addr_of_mut!(BANDS) };

    // ---- band 0 BEFORE the TE wait -------------------------------------
    // So the stream starts on the edge rather than one render after it: the
    // whole point of the wait is the phase it buys.
    // The band-aligned window: `xa` is a band's first column, `xend` one past
    // the last band's (the last band is 44 columns: W = 428).
    let (xa, xend) = match cols {
        Some((c0, c1)) => {
            let a = (c0.clamp(0, W - 1) / BAND_W) * BAND_W;
            let e = ((c1.clamp(0, W - 1) / BAND_W) + 1) * BAND_W;
            (a, e.min(W))
        }
        None => (0, W),
    };
    let w0 = BAND_W.min(xend - xa);
    #[cfg(feature = "ui-px-frametime")]
    let t0 = frametime::cycles();
    {
        let Some(mut strip) = Strip::new(xa, w0, &mut bands[0].0[..]) else {
            return cost;
        };
        render_band(frame, font, &mut strip, &mut cost);
    }
    #[cfg(feature = "ui-px-frametime")]
    {
        cost.render = cost.render.wrapping_add(frametime::cycles().wrapping_sub(t0));
    }

    // ---- phase-lock, then one monotone sweep ---------------------------
    // 62.5 Hz measured => T = 16.0 ms. The sweep is SLOWER than the beam, and
    // that is fine as long as it finishes before the beam's next pass laps it:
    // it trails through refresh N (which shows all-old, no composite) and the
    // beam wraps while the write pointer is mid-frame, so refresh N+1 shows
    // all-new.
    //
    // The bound is NOT `2 x T_refresh`. The panel's tear scanline is
    // programmed to 16 (`lcd_nv3007.rs`, DCS 0x44 = `[0x00, 0x10]`), so at the
    // TE edge the beam is already 16 of 428 rows in and those rows come off
    // the allowance: solving `16 + R*t - 428 = (428/Tw)*t` for a root below
    // `Tw` gives TEAR-FREE IFF `Tw < 31.40 ms` (conservative — no V-blank
    // credit, since the panel datasheet is not in this repo). The other
    // failure modes are NEAR-EQUAL speed (a full frame matches the beam at
    // ~41 Hz) and refresh above ~81 Hz; 62.5 Hz is clear of both.
    //
    // `cost.stream` measures exactly `Tw`, because that bound is the thing
    // this frame has to satisfy and nothing else in `FrameCost` is it (#790).
    // MEASURED on the EVT screen unit 2026-10-07: Tw = 27.9 ms against the
    // 31.40 ms bound, so the sweep is inside its own precondition by 3.5 ms.
    // Before #790 it was ~31.8 ms by arithmetic -- possibly OVER, with the
    // composite at x ~ 417, the 11 rightmost of 428 columns, where the hero
    // animation's +-95 px swing never reaches. Do not let Tw grow without
    // re-reading this number.
    //
    // Bound: ~5 cycles per poll, so 2,000,000 is ~62 ms at 160 MHz — four TE
    // periods, and it latches dead on the first miss so a panel-less board
    // pays it once. A frozen counter cannot stall this: it counts ITERATIONS.
    #[cfg(feature = "ui-px-frametime")]
    let t_te = frametime::cycles();
    // The busy film's partial frames, while the TE edges are stamped (#934
    // stage 1): start when the beam is inside the window's start range,
    // without waiting for an edge. Anything else, or no fresh stamp, takes
    // the edge-synchronised path below exactly as before.
    //
    // A background frame (`bg`) renders its next bands into the free buffers
    // while it waits, rather than spinning: `pre` bands are then ready, the
    // next starting at column `pre_x`.
    let mut pre = 1usize;
    let mut pre_x = xa + w0;
    let phased = cols.is_some() && {
        let mut work = || {
            if !bg || pre >= N_BANDBUF || pre_x >= xend {
                return false;
            }
            let w = BAND_W.min(xend - pre_x);
            let Some(mut strip) = Strip::new(pre_x, w, &mut bands[pre].0[..]) else {
                return false;
            };
            render_band(frame, font, &mut strip, &mut cost);
            pre_x += w;
            pre += 1;
            true
        };
        phase_start(xa, xend, &mut work)
    };
    if !phased {
        let synced = crate::hw::lcd_te::sync_to_scanout(2_000_000);
        let _ = synced;
    }
    #[cfg(feature = "ui-px-frametime")]
    let t_edge = frametime::cycles();
    #[cfg(feature = "ui-px-frametime")]
    {
        cost.te_wait = t_edge.wrapping_sub(t_te);
    }

    // ONE window for the whole frame. The panel auto-increments across all
    // 428 native rows, so the nine band transfers below are a single
    // continuous stream and nothing may send a command (DC low) between them.
    // A window that starts below the tear scanline: the stream must start
    // BEHIND the beam, as a full frame does, or the beam (faster than the
    // wire) catches the write pointer inside the window during this refresh
    // and shows a split. So wait until the beam has passed `xa`:
    // (xa - 16) rows at 26.75 rows/ms (62.5 Hz, 428 rows), rounded up, + 1 ms
    // for the millisecond clock's granularity. The window then trails the
    // beam through this refresh and is all-new in the next, which it laps
    // only after (delay + (xend - xa) / 15.3 rows/ms) < 16 + (xend - 16) /
    // 26.75, true for every window here (the full sweep is the worst case and
    // is the #780 bound). Full frames (xa = 0) start at once, as before.
    // (`phase_start` has already placed a phased frame inside that range.)
    if !phased && xa > TE_SCANLINE {
        let wait_ms = ((xa - TE_SCANLINE) as u32 * 1000).div_ceil(26_750) + 1;
        let t = timeout::now();
        while timeout::now().wrapping_sub(t) < wait_ms {
            core::hint::spin_loop();
        }
    }
    #[cfg(feature = "ui-px-frametime")]
    {
        cost.beam_wait = frametime::cycles().wrapping_sub(t_edge);
        cost.cols = (xend - xa) as u32;
    }
    lcd::set_window(0, xa as u16, (H - 1) as u16, (xend - 1) as u16);
    lcd::stream_open();

    // The busy film's partial frames stream in the background (#934 stage
    // 2): the bands are rendered here ahead of the wire and queued, the DMA
    // interrupt starts each one, and this returns while the last bands are
    // still going out. The latch and the band buffers stay held until
    // `film_reap` collects the frame; on any failure the stream is aborted
    // and `_guard` wipes and releases as for every other frame.
    #[cfg(feature = "ui-px-dma")]
    if bg {
        if present_bg(frame, font, bands, xa, xend, (pre, pre_x), &mut cost) {
            core::mem::forget(_guard);
            FILM_BG.store(true, Ordering::Release);
            // Provisional: `film_reap` forgets the glass if the stream then
            // fails. A partial frame is never `complete`.
            cost.streamed = true;
        } else {
            lcd::async_abort();
        }
        return cost;
    }
    #[cfg(not(feature = "ui-px-dma"))]
    let _ = (bg, pre, pre_x);

    // The buffer the wire is currently reading. Bands alternate, so the
    // rasteriser always writes the OTHER one (`N_BANDBUF` = 1 collapses this
    // to a single buffer, which is correct because the polled blit is
    // synchronous).
    let mut cur = 0usize;
    let mut ok = true;
    #[cfg(feature = "ui-px-dma")]
    let mut dma_pending = lcd::stream_dma_start(&bands[0].0[..(w0 * H) as usize]);
    #[cfg(feature = "ui-px-dma")]
    {
        // `false` for a non-empty band is a REFUSAL (over the BNDT cap, or an
        // odd pixel count), not "nothing to send".
        ok &= dma_pending;
    }
    #[cfg(not(feature = "ui-px-dma"))]
    {
        ok &= lcd::stream_chunk(&bands[0].0[..(w0 * H) as usize]);
    }

    let mut x0 = xa + w0;
    while x0 < xend {
        let w = BAND_W.min(xend - x0);
        let nxt = (cur + 1) % N_BANDBUF;
        #[cfg(feature = "ui-px-frametime")]
        let t0 = frametime::cycles();
        {
            // Renders UNDER the previous band's DMA — that overlap is what
            // keeps the sweep continuous. Band render is ~1.9 ms against
            // ~2.7 ms of wire, so the wire never starves.
            let Some(mut strip) = Strip::new(x0, w, &mut bands[nxt].0[..]) else {
                // MUST NOT `return`: the drain and `stream_close` below are
                // the only exit that leaves the panel out of mid-stream.
                ok = false;
                break;
            };
            render_band(frame, font, &mut strip, &mut cost);
        }
        #[cfg(feature = "ui-px-frametime")]
        let t1 = frametime::cycles();
        #[cfg(feature = "ui-px-dma")]
        {
            if dma_pending {
                #[cfg(feature = "ui-px-frametime")]
                let t_w = frametime::cycles();
                ok &= lcd::stream_dma_finish().is_ok();
                #[cfg(feature = "ui-px-frametime")]
                {
                    cost.dma_wait = cost.dma_wait.wrapping_add(frametime::cycles().wrapping_sub(t_w));
                }
            }
            if !ok {
                // STOP THE SWEEP. The panel auto-increments through one
                // frame-wide window, so once a band has stopped short every
                // later band lands at the wrong offset — continuing just
                // paints more garbage and spends more wire. `x0 < W` on this
                // path, so `complete` is false either way; breaking only
                // makes the glass less wrong and the recovery quicker.
                break;
            }
            dma_pending = lcd::stream_dma_start(&bands[nxt].0[..(w * H) as usize]);
            ok &= dma_pending;
        }
        #[cfg(not(feature = "ui-px-dma"))]
        {
            ok &= lcd::stream_chunk(&bands[nxt].0[..(w * H) as usize]);
        }
        #[cfg(feature = "ui-px-frametime")]
        {
            let t2 = frametime::cycles();
            cost.render = cost.render.wrapping_add(t1.wrapping_sub(t0));
            cost.blit = cost.blit.wrapping_add(t2.wrapping_sub(t1));
        }
        cur = nxt;
        x0 += w;
    }

    #[cfg(feature = "ui-px-dma")]
    if dma_pending {
        // Counted twice, on purpose. Into `dma_wait` because it is wire the
        // CPU blocked on, and into `wire_last` ALONE because this band has
        // nothing rendering behind it: it is the one uncontaminated
        // single-band wire measurement in the frame, self-checking against
        // its 2.73 ms theoretical floor (13,632 B at 40 MHz). `stream` close
        // to `9 * wire_last` means the sweep is continuous and wire-bound;
        // materially more means it is stalling between bands (#790).
        #[cfg(feature = "ui-px-frametime")]
        let t_w = frametime::cycles();
        ok &= lcd::stream_dma_finish().is_ok();
        #[cfg(feature = "ui-px-frametime")]
        {
            let d = frametime::cycles().wrapping_sub(t_w);
            cost.dma_wait = cost.dma_wait.wrapping_add(d);
            cost.wire_last = d;
        }
    }
    lcd::stream_close();
    cost.complete = ok && cols.is_none() && x0 >= W;
    cost.streamed = ok && x0 >= xend;
    #[cfg(feature = "ui-px-frametime")]
    {
        cost.stream = frametime::cycles().wrapping_sub(t_edge);
    }
    // `_guard` wipes the band buffers and clears the latch here.
    cost
}

/// Queue a partial frame's bands for the background stream (#934 stage 2):
/// the first `pre.0` bands are already rendered into `bands[0..pre.0]` (band
/// 0, plus any rendered while waiting for the start range), the next one
/// starting at column `pre.1`; render each later band into buffer
/// `k % N_BANDBUF` once the band that last used it has left the wire, and
/// queue it. `false` if anything refused or stalled (the caller aborts).
#[cfg(feature = "ui-px-dma")]
fn present_bg(
    frame: &Frame<'_>,
    font: &Font<'_>,
    bands: &mut [Band; N_BANDBUF],
    xa: i32,
    xend: i32,
    pre: (usize, i32),
    cost: &mut FrameCost,
) -> bool {
    let total = (xend - xa + BAND_W - 1) / BAND_W;
    if !lcd::async_begin(total as u8) {
        return false;
    }
    let mut x = xa;
    for band in bands.iter().take(pre.0) {
        let w = BAND_W.min(xend - x);
        if !lcd::async_queue(&band.0[..(w * H) as usize]) {
            return false;
        }
        x += w;
    }
    if x != pre.1 {
        return false;
    }
    let mut x0 = pre.1;
    let mut k = pre.0;
    while x0 < xend {
        let w = BAND_W.min(xend - x0);
        let buf = k % N_BANDBUF;
        // The buffer's previous band (k - N_BANDBUF) must have left the wire.
        // Bounded like the drain; a stream that died stops it at once.
        #[cfg(feature = "ui-px-frametime")]
        let t_w = frametime::cycles();
        let mut spins = 0u32;
        while k >= usize::from(lcd::async_sent()) + N_BANDBUF {
            if !lcd::async_busy() || spins >= 4_000_000 {
                return false;
            }
            spins += 1;
            core::hint::spin_loop();
        }
        #[cfg(feature = "ui-px-frametime")]
        {
            cost.dma_wait = cost.dma_wait.wrapping_add(frametime::cycles().wrapping_sub(t_w));
        }
        #[cfg(feature = "ui-px-frametime")]
        let t0 = frametime::cycles();
        {
            let Some(mut strip) = Strip::new(x0, w, &mut bands[buf].0[..]) else {
                return false;
            };
            render_band(frame, font, &mut strip, cost);
        }
        #[cfg(feature = "ui-px-frametime")]
        {
            cost.render = cost.render.wrapping_add(frametime::cycles().wrapping_sub(t0));
        }
        if !lcd::async_queue(&bands[buf].0[..(w * H) as usize]) {
            return false;
        }
        x0 += w;
        k += 1;
    }
    true
}

/// A busy-film frame is streaming in the background, or has finished but not
/// been collected: it holds `FRAME_IN_FLIGHT` and the band buffers.
#[cfg(feature = "ui-px-dma")]
static FILM_BG: AtomicBool = AtomicBool::new(false);

/// Collect a background film frame (`present_bg`): once its stream is done
/// (waiting for it when `wait`, aborting it if it stalls), wipe the band
/// buffers and release the latch; if the stream did not reach the panel in
/// full, forget what the film thinks the glass holds. Returns whether no
/// frame is outstanding now.
#[cfg(feature = "ui-px-dma")]
fn film_reap(wait: bool) -> bool {
    if !FILM_BG.load(Ordering::Acquire) {
        return true;
    }
    if lcd::async_busy() {
        if !wait {
            return false;
        }
        let _ = lcd::async_drain();
    }
    if !lcd::async_ok() {
        // SAFETY: single-threaded driver state, never touched from an ISR.
        unsafe {
            *core::ptr::addr_of_mut!(FILM_SIGS) = (pqsigner_ui_px::damage::FrameSigs::UNKNOWN, 0);
        }
    }
    wipe_scratch();
    FILM_BG.store(false, Ordering::Release);
    FRAME_IN_FLIGHT.store(false, Ordering::Release);
    true
}

#[cfg(not(feature = "ui-px-dma"))]
fn film_reap(_wait: bool) -> bool {
    true
}

/// Whether the film's partial frames may stream in the background. Always
/// under DMA, except that the dev bench (`ui-px-film-bench`) alternates it.
#[cfg(feature = "ui-px-film-bench")]
static FILM_BG_ON: AtomicBool = AtomicBool::new(true);

fn film_bg_allowed() -> bool {
    #[cfg(feature = "ui-px-film-bench")]
    {
        FILM_BG_ON.load(Ordering::Relaxed)
    }
    #[cfg(not(feature = "ui-px-film-bench"))]
    {
        cfg!(feature = "ui-px-dma")
    }
}

/// Zeroize EVERY band buffer once the frame is on the glass.
///
/// REQUIRED, not hygiene. Seed-word pixels from `Font::blit_secret_run`
/// transit the band buffers, and the 2026-09-24 adversarial review flagged
/// that they are never cleared — judging it unexploitable only "by layout
/// accident: the loop renders bands in ascending y, so STRIP is left holding
/// the y=128..142 band,
/// while the words grid's lowest row is WORDS_ROWS[3]=110 ... Nothing enforces
/// that relationship", and predicting it "becomes a real secret-retention bug
/// the moment the words-grid layout changes".
///
/// Vertical bands broke that accident. The last band is now x in [384, 428)
/// spanning EVERY row, and the seed grid's second word column starts at
/// `WORDS_COLS[1].1 = 282` (`rows.rs:120`), so a long word at the 22 px tier
/// reaches well past 384. The residue the review called latent became live, so
/// the wipe it prescribed is now load-bearing.
///
/// The WHOLE buffer, not the `w * H` the band used. `render_strip` clears only
/// `w * H` pixels, and the last band is 44 columns wide (W = 428, 8 x 48 =
/// 384) against a 48-column buffer — so 568 pixels of the tail are never
/// touched by that clear and still hold an EARLIER band's ink. Which band's
/// depends on the buffer rotation (two buffers until #934 stage 2: bands
/// 0,2,4,6,8 in `BANDS[0]`; three since, under DMA: bands 0,3,6). Zeroizing
/// the array rather than the used prefix is what makes that irrelevant.
///
/// A busy-film frame streaming in the background is wiped when `film_reap`
/// collects it, after its last band has left the wire, not when its
/// presenter returns.
///
/// Unconditional rather than gated on a "this frame was secret" flag: that is
/// the same kind of remembered relationship the review objected to. The cost
/// is one clear of a buffer `render_strip` already clears nine times a frame
/// (~0.085 ms per buffer against a 24.31 ms wire), so there is nothing to
/// buy by being clever. Iterating `BANDS` rather than naming each buffer is
/// deliberate: adding one would otherwise leave it un-wiped, silently.
fn wipe_scratch() {
    // SAFETY: single-threaded frame loop, and every transfer that could read
    // these buffers has been drained above (`stream_dma_finish`) before the
    // stream was closed.
    unsafe {
        for b in (*core::ptr::addr_of_mut!(BANDS)).iter_mut() {
            b.0.zeroize();
        }
    }
}

/// Rasterise one band, with or without the per-class cost split.
fn render_band(frame: &Frame<'_>, font: &Font<'_>, strip: &mut Strip<'_>, cost: &mut FrameCost) {
    let _ = cost;
    #[cfg(not(feature = "ui-px-frametime"))]
    render_strip(frame, font, strip);
    #[cfg(feature = "ui-px-frametime")]
    pqsigner_ui_px::raster::render_strip_split(frame, font, strip, frametime::cycles, &mut cost.split);
}

/// Build the display list for `anim` and present it. `overlay` is the bench
/// frame-time text (top-left, 16 px), `None` in every non-bench build; `split`
/// is the optional second line beneath it (per-class render breakdown).
fn build_and_present(
    anim: &Anim,
    marks: &Marks<'_>,
    font: &Font<'_>,
    overlay: Option<&[u8]>,
    split: Option<&[u8]>,
    wire: Option<&[u8]>,
) -> FrameCost {
    let mut frame = Frame::new();
    #[cfg(feature = "ui-px-frametime")]
    let t0 = frametime::cycles();
    anim.build(marks, font, &mut frame);
    // NOTE for the render split: these overlay runs are themselves `Item::Text`
    // and so land in the `glyphs` bucket. They are ~8-12 glyphs per line against
    // a caption of ~20, so they inflate `glyphs` somewhat. Stated rather than
    // corrected: the decision this measurement feeds (is glyph work a big
    // enough share to be worth a DMA2D driver?) tolerates that, and a marker
    // field on `Item` to exclude them would cost more than it buys.
    if let Some(text) = split {
        use pqsigner_ui_px::font::{Align, TextRun, TierId};
        use pqsigner_ui_px::raster::{Item, Rgb};
        frame.push(Item::Text {
            run: TextRun {
                text,
                tier: TierId::regular(16),
                x: 40,
                y: 34,
                align: Align::Left,
                baseline: true,
                ls_q6: 0,
                alpha: 255,
            },
            color: Rgb::WHITE,
        });
    }
    // Third line (green): the WIRE, in tenths --- stream / wire_last /
    // te_wait.
    //   stream    = TE edge -> last pixel at TXDR. MUST read < 314 (31.40 ms)
    //               or the frame is outside #780's tear-free bound.
    //   wire_last = one band's wire with nothing overlapping it. The LAST
    //               band is 44 cols, not 48, so its floor is 2.4992 ms --
    //               and the formatter TRUNCATES, so the floor PRINTS AS 24.
    //               24 therefore means line rate, not "below the floor".
    //               Reading it against the 48-col 2.73 ms figure would score
    //               an 8%-slow wire as perfect.
    //   te_wait   = the slack before a whole refresh period is lost.
    if let Some(text) = wire {
        use pqsigner_ui_px::font::{Align, TextRun, TierId};
        use pqsigner_ui_px::raster::{Item, Rgb};
        frame.push(Item::Text {
            run: TextRun {
                text,
                tier: TierId::regular(16),
                x: 40,
                y: 52,
                align: Align::Left,
                baseline: true,
                ls_q6: 0,
                alpha: 255,
            },
            color: Rgb::GREEN,
        });
    }
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
        // Zero the INSTRUMENTATION, keep the VERDICT. `complete` is not a
        // counter — `paint_legacy` and the sign-gesture arming both read it —
        // so a blanket `FrameCost::default()` here would make it false in
        // every build WITHOUT `ui-px-frametime`, i.e. in the shipping-shaped
        // one: `presented_at` would never latch and `mark_rendered` would
        // never run, so the chord would never arm. The bench config would
        // have looked perfect throughout.
        cost = FrameCost {
            complete: cost.complete,
            streamed: cost.streamed,
            ..FrameCost::default()
        };
    }
    cost
}

/// Paint a legacy 16×4 page through the pixel engine (the `Display::flush`
/// path under `ui-px`, so every status / progress / PIN screen shares the
/// design's typography).
///
/// Returns `false` when the NS-resident atlas does not hash to
/// `ATLAS_ROOT`, so the caller paints with the SECURE-RESIDENT glyph
/// blitter instead — the device stays readable, the pixel dialogs refuse.
///
/// This re-verifies on EVERY call (`assets::atlas_verified`), not once at
/// boot. It has to: `ui::lcd::Display::flush` routes every legacy 16x4
/// page — `ui::confirm`'s pages among them — through here, so a cached
/// verdict would let a tampered NS atlas paint a consent screen.
pub fn paint_legacy(rows: &[[u8; crate::ui::DISPLAY_COLS]; crate::ui::DISPLAY_ROWS]) -> bool {
    // Any legacy paint ends a running film (an error status after the
    // sign started, for instance).
    film_abort();
    let Some(atlas) = assets::atlas_verified() else {
        return false;
    };
    // The legacy glyph blitter may have painted between calls.
    let s = Screen::legacy(rows);
    let anim = Anim::new(&s, 0, timeout::now());
    // RETURNS THE TRUTH. `flush()` skips the glyph blitter only when this
    // says the page is on the glass. Two ways it is not, and both reach here
    // from the #484 panic handler: the re-entrancy latch (a panic landed
    // INSIDE `present_frame_ex`, so this call paints nothing at all), and a
    // band that stopped short. Returning `true` regardless would make the
    // fatal "Secrets wiped / Power-cycle" screen silently disappear in
    // exactly the situation it exists for.
    build_and_present(&anim, &atlas.marks(), &atlas.font(), None, None, None).complete
}

/// Clear the panel (before the legacy glyph blitter paints again).
pub fn clear() {
    lcd::fill_screen(0);
}

/// Play an ending (the film-less cancel resolve, or the running film's
/// landing) through its result hold and leave the resting frame on the glass.
pub fn show_ending(e: Ending) {
    film_resolve(e);
}

// ---- the signing film ------------------------------------------------------
//
// The qubit loading film plays AROUND `crypto::c10_sign_verified*`: it is
// started by the handler before the sign, paced by the signer's opaque
// `fn(u8)` progress hook (`film_tick`: one frame at most per `FRAME_PERIOD_MS`,
// never more than one frame of delay), and resolved by the handler at the
// existing post-release site (`film_resolve(Signed)`) or on the decline path.
// The hook returns unit and captures nothing, so the film cannot alter, delay
// past one frame, or skip any gate of the FI chain; the film state lives
// here, never in `crypto.rs`. Frames are timed off the S-only SysTick clock.

/// A film is running (started and not yet resolved).
static FILM_LIVE: AtomicBool = AtomicBool::new(false);
/// The film's runtime + the wall-clock ms of its last presented frame,
/// valid only while `FILM_SET` is true. Single-threaded driver state:
/// touched only from the sign handler's thread of execution, never from an
/// ISR.
///
/// Zeroed `MaybeUninit` plus a flag rather than `Option<(Anim, u32)>`: the
/// `Option`'s `None` is not all-zero bits, so it was stored as a 736-byte
/// initialiser in flash (`.data`); a zeroed static lands in `.bss` (measured
/// 2026-10-14).
static mut FILM: MaybeUninit<(Anim, u32)> = MaybeUninit::zeroed();
/// `FILM` holds a film: set by `film_start_with` after the write, cleared by
/// `film_resolve` (which moves it out) and `film_abort`.
static FILM_SET: AtomicBool = AtomicBool::new(false);
// `film_abort` forgets the film by clearing `FILM_SET`; that is only sound
// while the film owns nothing that needs dropping.
const _: () = assert!(!core::mem::needs_drop::<(Anim, u32)>());

/// The family the next film / ending dresses in: its disc and its two ending
/// captions. Single-threaded driver state (set by the sign handler's pixel
/// route, read by the film, reset once a film lands).
#[derive(Clone, Copy)]
struct FilmLook {
    look: pqsigner_ui_px::Look,
    signed: &'static [u8],
    declined: &'static [u8],
    failed: &'static [u8],
}

const FILM_LOOK_SAFE: FilmLook = FilmLook {
    look: pqsigner_ui_px::Look::SAFE,
    signed: b"SIGNED SAFE TX",
    declined: b"SAFE TX DECLINED",
    failed: b"SAFE TX FAILED",
};

static mut FILM_LOOK: FilmLook = FILM_LOOK_SAFE;

/// Dress the next film / ending in a family's disc and captions (e.g.
/// `Look::plain(Icon::Eth)`, `b"TRANSACTION CONFIRMED"`, `b"TRANSACTION DECLINED"`).
/// Reset to the Safe look when the film lands, so a stale look never leaks
/// into the next dialog. A caption that is not printable ASCII or longer
/// than a line falls back to the Safe captions (the builder refuses it).
pub fn set_film_look(
    look: pqsigner_ui_px::Look,
    signed: &'static [u8],
    declined: &'static [u8],
    failed: &'static [u8],
) {
    // SAFETY: single-threaded driver state (no ISR touches it).
    unsafe {
        *core::ptr::addr_of_mut!(FILM_LOOK) = FilmLook { look, signed, declined, failed };
    }
}

fn reset_film_look() {
    // SAFETY: single-threaded driver state (no ISR touches it).
    unsafe {
        *core::ptr::addr_of_mut!(FILM_LOOK) = FILM_LOOK_SAFE;
    }
}

/// The centred status screen the film plays over: the family's disc, the
/// three ending captions as lines 0 / 1 / 2 — signed, declined, failed
/// (`scene::ending_captions`).
fn film_screen() -> Screen {
    // SAFETY: single-threaded driver state; copied out.
    let fl = unsafe { *core::ptr::addr_of!(FILM_LOOK) };
    let build = |fl: FilmLook| {
        pqsigner_ui_px::ScreenBuilder::status(b"SIGN", fl.look.icon, b"", pqsigner_ui_px::State::Awaiting, pqsigner_ui_px::ResultMark::None)
            .look_tint(fl.look)
            .line(fl.signed, pqsigner_ui_px::Weight::Regular)
            .line(fl.declined, pqsigner_ui_px::Weight::Regular)
            .line(fl.failed, pqsigner_ui_px::Weight::Regular)
            .finish()
    };
    build(fl).or_else(|_| build(FILM_LOOK_SAFE)).unwrap_or(Screen::BLANK)
}

/// Start the loading film: the disc seeds into the qubits and the orbit
/// loops until [`film_resolve`]. Without a verified atlas nothing plays
/// (and the ticks stay no-ops).
pub fn film_start() {
    film_start_with(&film_screen());
}

/// Start the loading film on `s` — the busy look of port step 4: `s` is a
/// status record whose disc seeds the qubits and whose caption breathes
/// over the orbit (GENERATING KEYS, WIPING, …).
pub fn film_start_with(s: &Screen) {
    let Some(atlas) = assets::atlas_verified() else {
        return;
    };
    film_reap(true);
    // Stamp TE edges while the film runs (off again at `film_resolve` /
    // `film_abort`), and forget the previous film's window.
    crate::hw::lcd_te::stamps(true);
    FILM_WIN.store(0, Ordering::Relaxed);
    #[cfg(feature = "ui-px-film-gaps")]
    film_gaps_begin();
    let now = timeout::now();
    #[cfg(all(feature = "stack-hwm", target_arch = "arm"))]
    {
        FILM_BEGAN.0.store(now, Ordering::Relaxed);
        FILM_BEGAN.1.store(lcd::glass_writes(), Ordering::Relaxed);
    }
    let mut anim = Anim::new(s, 0, now);
    anim.film_start(now);
    let _ = present_film(&anim, &atlas.marks(), &atlas.font(), true);
    #[cfg(feature = "ui-px-film-gaps")]
    super::film_gaps::frame(timeout::now());
    // SAFETY: `FILM` is single-threaded driver state (no ISR touches it) and
    // this is the only writer while `FILM_LIVE` is false.
    unsafe {
        (*core::ptr::addr_of_mut!(FILM)).write((anim, now));
    }
    FILM_SET.store(true, Ordering::Relaxed);
    FILM_LIVE.store(true, Ordering::Relaxed);
}

/// What the glass holds after the last film frame, for the next one's
/// partial redraw: the frame's item fingerprints and the panel write count
/// right after it. `FrameSigs::UNKNOWN` (or a moved count: anything else
/// drew) forces a full frame. Single-threaded driver state, never touched
/// from an ISR.
static mut FILM_SIGS: (pqsigner_ui_px::damage::FrameSigs, u32) = (pqsigner_ui_px::damage::FrameSigs::UNKNOWN, 0);

/// Whether the film may redraw partially. Always; the dev bench
/// (`ui-px-film-bench`) can switch it off to compare. Measured on the EVT
/// 2026-10-16: 20.6 fps partial against 18.2 full, no tearing seen.
#[cfg(feature = "ui-px-film-bench")]
static FILM_PARTIAL: AtomicBool = AtomicBool::new(true);

fn film_partial_allowed() -> bool {
    #[cfg(feature = "ui-px-film-bench")]
    {
        FILM_PARTIAL.load(Ordering::Relaxed)
    }
    #[cfg(not(feature = "ui-px-film-bench"))]
    {
        true
    }
}

/// The band-aligned window `present_frame_cols` streams for columns
/// `c0..=c1`, packed `xa << 16 | xend` for [`FILM_WIN`].
fn band_window(c0: i32, c1: i32) -> u32 {
    let a = (c0.clamp(0, W - 1) / BAND_W) * BAND_W;
    let e = (((c1.clamp(0, W - 1) / BAND_W) + 1) * BAND_W).min(W);
    (a as u32) << 16 | e as u32
}

/// The window of the film's latest partial frame (`xa << 16 | xend`), 0 for
/// none yet. The next frame's window is usually close to it: the orbit
/// moves a few columns per frame.
static FILM_WIN: AtomicU32 = AtomicU32::new(0);

/// Build plus the first band's render, before a partial frame can start
/// streaming: ~2 ms on the EVT (1.0 ms other + ~1.1 ms per band, measured
/// 2026-10-19).
const FILM_LEAD_CYC: u32 = 320_000;

/// How long a frame may spin for its start range rather than wait for a
/// later tick: 2 ms.
const FILM_SPIN_OK_CYC: u32 = 320_000;

/// Whether a film frame may start at this tick (#934 stage 1). With the TE
/// stamps on, a partial frame should start when the beam is in its window's
/// start range; a tick that would have to spin longer than
/// `FILM_SPIN_OK_CYC` for it returns, and a later tick draws the frame.
/// Without stamps (or before the first partial frame) every due tick draws,
/// as before.
fn film_phase_ok() -> bool {
    // The time between ticks, for guessing where the next one lands.
    let now = crate::hw::lcd_te::cycles();
    let dt = now.wrapping_sub(FILM_TICK_AT.swap(now, Ordering::Relaxed)).min(REFRESH_CYC);
    let ema = FILM_TICK_DT.load(Ordering::Relaxed);
    let dt = (ema * 3 + dt) / 4;
    FILM_TICK_DT.store(dt, Ordering::Relaxed);

    let Some(edge) = crate::hw::lcd_te::last_edge() else { return true };
    let win = FILM_WIN.load(Ordering::Relaxed);
    if win == 0 {
        return true;
    }
    let Some((lo, hi)) = start_window((win >> 16) as i32, (win & 0xFFFF) as i32) else {
        return true;
    };
    let since = now.wrapping_sub(edge);
    if since > STAMP_STALE_CYC {
        return true;
    }
    // Starting at `at` cycles after an edge is fine if it is inside the start
    // range or a short spin before it, in this refresh or the next.
    let ok = |at: u32| pqsigner_ui_px::stream::phase::start_ok(at, lo, hi, FILM_SPIN_OK_CYC);
    // Where the beam will be when the stream could start.
    let at = (since + FILM_LEAD_CYC) % REFRESH_CYC;
    if ok(at) {
        return true;
    }
    // Not now. Wait for the next tick only if it should land in range;
    // when ticks are sparse (CPU-bound work) and it would miss too, draw now
    // and let the presenter spin, rather than drop a tick and stutter.
    !ok((at + dt) % REFRESH_CYC)
}

/// Cycle count at the film's previous tick, and the smoothed interval
/// between ticks (~1 ms in chip waits, ~6 ms in the signer, longer in
/// coarse CPU-bound work).
static FILM_TICK_AT: AtomicU32 = AtomicU32::new(0);
static FILM_TICK_DT: AtomicU32 = AtomicU32::new(160_000);

/// Present one busy-film frame, streaming only the bands whose columns
/// changed since the film's previous frame (#934, scoped to the film, owner
/// 2026-10-16). `first` (the film's opening frame) is always full, and so is
/// any frame after something else drew, after a frame that did not fully
/// stream, or one the fingerprints cannot bound ([`pqsigner_ui_px::damage`]).
/// The film carries no consent and never a secret, and a partial frame is
/// never `complete`.
fn present_film(anim: &Anim, marks: &Marks<'_>, font: &Font<'_>, first: bool) -> FrameCost {
    use pqsigner_ui_px::damage::{Damage, FrameSigs};
    let mut frame = Frame::new();
    anim.build(marks, font, &mut frame);
    let sigs = FrameSigs::of(&frame, font);
    // SAFETY: single-threaded driver state (no ISR touches it); copied out.
    let (prev, glass) = unsafe { *core::ptr::addr_of!(FILM_SIGS) };
    let damage = if first || glass != lcd::glass_writes() || !film_partial_allowed() {
        Damage::All
    } else {
        sigs.damage(&prev)
    };
    let cost = match damage {
        Damage::Nothing => FrameCost { streamed: true, ..FrameCost::default() },
        Damage::Cols(x0, x1) => {
            FILM_WIN.store(band_window(x0, x1), Ordering::Relaxed);
            present_frame_cols(&frame, font, false, Some((x0, x1)), film_bg_allowed())
        }
        Damage::All => present_frame_cols(&frame, font, false, None, false),
    };
    let kept = if cost.streamed { sigs } else { FrameSigs::UNKNOWN };
    // SAFETY: as above; the only writer.
    unsafe {
        *core::ptr::addr_of_mut!(FILM_SIGS) = (kept, lcd::glass_writes());
    }
    cost
}

/// Where a film frame's time goes, summed over a bench run (dev only:
/// `ui-px-film-bench` + `ui-px-frametime`). Cycles, except `cols`.
#[cfg(all(feature = "ui-px-film-bench", feature = "ui-px-frametime"))]
#[derive(Clone, Copy, Default)]
struct BenchSplit {
    frames: u32,
    total: u64,
    render: u64,
    te: u64,
    beam: u64,
    dma: u64,
    cols: u64,
}

#[cfg(all(feature = "ui-px-film-bench", feature = "ui-px-frametime"))]
static mut BENCH_SPLIT: BenchSplit = BenchSplit { frames: 0, total: 0, render: 0, te: 0, beam: 0, dma: 0, cols: 0 };

/// Add one film frame (`total`: its whole tick, in cycles). Frames that drew
/// nothing (`Damage::Nothing`) are not counted.
#[cfg(all(feature = "ui-px-film-bench", feature = "ui-px-frametime"))]
fn bench_split_add(c: &FrameCost, total: u32) {
    if c.cols == 0 {
        return;
    }
    // SAFETY: single-threaded bench state, never touched from an ISR.
    let s = unsafe { &mut *core::ptr::addr_of_mut!(BENCH_SPLIT) };
    s.frames += 1;
    s.total += u64::from(total);
    s.render += u64::from(c.render);
    s.te += u64::from(c.te_wait);
    s.beam += u64::from(c.beam_wait);
    s.dma += u64::from(c.dma_wait);
    s.cols += u64::from(c.cols);
}

/// The sums so far, and start again from zero.
#[cfg(all(feature = "ui-px-film-bench", feature = "ui-px-frametime"))]
fn bench_split_take() -> BenchSplit {
    // SAFETY: as `bench_split_add`.
    unsafe { core::mem::take(&mut *core::ptr::addr_of_mut!(BENCH_SPLIT)) }
}

/// Dev bench (`ui-px-film-bench`, NEVER ships): the setup busy film at boot,
/// with no wallet, no secure element and no wizard, so the film can be judged
/// on the glass without a provisioning run (owner 2026-10-16).
///
/// 2026-10-16 it compared partial and full redraw (20.6 vs 18.2 fps, no
/// tearing; partial kept). Now it alternates the chip waits' pacing: PAUSED
/// (the signer's: a 16 ms pause after each frame) and BACK TO BACK
/// ([`film_tick_chip`] starting a frame as soon as one ends). Each run plays
/// the film for 12 s:
/// - 6 s of 8 ms CPU slices with the signer's tick between (key derivation,
///   signing): frames per second, and how many times longer the slices took
///   than their own CPU time (`x1.0` = the film cost nothing);
/// - 6 s of simulated chip operations with [`film_tick_chip`] (each busy for
///   2, 5, 10 or 30 ms, polled every 1 ms like the OPTIGA driver): frames per
///   second, and how many times longer the operations took than the chip was
///   busy;
/// - then a 16x4 page: the mode; `cpu` fps and slowdown; `chip` fps and
///   slowdown; the mean frame time and the longest pause between two frames
///   (ms, both halves).
/// A press (or 15 s) starts the next run. Never returns.
#[cfg(feature = "ui-px-film-bench")]
pub fn film_bench() -> ! {
    use pqsigner_ui_px::{Icon, ResultMark, ScreenBuilder, State};

    /// Frames drawn, time inside them, and the longest pause, over one half.
    #[derive(Default)]
    struct Half {
        frames: u32,
        busy: u32,
        gap: u32,
        last_end: u32,
    }
    impl Half {
        fn new(t0: u32) -> Self {
            Self { last_end: t0, ..Self::default() }
        }
        /// Run one tick; a moved panel write count means it drew a frame.
        fn tick(&mut self, f: impl FnOnce()) {
            let w = lcd::glass_writes();
            let a = timeout::now();
            f();
            if lcd::glass_writes() != w {
                let b = timeout::now();
                self.frames += 1;
                self.busy += b.wrapping_sub(a);
                self.gap = self.gap.max(b.wrapping_sub(self.last_end));
                self.last_end = b;
            }
        }
    }

    let screen = ScreenBuilder::status(b"SETUP", Icon::Dots, b"SETTING UP YOUR PQ1", State::Awaiting, ResultMark::None)
        .finish()
        .unwrap_or(Screen::BLANK);
    sign_test();
    // (chip waits back to back, background stream): today's sync presenter,
    // then the background one, paused and back to back.
    const MODES: [(bool, bool, &[u8]); 3] = [(false, false, b"PAUSED SYNC"), (false, true, b"PAUSED BG"), (true, true, b"B2B BG")];
    let mut mode = 0usize;
    loop {
        let (back_to_back, bg, label) = MODES[mode];
        FILM_CHIP_BACK_TO_BACK.store(back_to_back, Ordering::Relaxed);
        FILM_BG_ON.store(bg, Ordering::Relaxed);
        film_start_with(&screen);
        #[cfg(feature = "ui-px-frametime")]
        let _ = bench_split_take();

        // CPU half: 8 ms slices (1,280,000 cycles at 160 MHz), the signer's tick.
        let t0 = timeout::now();
        let mut cpu = Half::new(t0);
        let mut slices = 0u32;
        while timeout::now().wrapping_sub(t0) < 6_000 {
            cortex_m::asm::delay(1_280_000);
            slices += 1;
            cpu.tick(|| film_tick(0));
        }
        let cpu_ms = timeout::now().wrapping_sub(t0);

        // Chip half: operations busy for a set time, polled every 1 ms with
        // the tick `ui::busy_poll` gives the drivers. (Called directly: only
        // provisioning raises `ChipWaitTicks`.)
        const BUSY_MS: [u32; 4] = [2, 5, 10, 30];
        let t1 = timeout::now();
        let mut chip = Half::new(t1);
        let mut chip_busy = 0u32;
        let mut op = 0usize;
        while timeout::now().wrapping_sub(t1) < 6_000 {
            let busy = BUSY_MS[op % BUSY_MS.len()];
            let s = timeout::now();
            while timeout::now().wrapping_sub(s) < busy {
                cortex_m::asm::delay(160_000);
                chip.tick(film_tick_chip);
            }
            chip_busy += busy;
            op += 1;
        }
        let chip_ms = timeout::now().wrapping_sub(t1);
        film_abort();

        let tenths = |num: u32, den: u32| if den > 0 { num * 10 / den } else { 0 };
        let cpu_fps = tenths(cpu.frames * 1000, cpu_ms);
        let cpu_x = tenths(cpu_ms, slices * 8);
        let chip_fps = tenths(chip.frames * 1000, chip_ms);
        let chip_x = tenths(chip_ms, chip_busy);
        let frames = cpu.frames + chip.frames;
        let mean = if frames > 0 { (cpu.busy + chip.busy) / frames } else { 0 };

        let mut rows = [[b' '; crate::ui::DISPLAY_COLS]; crate::ui::DISPLAY_ROWS];
        bench_row(&mut rows[0], &[label], &[]);
        bench_row(&mut rows[1], &[b"cpu ", b".", b" x", b"."], &[cpu_fps / 10, cpu_fps % 10, cpu_x / 10, cpu_x % 10]);
        bench_row(&mut rows[2], &[b"chip ", b".", b" x", b"."], &[chip_fps / 10, chip_fps % 10, chip_x / 10, chip_x % 10]);
        bench_row(&mut rows[3], &[b"frame ", b" gap "], &[mean, cpu.gap.max(chip.gap)]);
        bench_page(&rows, 15_000);

        // Where the time inside a frame went, both halves together: means per
        // drawn frame in tenths of a millisecond.
        #[cfg(feature = "ui-px-frametime")]
        {
            let s = bench_split_take();
            let n = u64::from(s.frames.max(1));
            // Cycles summed over `n` frames -> tenths of a ms per frame.
            let t = |c: u64| (c / n / 16_000) as u32;
            let other = s.total.saturating_sub(s.render + s.te + s.beam + s.dma);
            let mut rows = [[b' '; crate::ui::DISPLAY_COLS]; crate::ui::DISPLAY_ROWS];
            bench_row(&mut rows[0], &[b"all ", b".", b" draw ", b"."], &[t(s.total) / 10, t(s.total) % 10, t(s.render) / 10, t(s.render) % 10]);
            bench_row(&mut rows[1], &[b"te ", b".", b" beam ", b"."], &[t(s.te) / 10, t(s.te) % 10, t(s.beam) / 10, t(s.beam) % 10]);
            bench_row(&mut rows[2], &[b"dma ", b".", b" oth ", b"."], &[t(s.dma) / 10, t(s.dma) % 10, t(other) / 10, t(other) % 10]);
            bench_row(&mut rows[3], &[b"cols ", b" n "], &[(s.cols / n) as u32, s.frames]);
            bench_page(&rows, 15_000);
        }
        mode = (mode + 1) % MODES.len();
    }
}

/// Dev bench: the signing work of one verified C10 signature — the two
/// shuffled signs, their comparison and the verify that
/// `crypto::c10_sign_verified_with_progress` runs — with a fixed test key,
/// first with no film and then with the signing film on the progress hook,
/// as a sign request runs it. Shows each one's time, the film's slowdown and
/// frame rate, and the secure stack's deepest point in each
/// (`stack_scrub::untouched_since_scrub` after a scrub), so the stack
/// headroom is measured rather than assumed (#374).
///
/// Not the wrapper itself: its OptRand and shuffle seeds come from the
/// three-source strong RNG, and the bench runs before the secure elements
/// are up. Fixed test values stand in; the cost and the call depth of the
/// signing are the same.
#[cfg(feature = "ui-px-film-bench")]
fn sign_test() {
    fn no_film(_: u8) {}
    let mut rows = [[b' '; crate::ui::DISPLAY_COLS]; crate::ui::DISPLAY_ROWS];
    bench_row(&mut rows[0], &[b"SIGN TEST"], &[]);
    bench_row(&mut rows[1], &[b"key..."], &[]);
    let _ = paint_legacy(&rows);
    // Bench-only test key: never a wallet key, never leaves this function.
    let sk = sphincs_c10::SigningKey::keygen([0x5A; 32], [0xA5; sphincs_c10::params::N]);
    let msg = [0x3C; 32];
    let opt_rand = [0x11; sphincs_c10::params::N];
    let run = |film: bool, bg: bool| -> (u32, u32, u32) {
        FILM_BG_ON.store(bg, Ordering::Relaxed);
        if film {
            film_start();
        }
        let w = lcd::glass_writes();
        crate::stack_scrub::scrub_dead_stack();
        let t0 = timeout::now();
        let hook: fn(u8) = if film { film_tick } else { no_film };
        let sig_a = sk.sign_with_shuffle(&msg, Some(&opt_rand), &sphincs_c10::shuffle::ShuffleSeed([0x22; 32]), hook);
        let sig_b = sk.sign_with_shuffle(&msg, Some(&opt_rand), &sphincs_c10::shuffle::ShuffleSeed([0x33; 32]), hook);
        let ok = sig_a == sig_b && sphincs_c10::verify(sk.pk_seed(), sk.pk_root(), &msg, &sig_a);
        let ms = timeout::now().wrapping_sub(t0);
        let free = crate::stack_scrub::untouched_since_scrub();
        let frames = lcd::glass_writes().wrapping_sub(w);
        if film {
            film_abort();
        }
        (if ok { ms } else { 0 }, free, frames)
    };
    let (t_alone, free_alone, _) = run(false, false);
    let (t_sync, free_sync, f_sync) = run(true, false);
    let (t_bg, free_bg, f_bg) = run(true, true);
    FILM_BG_ON.store(true, Ordering::Relaxed);
    let fps = |frames: u32, ms: u32| if ms > 0 { frames * 10_000 / ms } else { 0 };
    let (p_sync, p_bg) = (fps(f_sync, t_sync), fps(f_bg, t_bg));
    let mut rows = [[b' '; crate::ui::DISPLAY_COLS]; crate::ui::DISPLAY_ROWS];
    bench_row(&mut rows[0], &[b"alone ", b".", b"s f", b"K"], &[t_alone / 1000, t_alone % 1000 / 100, free_alone / 1024]);
    bench_row(&mut rows[1], &[b"sync ", b".", b"s ", b"."], &[t_sync / 1000, t_sync % 1000 / 100, p_sync / 10, p_sync % 10]);
    bench_row(&mut rows[2], &[b"bg ", b".", b"s ", b"."], &[t_bg / 1000, t_bg % 1000 / 100, p_bg / 10, p_bg % 10]);
    bench_row(&mut rows[3], &[b"free ", b"K ", b"K/", b"K"], &[free_sync / 1024, free_bg / 1024, crate::stack_scrub::stack_size() / 1024]);
    bench_page(&rows, 60_000);
}

/// One 16x4 bench row: each part followed by its number (if any), cut at
/// the row's width.
#[cfg(any(feature = "ui-px-film-bench", feature = "stack-hwm"))]
fn bench_row(row: &mut [u8; crate::ui::DISPLAY_COLS], parts: &[&[u8]], nums: &[u32]) {
    let mut n = 0;
    let mut push = |b: u8| {
        if n < row.len() {
            row[n] = b;
            n += 1;
        }
    };
    for (k, p) in parts.iter().enumerate() {
        for &b in *p {
            push(b);
        }
        if let Some(&v) = nums.get(k) {
            let mut d = [0u8; 10];
            let mut i = 0;
            let mut x = v;
            loop {
                d[i] = b'0' + (x % 10) as u8;
                i += 1;
                x /= 10;
                if x == 0 {
                    break;
                }
            }
            while i > 0 {
                i -= 1;
                push(d[i]);
            }
        }
    }
}

/// Show a bench page until a press or `ms`.
#[cfg(feature = "ui-px-film-bench")]
fn bench_page(rows: &[[u8; crate::ui::DISPLAY_COLS]; crate::ui::DISPLAY_ROWS], ms: u32) {
    let _ = paint_legacy(rows);
    let t = timeout::now();
    let _ = crate::ui::input().wait_button(&mut || timeout::now().wrapping_sub(t) >= ms);
}

/// One frame of the running film, if one is due — the signer's `fn(u8)`
/// progress hook. `_percent` is not used for the pose: the film is a pure
/// function of the S-only clock. Bounded: at most one frame per
/// `FRAME_PERIOD_MS`, and a frame that overran 50 ms skips the next slot, so
/// the sign chain is never delayed by more than one frame per call.
pub fn film_tick(_percent: u8) {
    #[cfg(feature = "ui-px-film-gaps")]
    super::film_gaps::note_pct(_percent);
    film_tick_paced(false);
}

/// Dev: the running film started the pause recorder itself.
#[cfg(feature = "ui-px-film-gaps")]
static FILM_GAPS_OWN: AtomicBool = AtomicBool::new(false);

/// Dev: record this film's pauses, unless a caller (provisioning) already
/// records a longer run.
#[cfg(feature = "ui-px-film-gaps")]
fn film_gaps_begin() {
    if !super::film_gaps::recording() {
        super::film_gaps::start();
        FILM_GAPS_OWN.store(true, Ordering::Relaxed);
    }
}

/// Dev: stop the recorder if this film started it.
#[cfg(feature = "ui-px-film-gaps")]
fn film_gaps_end() {
    if FILM_GAPS_OWN.swap(false, Ordering::Relaxed) {
        super::film_gaps::stop();
    }
}

/// Dev: the film's longest pauses, `<ms>@<percent>`, until a press.
#[cfg(feature = "ui-px-film-gaps")]
fn film_gaps_page() {
    let mut rows = [[b' '; crate::ui::DISPLAY_COLS]; crate::ui::DISPLAY_ROWS];
    super::film_gaps::rows(&mut rows);
    dev_page(&rows);
}

/// Whether a chip wait's tick ([`film_tick_chip`]) draws back to back. On
/// (owner 2026-10-19): with the background stream a frame costs ~7.7 ms, and
/// the bench's chip waits ran at 58 fps back to back against 31 paused, both
/// at x1.3 (the operations' slowdown). The dev bench (`ui-px-film-bench`)
/// alternates it.
#[cfg(feature = "ui-px-film-bench")]
static FILM_CHIP_BACK_TO_BACK: AtomicBool = AtomicBool::new(true);

fn film_chip_back_to_back() -> bool {
    #[cfg(feature = "ui-px-film-bench")]
    {
        FILM_CHIP_BACK_TO_BACK.load(Ordering::Relaxed)
    }
    #[cfg(not(feature = "ui-px-film-bench"))]
    {
        true
    }
}

/// One frame of the running film, if one is due, from a wait on a busy
/// secure element (`ui::busy_poll`). There the CPU only polls the chip, so
/// the film may start its next frame as soon as one ends (paced start to
/// start) instead of leaving the signer's pause; the cost is that the wait
/// returns up to one frame late.
pub fn film_tick_chip() {
    film_tick_paced(film_chip_back_to_back());
}

fn film_tick_paced(back_to_back: bool) {
    if !FILM_LIVE.load(Ordering::Relaxed) {
        return;
    }
    let now = timeout::now();
    if !FILM_SET.load(Ordering::Relaxed) {
        return;
    }
    // SAFETY: single-threaded driver state; `FILM_SET` says `film_start`
    // wrote it, and no other reference is live during this call.
    let (anim, last) = unsafe { (*core::ptr::addr_of_mut!(FILM)).assume_init_mut() };
    if now.wrapping_sub(*last) < FRAME_PERIOD_MS {
        return;
    }
    // The previous frame is still streaming in the background: next tick.
    if !film_reap(false) {
        return;
    }
    if !film_phase_ok() {
        return;
    }
    #[cfg(all(feature = "ui-px-film-bench", feature = "ui-px-frametime"))]
    let t_frame = frametime::cycles();
    let Some(atlas) = assets::atlas_film_frame() else {
        return;
    };
    anim.step(now);
    let _cost = present_film(anim, &atlas.marks(), &atlas.font(), false);
    #[cfg(all(feature = "ui-px-film-bench", feature = "ui-px-frametime"))]
    bench_split_add(&_cost, frametime::cycles().wrapping_sub(t_frame));
    let after = timeout::now();
    #[cfg(feature = "ui-px-film-gaps")]
    super::film_gaps::frame(after);
    *last = if back_to_back {
        now
    } else if after.wrapping_sub(now) > 50 {
        after.wrapping_add(FRAME_PERIOD_MS)
    } else {
        after
    };
}

/// The work answered: land the running film on `e` (the current turn
/// completes, then the spiral, flash, result and its hold), or — with no
/// film running — play the film-less resolve. Returns when the result has
/// held `RESULT_HOLD_MS`; the resting frame stays on the glass.
pub fn film_resolve(e: Ending) {
    let Some(atlas) = assets::atlas_verified() else {
        film_abort();
        reset_film_look();
        return;
    };
    film_reap(true);
    let now = timeout::now();
    #[cfg(all(feature = "stack-hwm", target_arch = "arm"))]
    let ran = (
        now.wrapping_sub(FILM_BEGAN.0.load(Ordering::Relaxed)),
        lcd::glass_writes().wrapping_sub(FILM_BEGAN.1.load(Ordering::Relaxed)),
    );
    FILM_LIVE.store(false, Ordering::Relaxed);
    crate::hw::lcd_te::stamps(false);
    #[cfg(feature = "ui-px-film-gaps")]
    film_gaps_end();
    // SAFETY: single-threaded driver state; `FILM_SET` says it was written,
    // and clearing it first makes the move-out the last read, so a later
    // tick is a no-op.
    let taken = if FILM_SET.swap(false, Ordering::Relaxed) {
        Some(unsafe { (*core::ptr::addr_of_mut!(FILM)).assume_init_read() })
    } else {
        None
    };
    let mut anim = match taken {
        Some((anim, _)) => anim,
        None => {
            let s = film_screen();
            Anim::new(&s, 0, now)
        }
    };
    anim.film_resolve(e, now);
    let marks = atlas.marks();
    let font = atlas.font();
    loop {
        let t = timeout::now();
        anim.step(t);
        let _ = build_and_present(&anim, &marks, &font, None, None, None);
        if anim.film_done(t) {
            break;
        }
    }
    reset_film_look();
    #[cfg(all(feature = "stack-hwm", target_arch = "arm"))]
    show_stack_hwm(ran.0, ran.1);
}

/// When the running film started, and the panel write count then (dev,
/// `stack-hwm`'s readout).
#[cfg(all(feature = "stack-hwm", target_arch = "arm"))]
static FILM_BEGAN: (AtomicU32, AtomicU32) = (AtomicU32::new(0), AtomicU32::new(0));

/// A film is running (started and not yet resolved).
#[must_use]
pub fn film_live() -> bool {
    FILM_LIVE.load(Ordering::Relaxed)
}

/// Lands the running film on [`Ending::Failed`] if the sign window is left
/// without landing it — #773.
///
/// `film_tick` is the signer's progress hook, so an error return inside the
/// film window simply stopped calling it and left the last painted orbit
/// frame on the glass forever: a signing FAILURE, the one event the user
/// most needs to see, looked identical to "still working". There were 25
/// such returns across the three sign handlers, and enumerating them is the
/// kind of fix a future `return` silently undoes.
///
/// This is structural instead: arm it next to `film_start()`, `disarm()` it
/// at the success landing, and every other way out of the scope — including
/// one added later — lands the film on the X.
///
/// Only construct it on a route that actually started a film: with none
/// running `film_resolve` plays the film-less resolve, which would paint an
/// ending on a route that never showed one.
///
/// RESIDUAL: `panic = abort`, so `Drop` does not run on a panic. A panicking
/// sign path still leaves the last frame up. That is the device halting, not
/// a silent wrong answer, and it is out of this guard's scope.
pub struct FilmLanding {
    armed: bool,
}

impl FilmLanding {
    /// Arm immediately after [`film_start`].
    #[must_use]
    pub fn armed() -> Self {
        Self { armed: true }
    }

    /// The caller landed the film itself (the success path).
    pub fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for FilmLanding {
    fn drop(&mut self) {
        if self.armed {
            film_resolve(Ending::Failed);
        }
    }
}

/// Dev readout page: shown until a press, or 60 s.
#[cfg(any(feature = "stack-hwm", feature = "ui-px-film-gaps"))]
fn dev_page(rows: &[[u8; crate::ui::DISPLAY_COLS]; crate::ui::DISPLAY_ROWS]) {
    let _ = paint_legacy(rows);
    let t = timeout::now();
    let _ = crate::ui::input().wait_button(&mut || timeout::now().wrapping_sub(t) >= 60_000);
}

/// Dev (`stack-hwm`, DVT row 5.9, never ships): after a film lands, show
/// the secure stack's headroom so far — the deepest any frame (a sign
/// request's whole path, the film's frames, interrupts) has reached since
/// boot — until a press. The EVT has no SWD to read `STACK_HWM_LOW` from.
/// With it, how long the film ran before it landed and its frame rate
/// (`ms`, `frames`), i.e. the work it played over.
#[cfg(all(feature = "stack-hwm", target_arch = "arm"))]
fn show_stack_hwm(ms: u32, frames: u32) {
    let free = crate::stack_scrub::hwm::free_now().unwrap_or(0);
    let size = crate::stack_scrub::hwm::size();
    let fps = if ms > 0 { frames * 10_000 / ms } else { 0 };
    let mut rows = [[b' '; crate::ui::DISPLAY_COLS]; crate::ui::DISPLAY_ROWS];
    bench_row(&mut rows[0], &[b"STACK HWM"], &[]);
    bench_row(&mut rows[1], &[b"free ", b" B"], &[free]);
    bench_row(&mut rows[2], &[b"used ", b"/"], &[size.saturating_sub(free), size]);
    bench_row(&mut rows[3], &[b"film ", b".", b"s ", b"."], &[ms / 1000, ms % 1000 / 100, fps / 10, fps % 10]);
    dev_page(&rows);
    // And the film's longest pauses (dev, film-gaps).
    #[cfg(feature = "ui-px-film-gaps")]
    film_gaps_page();
}

/// Drop a running film without landing it (error paths).
pub fn film_abort() {
    film_reap(true);
    FILM_LIVE.store(false, Ordering::Relaxed);
    crate::hw::lcd_te::stamps(false);
    // Forget the film; it needs no drop (asserted at `FILM`).
    FILM_SET.store(false, Ordering::Relaxed);
}

/// The busy look while the device computes (split/join film pending: a
/// resting disc with the caption). `pct` throttles nothing yet.
pub fn show_busy(caption: &[u8]) {
    let s = pqsigner_ui_px::ScreenBuilder::status(b"BUSY", pqsigner_ui_px::Icon::Safe, caption, pqsigner_ui_px::State::Awaiting, pqsigner_ui_px::ResultMark::None)
        .finish()
        .unwrap_or(Screen::BLANK);
    let Some(atlas) = assets::atlas_verified() else {
        return;
    };
    let anim = Anim::new(&s, 0, timeout::now());
    let _ = build_and_present(&anim, &atlas.marks(), &atlas.font(), None, None, None);
}

// ---- port step 4: screens outside the dialog -------------------------------------

/// Longest a non-dialog screen plays before it is left at rest (the longest
/// verdict timeline is 2.4 s).
const PLAY_CAP_MS: u32 = 3_000;

/// Whether the S-only clock is ticking (SysTick starts after some early
/// boot screens on QEMU-shaped boots; never wait on a stopped clock).
fn clock_running() -> bool {
    let a = timeout::now();
    for _ in 0..400_000u32 {
        if timeout::now() != a {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// The frame-time overlay for [`play_screen`] (bench only): the same three
/// lines as the dialog's (`run_flow`), so a status screen, a verdict or a seed
/// page can be read against the dialog's numbers. Until 2026-10-15 these
/// screens had no overlay at all, so the setup flow's "laggy shield" report
/// could not be measured. Worst case per second, like the dialog.
#[cfg(feature = "ui-px-frametime")]
#[derive(Default)]
struct PlayOverlay {
    last_paint: u32,
    window_at: u32,
    max_render: u32,
    max_blit: u32,
    max_period: u32,
    max_shapes: u32,
    max_glyphs: u32,
    max_secret: u32,
    max_stream: u32,
    max_wire_last: u32,
    max_te: u32,
    l1: [u8; 24],
    n1: usize,
    l2: [u8; 24],
    n2: usize,
    l3: [u8; 24],
    n3: usize,
}

#[cfg(feature = "ui-px-frametime")]
impl PlayOverlay {
    /// The last published window, as the dialog paints it: yellow
    /// render/blit/period (ms), white shapes/glyphs/secret and green
    /// stream/wire_last/te_wait (tenths of a ms).
    fn push_items<'a>(&'a self, frame: &mut Frame<'a>) {
        use pqsigner_ui_px::font::{Align, TextRun, TierId};
        use pqsigner_ui_px::raster::Rgb;
        for (text, y, color) in [
            (&self.l1[..self.n1], 16, Rgb::YELLOW),
            (&self.l2[..self.n2], 34, Rgb::WHITE),
            (&self.l3[..self.n3], 52, Rgb::GREEN),
        ] {
            if text.is_empty() {
                continue;
            }
            let run = TextRun {
                text,
                tier: TierId::regular(16),
                x: 40,
                y,
                align: Align::Left,
                baseline: true,
                ls_q6: 0,
                alpha: 255,
            };
            let _ = frame.text(run, color);
        }
    }

    /// Fold one presented frame in; republish once a second.
    fn account(&mut self, build: u32, cost: &FrameCost) {
        let now = timeout::now();
        if self.last_paint != 0 {
            self.max_period = self.max_period.max(now.wrapping_sub(self.last_paint));
        }
        self.last_paint = now;
        self.max_render = self.max_render.max(cost.render.wrapping_add(build));
        self.max_blit = self.max_blit.max(cost.blit);
        self.max_shapes = self.max_shapes.max(cost.split.shapes);
        self.max_glyphs = self.max_glyphs.max(cost.split.glyphs.wrapping_add(cost.split.fills));
        self.max_secret = self.max_secret.max(cost.split.secret);
        self.max_stream = self.max_stream.max(cost.stream);
        self.max_wire_last = self.max_wire_last.max(cost.wire_last);
        self.max_te = self.max_te.max(cost.te_wait);
        if now.wrapping_sub(self.window_at) >= 1_000 || self.n1 == 0 {
            self.n1 = frametime::format(&mut self.l1, self.max_render, self.max_blit, self.max_period);
            self.n2 = frametime::format_tenths(&mut self.l2, self.max_shapes, self.max_glyphs, self.max_secret);
            self.n3 = frametime::format_tenths(&mut self.l3, self.max_stream, self.max_wire_last, self.max_te);
            *self = Self {
                window_at: now,
                last_paint: now,
                l1: self.l1,
                n1: self.n1,
                l2: self.l2,
                n2: self.n2,
                l3: self.l3,
                n3: self.n3,
                ..Self::default()
            };
        }
    }
}

/// Play a non-dialog record from its arrival until it rests, leaving the
/// resting frame on the glass; `secret` grid cells are painted over every
/// frame by the constant-time run, and such a frame streams every strip.
/// With a stopped clock only the resting frame is shown.
pub fn play_screen(s: &Screen, atlas: &assets::AtlasRef, secret: &[(usize, &[u8])]) {
    film_abort();
    let marks = atlas.marks();
    let font = atlas.font();
    let force = !secret.is_empty();
    #[cfg(feature = "ui-px-frametime")]
    let mut ft = PlayOverlay::default();
    // `mut` only matters when the overlay accumulator is captured.
    #[cfg_attr(not(feature = "ui-px-frametime"), allow(unused_mut))]
    let mut paint = |anim: &Anim| {
        #[cfg(feature = "ui-px-frametime")]
        let t0 = frametime::cycles();
        let (_cost, _build) = {
            let mut frame = Frame::new();
            anim.build(&marks, &font, &mut frame);
            for &(k, w) in secret {
                pqsigner_ui_px::rows::push_secret_word(&mut frame, k, w, 255);
            }
            #[cfg(feature = "ui-px-frametime")]
            let build = frametime::cycles().wrapping_sub(t0);
            #[cfg(not(feature = "ui-px-frametime"))]
            let build = 0u32;
            #[cfg(feature = "ui-px-frametime")]
            ft.push_items(&mut frame);
            (present_frame_ex(&frame, &font, force), build)
        };
        #[cfg(feature = "ui-px-frametime")]
        ft.account(_build, &_cost);
    };
    if pqsigner_ui_px::scene::plays_forever(s, 0) {
        // #783. This screen has NO rest pose, so "play it until it rests"
        // cannot terminate and `PLAY_CAP_MS` is not a safety net — it is the
        // normal exit, and it fires mid-motion. Painting the opening frame
        // and returning is the honest thing: the caller gets a clean,
        // deliberate still rather than a swing abandoned 40% through. A
        // caller that wants the motion animates it against its own input
        // wait with `Ambient` + `wait_button_ticking`.
        let anim = Anim::new(s, 0, timeout::now());
        paint(&anim);
    } else if !clock_running() {
        // Settle on synthetic time, show the rest.
        let mut anim = Anim::new(s, 0, 0);
        let mut t = 16;
        while anim.step(t) && t < PLAY_CAP_MS {
            t += 16;
        }
        paint(&anim);
    } else {
        let t0 = timeout::now();
        // The PIN check's result continues from the CHECKING PIN pill still
        // on the glass instead of opening on black (owner 2026-10-16):
        // `Anim::verdict_to`. Only from that one screen, only if nothing
        // has drawn since (`carry_take`).
        let mut anim = match pin_check_take(s) {
            Some(mut a) => {
                a.verdict_to(s, t0);
                a
            }
            None => Anim::new(s, 0, t0),
        };
        loop {
            let now = timeout::now();
            let moving = anim.step(now);
            paint(&anim);
            if !moving || now.wrapping_sub(t0) >= PLAY_CAP_MS {
                break;
            }
            while now.wrapping_add(FRAME_PERIOD_MS).wrapping_sub(timeout::now()) < (1 << 31) {
                cortex_m::asm::wfi();
            }
        }
        // CHECKING PIN is public (no digit, no secret): keep it for the result.
        if !force && pqsigner_ui_px::verdict::is_pin_check(s) {
            carry_keep(anim);
        }
    }
    if force {
    }
}

/// Idle time after which the #802 probe calls `reset_activity()` ONCE.
///
/// 180 s: comfortably past the 120 s boundary, so the degraded state has been
/// established and read off the glass before the gate is closed again.
#[cfg(all(feature = "ui-px-frametime", feature = "ui-px-bench"))]
const ONE_SHOT_RESET_MS: u32 = 180_000;

/// #805 condition (d): the boot-time one-shot `fi::wait_random()` fallback
/// measurement — `(calls, fallbacks)` for a SINGLE top-level delay, taken by
/// the bench in thread mode before anything else runs.
///
/// Measured rather than inferred because the carve-out requires it; see the
/// rationale on `crate::rng::NONSECRET_CALLS`.
#[cfg(all(feature = "ui-px-frametime", feature = "ui-px-bench"))]
static FALLBACK_SHOT_CALLS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[cfg(all(feature = "ui-px-frametime", feature = "ui-px-bench"))]
static FALLBACK_SHOT_FB: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[cfg(all(feature = "ui-px-frametime", feature = "ui-px-bench"))]
static FALLBACK_SHOT_MISSES: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Publish the boot probe for the overlay: worst-case pool draw of any single
/// fill in the length sweep, total fallbacks, total pool misses.
#[cfg(all(feature = "ui-px-frametime", feature = "ui-px-bench"))]
pub fn set_fallback_probe(max_hits: u32, fallbacks: u32, misses: u32) {
    use core::sync::atomic::Ordering::Relaxed;
    FALLBACK_SHOT_CALLS.store(max_hits, Relaxed);
    FALLBACK_SHOT_FB.store(fallbacks, Relaxed);
    FALLBACK_SHOT_MISSES.store(misses, Relaxed);
}

#[cfg(feature = "ui-px-bench")]
/// An endless ambient screen, animated against real input (#783).
///
/// WHY THIS EXISTS. `play_screen` plays a record "until it rests", and for a
/// screen that NEVER rests its only exit is `PLAY_CAP_MS`. For the wizard
/// chooser that means: 1 s of still image (`sweep_offset` returns 0 until
/// `SWEEP_HOLD_MS`), then 2 s of a 5 s sine, then a hard stop 40% through the
/// swing with the disc stranded off-centre — and then a blocking input wait
/// during which nothing moves. That is the freeze, exactly as reported.
///
/// The fix is not a longer cap. A cap on an animation with no end is always
/// an arbitrary truncation; the screen has to be animated for as long as the
/// user is looking at it, which means for as long as the input wait lasts.
/// So this holds the animation state and paints ONE frame per call, and the
/// caller hands `tick` to `wait_button_ticking`.
///
/// Takes no `secret` cells, deliberately: nothing endless carries seed words
/// (the words grid is `Kind::Words`, which settles), so the constant-time
/// secret run has no business on this path and cannot be asked for.
pub struct Ambient {
    anim: Anim,
    /// Clock time the next frame is due.
    due_at: u32,
    /// Per-second worst case of `stream` / `te_wait` / frame period, in DWT
    /// cycles, plus the formatted line. Bench only.
    ///
    /// WHY THIS IS HERE AT ALL. The first cut of this struct painted through
    /// `present_frame_ex` with no overlay, so the only interactive screen that
    /// is NOT a sign dialog had no numbers — and when the owner reported it
    /// "feels laggier", there was nothing to read but adjectives. `run_flow`
    /// had three lines; this had none. The gap was mine, and it is the reason
    /// the first diagnosis of that report was guesswork.
    ///
    /// `period` is what settles it: phase-locked to a 16.0 ms refresh, a frame
    /// can only land on a multiple, so 320 vs 480 tenths is the difference
    /// between "inside the window" and "lost a whole refresh period".
    #[cfg(feature = "ui-px-frametime")]
    ft: AmbientFt,
}

/// The ambient overlay's accumulators (bench only).
#[cfg(all(feature = "ui-px-frametime", feature = "ui-px-bench"))]
#[derive(Default)]
struct AmbientFt {
    max_stream: u32,
    max_te: u32,
    max_period: u32,
    max_render: u32,
    max_shapes: u32,
    max_glyphs: u32,
    window_at: u32,
    last_paint: u32,
    buf: [u8; 24],
    len: usize,
    buf2: [u8; 24],
    len2: usize,
    buf3: [u8; 24],
    len3: usize,
    /// #802: ISR cycles and gate calls at the last window boundary.
    isr_at: u32,
    gate_at: u32,
    /// Did the one-shot `reset_activity()` probe already fire?
    reset_fired: bool,
}

#[cfg(feature = "ui-px-bench")]
impl Ambient {
    /// Start animating `s` and paint its first frame NOW.
    ///
    /// Eagerly, not on the first `tick`: a wait that returns immediately
    /// (a button already down, or an idle timeout) must still leave THIS
    /// screen on the glass rather than whatever the previous one left.
    pub fn new(s: &Screen, atlas: &assets::AtlasRef) -> Self {
        film_abort();
        let now = timeout::now();
        let mut a = Self {
            anim: Anim::new(s, 0, now),
            due_at: now,
            #[cfg(feature = "ui-px-frametime")]
            ft: AmbientFt::default(),
        };
        a.paint(atlas);
        a
    }

    /// Paint one frame if one is due. Cheap and bounded when it is not.
    ///
    /// MUST NOT be called while a button is down — see
    /// `hw::buttons::wait_event_ticking`, whose hold timing is synthetic.
    /// Returns whether it painted, so the caller can skip its poll delay —
    /// a painted frame has already spent ~34 ms.
    pub fn tick(&mut self, atlas: &assets::AtlasRef) -> bool {
        let now = timeout::now();
        if now.wrapping_sub(self.due_at) >= (1 << 31) {
            return false; // not due yet
        }
        self.due_at = now.wrapping_add(FRAME_PERIOD_MS);
        // #802's one-shot: close the idle gate again, once, well after the
        // boundary. Nothing else changes — same `Ambient`, same screen, same
        // binary, no reboot. The slowdown must vanish at this instant and
        // come back ~120 s later.
        #[cfg(feature = "ui-px-frametime")]
        if !self.ft.reset_fired && timeout::idle_for() > ONE_SHOT_RESET_MS {
            self.ft.reset_fired = true;
            timeout::reset_activity();
        }
        let _ = self.anim.step(now);
        self.paint(atlas);
        true
    }

    fn paint(&mut self, atlas: &assets::AtlasRef) {
        let marks = atlas.marks();
        let font = atlas.font();
        // Through `build_and_present`, not a hand-rolled frame build, so the
        // overlay text is drawn by exactly the same code as the dialog's.
        #[cfg(feature = "ui-px-frametime")]
        let overlay = (self.ft.len > 0).then(|| &self.ft.buf[..self.ft.len]);
        #[cfg(feature = "ui-px-frametime")]
        let split = (self.ft.len2 > 0).then(|| &self.ft.buf2[..self.ft.len2]);
        #[cfg(feature = "ui-px-frametime")]
        let wire = (self.ft.len3 > 0).then(|| &self.ft.buf3[..self.ft.len3]);
        #[cfg(not(feature = "ui-px-frametime"))]
        let wire = None;
        #[cfg(not(feature = "ui-px-frametime"))]
        let overlay = None;
        #[cfg(not(feature = "ui-px-frametime"))]
        let split = None;
        // Both of those borrow `self` IMMUTABLY, as does `&self.anim`, so no
        // dance is needed; they all end when `cost` comes back owned.
        let cost = build_and_present(&self.anim, &marks, &font, overlay, split, wire);
        let _ = cost;

        #[cfg(feature = "ui-px-frametime")]
        {
            let end = frametime::cycles();
            if self.ft.last_paint != 0 {
                self.ft.max_period = self.ft.max_period.max(end.wrapping_sub(self.ft.last_paint));
            }
            self.ft.last_paint = end;
            self.ft.max_stream = self.ft.max_stream.max(cost.stream);
            self.ft.max_te = self.ft.max_te.max(cost.te_wait);
            self.ft.max_render = self.ft.max_render.max(cost.render);
            self.ft.max_shapes = self.ft.max_shapes.max(cost.split.shapes);
            self.ft.max_glyphs = self.ft
                .max_glyphs
                .max(cost.split.glyphs.wrapping_add(cost.split.fills));
            let t = timeout::now();
            if t.wrapping_sub(self.ft.window_at) >= 1_000 || self.ft.len == 0 {
                // Line 1 (yellow) — the CADENCE: where the frame period goes.
                let (a, b, c) = (self.ft.max_stream, self.ft.max_te, self.ft.max_period);
                self.ft.len = frametime::format_tenths(&mut self.ft.buf, a, b, c);
                // Line 2 (white) — the CPU: where the render time goes.
                //
                // Six numbers, so one flash LOCALISES a drift instead of only
                // confirming it:
                //   period climbs + render climbs  -> the rasteriser
                //   period climbs + stream climbs  -> the wire
                //   period climbs, both flat       -> the tail / poll loop,
                //                                     i.e. my own code
                let (d, e, f) = (self.ft.max_render, self.ft.max_shapes, self.ft.max_glyphs);
                self.ft.len2 = frametime::format_tenths(&mut self.ft.buf2, d, e, f);
                // Line 3 (green) — the DISCRIMINATOR for "why after 1-2 min?".
                //   te_misses    = TE waits that found no edge (each costs the
                //                  whole ~100 ms spin cap)
                //   idle_seconds = seconds since the last activity reset; the
                //                  120 s timeout is the owner's hypothesis for
                //                  the onset, so show the boundary directly
                //                  instead of reasoning about it
                //   te_dead      = 1 once the line has latched dead
                //
                // If misses stay 0 and the lag still arrives, the TE poll was
                // never the cause and the idle counter is back in the frame.
                let idle_s = (timeout::idle_for() / 1_000).min(999);
                // Line 3 (green) — the #794 DISCRIMINATOR: `items / drawn /
                // idle_seconds`, plain counts.
                //
                // The render grew ~50-70% across every class over two minutes
                // on the EVT unit. Cycle counts cannot distinguish "more work"
                // from "the same work, slower", and every class growing by a
                // similar factor points at the latter — but points is not
                // measures. So count what is actually submitted and what
                // survives the band cull:
                //
                //   counts FLAT, cycles grow -> the same work taking longer:
                //       GPDMA/SRAM1 contention or fetch cost. The animation is
                //       out of scope and so is every motion constant.
                //   counts GROW              -> work is being submitted that
                //       inspection of the motion code did not find.
                //
                // `idle_seconds` stays because the owner's hypothesis for the
                // ONSET is the 120 s inactivity boundary, and it is still the
                // only one with the right timescale.
                //
                // The TE fields this replaces have served their purpose: the
                // latch is live and self-proving, `te_misses` reads 0, and
                // `te_wait` is back inside one refresh period.
                // Line 3 (green) — #802's CAUSAL test: `isr_ms_per_s /
                // gate_calls_per_s / idle_seconds`.
                //
                //   gate_calls jumps 0 -> ~1000 at the idle boundary: that IS
                //     the short-circuit flipping, measured rather than argued.
                //   isr_ms_per_s is how much of each second the ISR consumed.
                //     Predicted < 1 before the boundary, 250-450 after.
                //
                // And `ONE_SHOT_RESET_MS` calls `timeout::reset_activity()`
                // once, so the gate closes again WITHOUT a reboot, a cooling
                // interval or any content change. If the slowdown vanishes at
                // that instant and returns ~120 s later, the mechanism is
                // proven, not correlated.
                #[cfg(feature = "stm32u585")]
                let (isr_ms, gate_per_s) = {
                    use core::sync::atomic::Ordering::Relaxed;
                    let isr = crate::ISR_CYCLES.load(Relaxed);
                    let gate = crate::IDLE_GATE_CALLS.load(Relaxed);
                    let d_isr = isr.wrapping_sub(self.ft.isr_at);
                    let d_gate = gate.wrapping_sub(self.ft.gate_at);
                    self.ft.isr_at = isr;
                    self.ft.gate_at = gate;
                    (d_isr / 160_000, d_gate)
                };
                #[cfg(not(feature = "stm32u585"))]
                let (isr_ms, gate_per_s) = (0u32, 0u32);
                let _ = (cost.split.items, cost.split.drawn);
                // Line 3 (green) — REPURPOSED for #805 condition (d), now
                // that #802's `isr_ms -> 0` / `gate_calls` reading has been
                // taken on glass and the issue is closed:
                //
                //   shot_calls / shot_fallbacks / running_pct
                //
                //   selftest    #835 poison-boundary self-test bitmask,
                //               run once at boot. Expect 15:
                //                 bit 0 flag reads POISONED after poisoning
                //                 bit 1 `rng::fill` REFUSES while poisoned
                //                 bit 2 flag reads CLEAN after clearing
                //                 bit 3 `rng::fill` SUCCEEDS again after
                //               Four bits rather than a verdict, because a
                //               single pass/fail cannot tell "it works" from
                //               "it never ran". Bit 3 is what separates this
                //               from the halt it replaced: under #833/#834
                //               the device would be in a `wfe` loop and this
                //               screen would never paint.
                //   poisonings  poisonings in ordinary running since that
                //               self-test. MUST be 0 — a device doing nothing
                //               unusual should never fail to source a delay.
                //   zperm       zero bytes per 1000 bytes WRITTEN into the
                //               pool — the TRNG byte distribution measured at
                //               the source, with no consumption path in
                //               between. Expect 4 (1/256 = 3.9).
                //
                //               Replaces the consumption-side ratio, which
                //               was confounded: consumption is LIFO, bytes
                //               below AVAIL can be wiped at disarm without
                //               ever being drawn, and its two baselines are
                //               separate non-atomic loads. One boot read a
                //               PERSISTENT 0-1 against 3.9 — a sustained 4x
                //               deficit of zeros, which noise does not
                //               explain. This field says whether that is the
                //               accounting or the hardware.
                //
                //               A DEFICIT is bias just as much as an excess
                //               is. If this reads low too, the missing
                //               continuous-repetition test in
                //               `delay_pool_word` stops being theoretical.
                //
                //               999 until 1024 bytes have been written, so
                //               the first number shown is already stable.
                let (selftest, poisonings_now, zperm) = {
                    #[cfg(feature = "ui-px-frametime")]
                    {
                        use core::sync::atomic::Ordering::Relaxed;
                        let base = FALLBACK_SHOT_FB.load(Relaxed);
                        let now = crate::fi::DELAY_POISONINGS.load(Relaxed);
                        (
                            FALLBACK_SHOT_CALLS.load(Relaxed),
                            now.saturating_sub(base),
                            {
                                let z = crate::fi_delay_pool::ZERO_BYTES_WRITTEN
                                    .load(Relaxed);
                                let n = crate::fi_delay_pool::BYTES_WRITTEN.load(Relaxed);
                                const MIN_BYTES_FOR_RATIO: u32 = 1024;
                                if n < MIN_BYTES_FOR_RATIO {
                                    999
                                } else {
                                    z.saturating_mul(1000) / n
                                }
                                                        },
                        )
                    }
                    #[cfg(not(feature = "ui-px-frametime"))]
                    {
                        (0u32, 0u32, 0u32)
                    }
                };
                let _ = (isr_ms, gate_per_s, idle_s);
                self.ft.len3 = frametime::format_raw(
                    &mut self.ft.buf3,
                    selftest.min(999),
                    poisonings_now.min(999),
                    zperm.min(999),
                );
                self.ft.window_at = t;
                self.ft.max_stream = 0;
                self.ft.max_te = 0;
                self.ft.max_period = 0;
                self.ft.max_render = 0;
                self.ft.max_shapes = 0;
                self.ft.max_glyphs = 0;
            }
        }
    }
}

/// Paint a non-dialog record's resting frame at once (work in progress).
pub fn paint_rest(s: &Screen, atlas: &assets::AtlasRef) {
    film_abort();
    let mut anim = Anim::new(s, 0, 0);
    let mut t = 16;
    while anim.step(t) && t < PLAY_CAP_MS {
        t += 16;
    }
    let _ = build_and_present(&anim, &atlas.marks(), &atlas.font(), None, None, None);
}

// ---- the flow ------------------------------------------------------------------

/// Run the design's confirm loop over a proven transcript on the panel.
/// Returns the outcome and the FI gate (`OK_SENTINEL` only for `Signed`).
pub fn run_flow(screens: &Screens, atlas: &assets::AtlasRef, deadline_expired: &mut dyn FnMut() -> bool) -> (PxOutcome, u32) {
    let visible = screens.as_slice();
    let Some(mut driver) = FlowDriver::new(visible) else {
        return (PxOutcome::Cancelled, crate::fi::FAIL_SENTINEL);
    };
    if deadline_expired() {
        return (PxOutcome::DeadlineExpired, crate::fi::FAIL_SENTINEL);
    }
    // A busy film (key generation before the dialog) ends here; the sign
    // starts its own film after the consent.
    film_abort();
    // Parsed once per flow from the view `assets::verify_atlas` proved for
    // this dialog: the atlas header walk is cheap but it is per frame
    // otherwise, and the marks likewise.
    let marks = atlas.marks();
    let font = atlas.font();
    let now = timeout::now();
    let mut anim = Anim::new(&visible[0], 0, now);
    // F14/SCAFI-2: FI-hardened arming flag (complement pair + double read).
    let mut commit_armed = crate::fih::FihBool::new_false();
    // Whatever the panel shows now, the flow's first frame repaints it all.
    sampling_enable();
    // Seed the gesture FSM with the buttons' CURRENT level, which
    // `sampling_enable` just latched into `STABLE_BITS`. A plain
    // `InputFsm::new` starts from "nothing pressed", so a chord the user is
    // still holding from the previous dialog reads as a fresh press pair on
    // the first drain and fires `ChordClick` — the sign gesture — here.
    // Flushing the ring (`sampling_enable`) does NOT prevent that: the
    // gesture is reconstructed from the LEVEL, not replayed from the ring.
    let sb = stable_bits();
    let mut fsm = InputFsm::resumed(InputCtx::NAV, sb & 1 != 0, sb & 2 != 0);
    // The whole navigation phase is "waiting on physical input" for the
    // watchdog; it does NOT reset the inactivity timer (confirm.rs HIGH-13).
    let _trusted_ui_wait = timeout::TrustedUiWaitGuard::enter();

    #[cfg(feature = "ui-px-frametime")]
    frametime::enable();
    #[allow(unused_mut)]
    let mut overlay_buf = [0u8; 24];
    // Worst-case accumulators for the bench overlay (republished once a second).
    #[cfg(feature = "ui-px-frametime")]
    let (mut ft_max_render, mut ft_max_blit, mut ft_max_period, mut ft_window_at) = (0u32, 0u32, 0u32, 0u32);
    #[cfg(feature = "ui-px-frametime")]
    let (mut ft_max_shapes, mut ft_max_glyphs, mut ft_max_secret) = (0u32, 0u32, 0u32);
    let (mut ft_max_stream, mut ft_max_wire_last, mut ft_max_te) = (0u32, 0u32, 0u32);
    let mut wire_buf = [0u8; 24];
    let mut wire_len = 0usize;
    #[cfg(feature = "ui-px-frametime")]
    let (mut split_buf, mut split_len) = ([0u8; 24], 0usize);
    #[allow(unused_mut)]
    let mut overlay_len = 0usize;
    #[allow(unused_mut, unused_variables)]
    let mut last_frame_at = now;

    let mut painted_idx = usize::MAX;
    // (screen index, page) most recently handed to `build_and_present`.
    let mut presented_at: Option<(usize, u8)> = None;
    let result = loop {
        if deadline_expired() {
            break (PxOutcome::DeadlineExpired, crate::fi::FAIL_SENTINEL);
        }
        if timeout::is_idle() {
            break (PxOutcome::IdleWipe, crate::fi::FAIL_SENTINEL);
        }
        // The design's arming for the screen currently shown (kind ∈ {hero,
        // confirm}, commit byte double-read); the decline fill reads it.
        let armed = driver.armed(visible);
        // Signing is narrower: the consent policy (`FlowDriver::sign_point`:
        // `Confirm?` or the last screen, never the opening ask or a detail),
        // and only once THIS screen and page have been presented in a
        // complete frame. `build_and_present` sits at the BOTTOM of this
        // loop, so without the latch an affirmative gesture drained on the
        // first iteration returns `Signed` before the request's first frame
        // is ever painted — consent for something the glass never showed.
        // Navigating disarms for exactly one frame, until the new page lands.
        let here = (driver.index(), driver.page());
        let sign_ok = presented_at == Some(here) && driver.sign_point(visible);
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
        #[cfg(feature = "ui-px-frametime")]
        let split_line = if split_len > 0 { Some(&split_buf[..split_len]) } else { None };
        #[cfg(feature = "ui-px-frametime")]
        let wire_line = if wire_len > 0 { Some(&wire_buf[..wire_len]) } else { None };
        #[cfg(not(feature = "ui-px-frametime"))]
        let split_line = None;
        #[cfg(not(feature = "ui-px-frametime"))]
        let wire_line = None;
        let cost = build_and_present(&anim, &marks, &font, overlay, split_line, wire_line);
        // Only a frame that reached the glass IN FULL presents the screen: a
        // garbled `Confirm?` or returning ask must not arm the chord.
        presented_at = cost.complete.then_some((driver.index(), driver.page()));
        #[cfg(feature = "ui-px-frametime")]
        {
            // WORST-CASE HOLD. A per-frame instantaneous readout is unreadable
            // on the glass — the owner reported the digits "move a lot and I
            // can't read quick enough". A frame BUDGET is about the worst case
            // anyway, not the latest sample, so accumulate the max of each
            // field and republish once a second.
            let t = timeout::now();
            let period = t.wrapping_sub(last_frame_at);
            last_frame_at = t;
            ft_max_render = ft_max_render.max(cost.render);
            ft_max_blit = ft_max_blit.max(cost.blit);
            ft_max_shapes = ft_max_shapes.max(cost.split.shapes);
            ft_max_glyphs = ft_max_glyphs.max(cost.split.glyphs.wrapping_add(cost.split.fills));
            ft_max_secret = ft_max_secret.max(cost.split.secret);
            ft_max_stream = ft_max_stream.max(cost.stream);
            ft_max_wire_last = ft_max_wire_last.max(cost.wire_last);
            ft_max_te = ft_max_te.max(cost.te_wait);
            // Skip the first frame's period: `last_frame_at` starts at 0, so
            // its "period" is the whole boot time, not a frame.
            if overlay_len > 0 {
                ft_max_period = ft_max_period.max(period);
            }
            if t.wrapping_sub(ft_window_at) >= 1_000 || overlay_len == 0 {
                overlay_len =
                    frametime::format(&mut overlay_buf, ft_max_render, ft_max_blit, ft_max_period);
                // Second line: where the render time actually goes.
                // shapes = CPU-forever (no DMA2D geometry engine)
                // glyphs = text + masks + fills, the DMA2D-offloadable part
                // secret = the constant-time seed path, NEVER offloadable
                split_len = frametime::format_tenths(
                    &mut split_buf,
                    ft_max_shapes,
                    ft_max_glyphs,
                    ft_max_secret,
                );
                wire_len = frametime::format_tenths(
                    &mut wire_buf,
                    ft_max_stream,
                    ft_max_wire_last,
                    ft_max_te,
                );
                ft_window_at = t;
                ft_max_stream = 0;
                ft_max_wire_last = 0;
                ft_max_te = 0;
                ft_max_render = 0;
                ft_max_blit = 0;
                ft_max_period = 0;
                ft_max_shapes = 0;
                ft_max_glyphs = 0;
                ft_max_secret = 0;
            }
        }
        #[cfg(not(feature = "ui-px-frametime"))]
        let _ = cost;
        // `cost.complete` FIRST, as for `presented_at` above: only a frame
        // that fully reached the glass counts as the screen having been shown
        // (`mark_rendered`, and the text mirror). Leaving `painted_idx`
        // unadvanced means the next good frame does the mark.
        if cost.complete && driver.index() != painted_idx {
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

/// The setup flow's pager (owner decisions 2026-10-15): the signing grammar
/// without a signature. Tap right moves to the next screen, tap left to the
/// previous one; the two-button click selects on a screen that asks
/// (`commit` byte set) once that screen has reached the glass in full; holds
/// do nothing. A right tap on the last screen returns `Forward` and a left tap
/// on the first returns `Back`, each only where the caller allows it.
///
/// No inactivity timeout: setup has no wallet to protect yet, and a timeout
/// that restarted setup threw away a seed the user may already have written
/// down (and looped forever on the EVT). The watchdog wait guard is held for
/// the whole wait, as in `run_flow`.
/// The animation a pager left on the glass, so the next pager continues
/// from it: the disc travels to the next step's place instead of being
/// redrawn there (owner report 2026-10-15, CREATE NEW WALLET? -> the PIN
/// help). Valid only while `CARRY_SET` is true AND the panel has not been
/// written since (`CARRY_GLASS` against `lcd::glass_writes`). Only the pager
/// stores it: its screens are public, where a PIN row's record holds a live
/// digit that must not outlive its dialog in a static.
///
/// Zeroed `MaybeUninit` plus a flag, as `FILM`, to keep it in `.bss`.
/// Single-threaded driver state, never touched from an ISR.
static mut CARRY: MaybeUninit<Anim> = MaybeUninit::zeroed();
static CARRY_SET: AtomicBool = AtomicBool::new(false);
static CARRY_GLASS: AtomicU32 = AtomicU32::new(0);
const _: () = assert!(!core::mem::needs_drop::<Anim>());

/// Keep `anim`, the last thing presented, for the next pager.
fn carry_keep(anim: Anim) {
    // SAFETY: single-threaded driver state; nothing else references CARRY
    // (`carry_take` moves out under `CARRY_SET`, cleared before the read),
    // and `Anim` needs no drop, so overwriting a live value leaks nothing.
    unsafe { (*core::ptr::addr_of_mut!(CARRY)).write(anim) };
    CARRY_GLASS.store(lcd::glass_writes(), Ordering::Relaxed);
    CARRY_SET.store(true, Ordering::Relaxed);
}

/// A resting CHECKING PIN kept by `play_screen`, when `s` is the verdict that
/// answers it and the glass still shows the pill.
fn pin_check_take(s: &Screen) -> Option<Anim> {
    if s.kind() != Some(pqsigner_ui_px::Kind::Verdict) {
        return None;
    }
    carry_take().filter(|a| pqsigner_ui_px::verdict::is_pin_check(a.current().0))
}

/// The kept animation, if the glass still shows it.
fn carry_take() -> Option<Anim> {
    if !CARRY_SET.swap(false, Ordering::Relaxed) || CARRY_GLASS.load(Ordering::Relaxed) != lcd::glass_writes() {
        return None;
    }
    // SAFETY: `CARRY_SET` was true, so `carry_keep` wrote it; clearing the
    // flag first makes this read the last one.
    Some(unsafe { (*core::ptr::addr_of_mut!(CARRY)).assume_init_read() })
}

pub fn run_pager(
    screens: &[Screen],
    start: usize,
    atlas: &assets::AtlasRef,
    may_back: bool,
    may_forward: bool,
) -> crate::ui::PagerOut {
    use crate::ui::PagerOut;
    let n = screens.len();
    let mut i = start.min(n.saturating_sub(1));
    film_abort();
    let marks = atlas.marks();
    let font = atlas.font();
    let now = timeout::now();
    // Continue from the previous pager when its frame is still on the glass
    // (the disc springs over, the text cross-fades); otherwise start at rest.
    let mut anim = match carry_take() {
        Some(mut a) => {
            a.go_to(&screens[i], 0, now);
            a
        }
        None => Anim::new(&screens[i], 0, now),
    };
    sampling_enable();
    // Seed from the buttons' current level, as `run_flow` does, so a chord
    // still held from the previous step does not select here.
    let sb = stable_bits();
    let mut fsm = InputFsm::resumed(InputCtx::NAV, sb & 1 != 0, sb & 2 != 0);
    let _trusted_ui_wait = timeout::TrustedUiWaitGuard::enter();
    let mut presented: Option<usize> = None;
    let result = loop {
        let (g, now) = drain(&mut fsm);
        if g.edge {
            timeout::reset_activity();
        }
        // An armed screen, or the tutorial's demonstration (`Nav::Hint`).
        let asks = screens[i].confirmable();
        let mut decided: Option<PagerOut> = None;
        for ev in g.buf[..g.n].iter().flatten() {
            match *ev {
                Gesture::Press(side) => anim.press(side, now),
                Gesture::Chord => {
                    if asks {
                        anim.hold(Btn::Right, pqsigner_ui_px::motion::HOLD_COMMIT_MS, now);
                    }
                }
                Gesture::ChordClick => {
                    if asks && presented == Some(i) {
                        anim.hold_commit(now);
                        decided = Some(PagerOut::Selected(i));
                    } else {
                        anim.hold_release(now);
                    }
                }
                Gesture::Tap(Btn::Right) => {
                    if i + 1 < n {
                        i += 1;
                        presented = None;
                        anim.go_to(&screens[i], 0, now);
                    } else if may_forward {
                        decided = Some(PagerOut::Forward);
                    }
                }
                Gesture::Tap(Btn::Left) => {
                    if i > 0 {
                        i -= 1;
                        presented = None;
                        anim.go_to(&screens[i], 0, now);
                    } else if may_back {
                        decided = Some(PagerOut::Back);
                    }
                }
                Gesture::HoldCancel(_) | Gesture::HoldCommit(_) => anim.hold_release(now),
                Gesture::HoldStart(_) | Gesture::Release(_) | Gesture::DoubleTap(_) => {}
            }
            if decided.is_some() {
                break;
            }
        }
        if let Some(d) = decided {
            break d;
        }
        let animating = anim.step(now);
        let cost = build_and_present(&anim, &marks, &font, None, None, None);
        if cost.complete {
            presented = Some(i);
        }
        if !animating && anim.next_wake(now).is_none() && stable_bits() == 0 {
            loop {
                cortex_m::asm::wfi();
                if ring_has_edges() || stable_bits() != 0 {
                    break;
                }
            }
        } else {
            while now.wrapping_add(FRAME_PERIOD_MS).wrapping_sub(timeout::now()) < (1 << 31) {
                if ring_has_edges() {
                    break;
                }
                cortex_m::asm::wfi();
            }
        }
    };
    sampling_disable();
    carry_keep(anim);
    result
}

/// An entry row's input wait (the PIN, a word's letters) on the timestamped
/// input path the pager and the signing flow use.
///
/// WHY (owner report 2026-10-15). The entry rows used to wait on the legacy
/// button driver, which may only draw while no button is down (it times a
/// hold by counting its own polls) and stops polling for every frame it
/// draws. The row's hint fade froze on each press and slowed the presses it
/// overlapped. Here the SysTick sampler records every edge with its time and
/// the FSM turns them into gestures, so the row draws through presses
/// without delaying or losing one.
///
/// It hands back the legacy events the entry loops already speak, so their
/// grammar (and every pin on it) is unchanged. The reading is
/// `pqsigner_ui_px::input::EntryGrammar` (host-tested there): a tap is
/// `(side, Short)`; a hold that reaches 500 ms (the legacy long press) is
/// `(side, Long)` at once, then nothing more until both buttons are up; the
/// two-button click is `(Right, Long)`, the confirm.
///
/// Lives for one entry dialog; `wait` once per event. It re-syncs (drops
/// stale edges, adopts the live button level) whenever something else drew
/// since its last frame, because then another dialog had the buttons: the
/// letter row's candidate list and its NO SUCH WORD notice run between two
/// of its waits. No `reset_activity` here: the entry loops reset after each
/// event they receive (#426).
pub struct EntryInput {
    fsm: InputFsm,
    grammar: EntryGrammar,
    anim: Option<Anim>,
    queue: [Option<(crate::ui::Button, crate::ui::Press)>; 4],
    /// `lcd::glass_writes` after this wait's last frame.
    glass: u32,
    /// Sampling is on and `fsm` tracks it.
    live: bool,
}

impl EntryInput {
    #[must_use]
    pub fn new() -> Self {
        Self {
            fsm: InputFsm::new(InputCtx::NAV),
            grammar: EntryGrammar::default(),
            anim: None,
            queue: [None; 4],
            glass: 0,
            live: false,
        }
    }

    fn sync(&mut self) {
        sampling_enable();
        let sb = stable_bits();
        self.fsm = InputFsm::resumed(InputCtx::NAV, sb & 1 != 0, sb & 2 != 0);
        self.queue = [None; 4];
        self.grammar = EntryGrammar::default();
        self.live = true;
    }

    fn pop(&mut self) -> Option<(crate::ui::Button, crate::ui::Press)> {
        let ev = self.queue[0].take();
        self.queue.rotate_left(1);
        ev
    }

    fn push(&mut self, ev: (crate::ui::Button, crate::ui::Press)) {
        if let Some(slot) = self.queue.iter_mut().find(|q| q.is_none()) {
            *slot = Some(ev);
        }
    }

    /// Show `s` (kept drawing while it waits) and return the next event, or
    /// `None` when `idle` fires.
    pub fn wait(
        &mut self,
        s: &Screen,
        atlas: &assets::AtlasRef,
        idle: &mut dyn FnMut() -> bool,
    ) -> Option<(crate::ui::Button, crate::ui::Press)> {
        use crate::ui::{Button, Press};
        if !self.live || lcd::glass_writes() != self.glass {
            self.sync();
        }
        if let Some(ev) = self.pop() {
            return Some(ev);
        }
        film_abort();
        let marks = atlas.marks();
        let font = atlas.font();
        // A new record (a press changed the row): start it at rest.
        if self.anim.as_ref().map_or(true, |a| a.current().0 .0 != s.0) {
            self.anim = Some(Anim::new(s, 0, timeout::now()));
        }
        let mut drawn = false;
        loop {
            if idle() {
                return None;
            }
            let (g, now) = drain(&mut self.fsm);
            let side = |b: Btn| if b == Btn::Left { Button::Left } else { Button::Right };
            for &ev in g.buf[..g.n].iter().flatten() {
                if let Gesture::Press(b) = ev {
                    if let Some(a) = self.anim.as_mut() {
                        a.press(b, now);
                    }
                }
                let mapped = match self.grammar.feed(ev) {
                    Some(EntryEvent::Tap(b)) => Some((side(b), Press::Short)),
                    Some(EntryEvent::Hold(b)) => Some((side(b), Press::Long)),
                    Some(EntryEvent::Confirm) => Some((Button::Right, Press::Long)),
                    None => None,
                };
                if let Some(m) = mapped {
                    self.push(m);
                }
            }
            if stable_bits() == 0 {
                self.grammar.released();
            }
            if let Some(ev) = self.pop() {
                return Some(ev);
            }
            let Some(anim) = self.anim.as_mut() else { return None };
            let _ = anim.step(now);
            // Paint the row once, then only while something on it moves (the
            // hint's fade, a press nudge): between fades it is the same frame.
            let still = anim.cycle_wake(now);
            if !drawn || still.is_none() {
                let _ = build_and_present(anim, &marks, &font, None, None, None);
                drawn = true;
                self.glass = lcd::glass_writes();
            }
            // Sleep until the next change, an edge, or idle; a held button
            // is polled at the frame rate so its hold is timed.
            let mut wake = still.unwrap_or(now.wrapping_add(FRAME_PERIOD_MS));
            if stable_bits() != 0 {
                let poll = now.wrapping_add(FRAME_PERIOD_MS);
                if poll.wrapping_sub(wake) >= (1 << 31) {
                    wake = poll;
                }
            }
            while wake.wrapping_sub(timeout::now()).wrapping_sub(1) < (1 << 31) {
                if ring_has_edges() || idle() {
                    break;
                }
                cortex_m::asm::wfi();
            }
        }
    }
}

impl Default for EntryInput {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EntryInput {
    fn drop(&mut self) {
        if self.live {
            sampling_disable();
        }
        // The last row's record holds the dialed digit (or a typed letter of
        // a seed word): overwrite it rather than leave it on the stack.
        if let Some(a) = self.anim.as_mut() {
            // SAFETY: `a` is a valid, exclusive reference to an initialised
            // `Anim`; `Anim` needs no drop (asserted at `CARRY`), and the
            // volatile write keeps the scrub from being optimised away.
            unsafe { core::ptr::write_volatile(a, Anim::new(&Screen::BLANK, 0, 0)) };
        }
    }
}

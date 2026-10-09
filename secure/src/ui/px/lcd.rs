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
use zeroize::Zeroize;
use pqsigner_ui_px::scene::{Anim, Ending, Marks};
use pqsigner_ui_px::{Screen, Screens};

/// Frame pacing while something animates (~60 fps cap); a frame that already
/// took longer starts the next one immediately.
const FRAME_PERIOD_MS: u32 = 16;

/// Landscape COLUMNS per band: 9 bands per frame, 13,632 B of BSS.
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
#[cfg(feature = "ui-px-dma")]
const N_BANDBUF: usize = 2;
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
    /// actually knows the frame was dropped: otherwise `mark_rendered` runs
    /// and `PX_COMMIT_REQUIRES_SEEN_LAST` (owner decision 2026-09-24,
    /// `HARDENING.md` §2.4) counts a garbled amount or recipient page as
    /// SEEN, arming the sign chord on something never legibly displayed.
    complete: bool,
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
fn present_frame_ex(frame: &Frame<'_>, font: &Font<'_>, _force: bool) -> FrameCost {
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
    let w0 = BAND_W.min(W);
    #[cfg(feature = "ui-px-frametime")]
    let t0 = frametime::cycles();
    {
        let Some(mut strip) = Strip::new(0, w0, &mut bands[0].0[..]) else {
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
    let synced = crate::hw::lcd_te::sync_to_scanout(2_000_000);
    let _ = synced;
    #[cfg(feature = "ui-px-frametime")]
    let t_edge = frametime::cycles();
    #[cfg(feature = "ui-px-frametime")]
    {
        cost.te_wait = t_edge.wrapping_sub(t_te);
    }

    // ONE window for the whole frame. The panel auto-increments across all
    // 428 native rows, so the nine band transfers below are a single
    // continuous stream and nothing may send a command (DC low) between them.
    lcd::set_window(0, 0, (H - 1) as u16, (W - 1) as u16);
    lcd::stream_open();

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

    let mut x0 = w0;
    while x0 < W {
        let w = BAND_W.min(W - x0);
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
    cost.complete = ok && x0 >= W;
    #[cfg(feature = "ui-px-frametime")]
    {
        cost.stream = frametime::cycles().wrapping_sub(t_edge);
    }
    // `_guard` wipes the band buffers and clears the latch here.
    cost
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
/// touched by that clear and still hold an EARLIER band's ink. Under the
/// two-buffer ping-pong the parity is fixed (bands 0,2,4,6,8 all land in
/// `BANDS[0]`), so that residue is band SIX's, not band seven's as a reader
/// of the alternation would assume. Zeroizing the array rather than the used
/// prefix is what makes that irrelevant.
///
/// Unconditional rather than gated on a "this frame was secret" flag: that is
/// the same kind of remembered relationship the review objected to. The cost
/// is one clear of a buffer `render_strip` already clears nine times a frame
/// (~0.085 ms against a 24.31 ms wire), so there is nothing to buy by being
/// clever. Iterating `BANDS` rather than naming each buffer is deliberate:
/// adding a third would otherwise leave one un-wiped, silently.
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
        // one: `mark_rendered` would never run, `seen_last` would never set,
        // and the chord would never arm. The bench config would have looked
        // perfect throughout.
        cost = FrameCost {
            complete: cost.complete,
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
/// The film's runtime + the wall-clock ms of its last presented frame.
/// Single-threaded driver state: touched only from the sign handler's
/// thread of execution, never from an ISR.
static mut FILM: Option<(Anim, u32)> = None;

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
    let now = timeout::now();
    let mut anim = Anim::new(s, 0, now);
    anim.film_start(now);
    let _ = build_and_present(&anim, &atlas.marks(), &atlas.font(), None, None, None);
    // SAFETY: `FILM` is single-threaded driver state (no ISR touches it) and
    // this is the only writer while `FILM_LIVE` is false.
    unsafe {
        *core::ptr::addr_of_mut!(FILM) = Some((anim, now));
    }
    FILM_LIVE.store(true, Ordering::Relaxed);
}

/// One frame of the running film, if one is due — the signer's `fn(u8)`
/// progress hook. `_percent` is not used for the pose: the film is a pure
/// function of the S-only clock. Bounded: at most one frame per
/// `FRAME_PERIOD_MS`, and a frame that overran 50 ms skips the next slot, so
/// the sign chain is never delayed by more than one frame per call.
pub fn film_tick(_percent: u8) {
    if !FILM_LIVE.load(Ordering::Relaxed) {
        return;
    }
    let now = timeout::now();
    // SAFETY: single-threaded driver state; `film_start` published it and
    // no other reference is live during this call.
    let Some((anim, last)) = (unsafe { &mut *core::ptr::addr_of_mut!(FILM) }).as_mut() else {
        return;
    };
    if now.wrapping_sub(*last) < FRAME_PERIOD_MS {
        return;
    }
    let Some(atlas) = assets::atlas_film_frame() else {
        return;
    };
    anim.step(now);
    let _ = build_and_present(anim, &atlas.marks(), &atlas.font(), None, None, None);
    let after = timeout::now();
    *last = if after.wrapping_sub(now) > 50 { after.wrapping_add(FRAME_PERIOD_MS) } else { after };
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
    let now = timeout::now();
    FILM_LIVE.store(false, Ordering::Relaxed);
    // SAFETY: single-threaded driver state; taking it leaves `None` behind
    // so a later tick is a no-op.
    let taken = unsafe { core::ptr::replace(core::ptr::addr_of_mut!(FILM), None) };
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
}

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

/// Drop a running film without landing it (error paths).
pub fn film_abort() {
    FILM_LIVE.store(false, Ordering::Relaxed);
    // SAFETY: single-threaded driver state.
    unsafe {
        *core::ptr::addr_of_mut!(FILM) = None;
    }
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

/// Play a non-dialog record from its arrival until it rests, leaving the
/// resting frame on the glass; `secret` grid cells are painted over every
/// frame by the constant-time run, and such a frame streams every strip.
/// With a stopped clock only the resting frame is shown.
pub fn play_screen(s: &Screen, atlas: &assets::AtlasRef, secret: &[(usize, &[u8])]) {
    film_abort();
    let marks = atlas.marks();
    let font = atlas.font();
    let force = !secret.is_empty();
    let paint = |anim: &Anim| {
        let mut frame = Frame::new();
        anim.build(&marks, &font, &mut frame);
        for &(k, w) in secret {
            pqsigner_ui_px::rows::push_secret_word(&mut frame, k, w, 255);
        }
        let _ = present_frame_ex(&frame, &font, force);
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
        let mut anim = Anim::new(s, 0, t0);
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
    }
    if force {
    }
}

/// Idle time after which the #802 probe calls `reset_activity()` ONCE.
///
/// 180 s: comfortably past the 120 s boundary, so the degraded state has been
/// established and read off the glass before the gate is closed again.
#[cfg(feature = "ui-px-frametime")]
const ONE_SHOT_RESET_MS: u32 = 180_000;

/// #805 condition (d): the boot-time one-shot `fi::wait_random()` fallback
/// measurement — `(calls, fallbacks)` for a SINGLE top-level delay, taken by
/// the bench in thread mode before anything else runs.
///
/// Measured rather than inferred because the carve-out requires it; see the
/// rationale on `crate::rng::NONSECRET_CALLS`.
#[cfg(feature = "ui-px-frametime")]
static FALLBACK_SHOT_CALLS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[cfg(feature = "ui-px-frametime")]
static FALLBACK_SHOT_FB: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Publish the one-shot probe for the overlay.
#[cfg(feature = "ui-px-frametime")]
pub fn set_fallback_probe(calls: u32, fallbacks: u32) {
    use core::sync::atomic::Ordering::Relaxed;
    FALLBACK_SHOT_CALLS.store(calls, Relaxed);
    FALLBACK_SHOT_FB.store(fallbacks, Relaxed);
}

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
#[cfg(feature = "ui-px-frametime")]
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
                //   shot_hits   pool bytes served to ONE top-level
                //               `fi::wait_random()`, measured at boot in
                //               thread mode with a clean guard. Expect 31 —
                //               the measured fan-out — and a 0 here means the
                //               pool never armed, i.e. the #832 fix is inert.
                //   shot_fb     fallbacks on that same call. Expect 0. This
                //               going to zero IS the fix: before #832 it was
                //               31, every one of them replaying a single byte
                //               and making the receipt-recheck separation a
                //               known constant.
                //   misses      pool exhaustion since boot: a delay that
                //               found the pool ARMED but empty and had to
                //               replay after all. The one new degradation
                //               #832 introduces, and the number that sizes
                //               `POOL_LEN`/`REFILL_BELOW`. Expect 0; anything
                //               else means a fill length drains the pool
                //               faster than the per-output-word top-up fills
                //               it.
                //
                // Self-diagnosing: `shot_calls = 0` means the probe never
                // ran, and `shot_calls = 1` with `shot_fallbacks = 1` means
                // the OUTER draw failed too (RNG not yet initialised), so a
                // misleading reading cannot pass as a real one.
                let (shot_hits, shot_fb, misses) = {
                    #[cfg(feature = "ui-px-frametime")]
                    {
                        use core::sync::atomic::Ordering::Relaxed;
                        (
                            FALLBACK_SHOT_CALLS.load(Relaxed),
                            FALLBACK_SHOT_FB.load(Relaxed),
                            crate::fi_delay_pool::MISSES.load(Relaxed),
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
                    shot_hits.min(999),
                    shot_fb.min(999),
                    misses.min(999),
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
        // Arming follows the screen currently shown (kind ∈ {hero, confirm},
        // commit byte double-read, and the consent policy).
        let armed = driver.armed(visible);
        // Arming also requires that THIS screen and page have already been
        // presented. `build_and_present` sits at the BOTTOM of this loop, so
        // without the latch an affirmative gesture drained on the first
        // iteration returns `Signed` before the request's first frame is
        // ever painted — consent for something the glass never showed.
        // Navigating disarms for exactly one frame, until the new page lands.
        let here = (driver.index(), driver.page());
        let sign_ok = presented_at == Some(here)
            && armed.sign
            && (!super::PX_COMMIT_REQUIRES_SEEN_LAST || driver.seen_last());
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
        presented_at = Some((driver.index(), driver.page()));
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
        // `cost.complete` FIRST. `mark_rendered` is what sets `seen_last`,
        // which is the whole of `PX_COMMIT_REQUIRES_SEEN_LAST`: arming the
        // sign chord off a frame that did not fully reach the glass would
        // approve a recipient or amount the user never legibly saw. Leaving
        // `painted_idx` unadvanced means the next good frame does the mark.
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

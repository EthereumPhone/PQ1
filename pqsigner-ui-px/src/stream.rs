//! Bookkeeping for streaming one frame's bands to the panel in the
//! background (#934 stage 2, the busy film only).
//!
//! The thread renders the bands in order and queues each one; the DMA
//! completion interrupt finishes a band and starts the next queued one. One
//! DMA channel carries the stream, so at most one band is on the wire, and
//! bands go out strictly in order (the panel auto-increments through one
//! window). The two sides share these counters under a critical section on
//! the thread's side; the rules live here so they are host-tested rather than
//! trusted on the device.
//!
//! Display only: nothing here decides what is signed.

/// What the caller does after an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Start sending band `n` (its index in the frame) now.
    Start(u8),
    /// Nothing to start: a band is on the wire, or the next one is not
    /// queued yet (the next event starts it).
    Idle,
    /// Every band has been sent: close the stream.
    Finished,
}

/// The counters of one frame's stream: `total` bands, of which `queued` are
/// rendered and handed over, `started` have been put on the wire and `sent`
/// have left it. Always `sent <= started <= queued <= total`, and
/// `started - sent <= 1`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BandQueue {
    total: u8,
    queued: u8,
    started: u8,
    sent: u8,
}

impl BandQueue {
    /// A stream of `total` bands, none queued.
    #[must_use]
    pub const fn new(total: u8) -> Self {
        Self { total, queued: 0, started: 0, sent: 0 }
    }

    /// The thread has rendered the next band and hands it over. `None` if
    /// every band was already queued (a caller bug, refused); otherwise what
    /// to do: start it at once when the wire is idle, else nothing (the
    /// completion of the band on the wire starts it).
    pub fn queue(&mut self) -> Option<Step> {
        if self.queued >= self.total {
            return None;
        }
        self.queued += 1;
        Some(self.next())
    }

    /// The band on the wire has been sent (DMA complete and the SPI drained).
    /// `None` if no band was on the wire (a spurious completion, ignored).
    pub fn sent(&mut self) -> Option<Step> {
        if self.started == self.sent {
            return None;
        }
        self.sent += 1;
        if self.sent == self.total {
            return Some(Step::Finished);
        }
        Some(self.next())
    }

    fn next(&mut self) -> Step {
        if self.started == self.sent && self.started < self.queued {
            let n = self.started;
            self.started += 1;
            Step::Start(n)
        } else {
            Step::Idle
        }
    }

    /// Whether band `k` may be rendered into buffer `k % n_buf`: the band
    /// that last used that buffer, `k - n_buf`, has left the wire.
    #[must_use]
    pub fn buffer_free(&self, k: u8, n_buf: u8) -> bool {
        u16::from(k) < u16::from(self.sent) + u16::from(n_buf)
    }

    /// Bands queued so far.
    #[must_use]
    pub fn queued_count(&self) -> u8 {
        self.queued
    }

    /// Bands sent so far.
    #[must_use]
    pub fn sent_count(&self) -> u8 {
        self.sent
    }

    /// Whether every band has been sent.
    #[must_use]
    pub fn finished(&self) -> bool {
        self.total > 0 && self.sent == self.total
    }
}

/// When a partial frame may start streaming, from the time since the panel's
/// last TE edge (#934 stage 1). Pure arithmetic on cycle counts at 160 MHz,
/// so every input is host-checked, overflow included (release builds keep
/// `overflow-checks`: an overflow here is a panic on the device).
///
/// The scan model is the one the firmware's presenter states its tear-free
/// start in and that the glass confirmed (no split seen, partial and full,
/// 2026-10-16): the beam is at row [`TE_SCANLINE`] at the TE edge and moves
/// 26.75 rows/ms (428 rows per 16.0 ms); the write moves 15.3 rows/ms. A
/// window [xa, xend) may start while the beam's row r satisfies
///   r >= xa                                   (the write trails the beam)
///   r <  W + xend - 26.75/15.3 * (xend - xa)  (the beam does not lap the
///                                              write before it ends)
/// with [`PHASE_MARGIN_ROWS`] kept off both ends.
///
/// 2026-10-19 the panel moved its TE pulse by 3.6 ms for 200 tear scanlines
/// (the film bench's probe), not the 7.5 ms this model predicts, so the
/// scanline register's unit is not a row of this model. Nothing here depends
/// on that register; the firmware keeps it at [`TE_SCANLINE`].
pub mod phase {
    use crate::raster::W;

    /// The panel's tear scanline: the beam's row at the TE edge.
    pub const TE_SCANLINE: i32 = 16;
    /// Beam rows per cycle: 26.75 rows/ms = 107 / 640,000 at 160 MHz.
    pub const BEAM_ROWS_NUM: u32 = 107;
    pub const BEAM_ROWS_DEN: u32 = 640_000;
    /// One refresh, 16.0 ms, in cycles.
    pub const REFRESH_CYC: u32 = 2_560_000;
    /// Kept off both ends of the start range: 1 ms of beam.
    pub const PHASE_MARGIN_ROWS: i32 = 27;
    /// A stamp older than this means no edge for over a refresh: the caller
    /// falls back to waiting for the edge.
    pub const STAMP_STALE_CYC: u32 = REFRESH_CYC + REFRESH_CYC / 8;

    /// The cycles after a TE edge during which window [xa, xend) may start
    /// streaming, or `None` if the range is empty or the window is not one
    /// (`0 <= xa < xend <= W` is required).
    #[must_use]
    pub fn start_window(xa: i32, xend: i32) -> Option<(u32, u32)> {
        if !(0 <= xa && xa < xend && xend <= W) {
            return None;
        }
        let w = xend - xa;
        let lo = xa.max(TE_SCANLINE) + PHASE_MARGIN_ROWS;
        // 26.75 / 15.3 = 1.7484 beam rows per written row, rounded up.
        let hi = (W + xend - (w * 1749 + 999) / 1000 - PHASE_MARGIN_ROWS).min(W - 1);
        if hi < lo {
            return None;
        }
        let cyc = |row: i32| (row - TE_SCANLINE) as u32 * BEAM_ROWS_DEN / BEAM_ROWS_NUM;
        Some((cyc(lo), cyc(hi)))
    }

    /// Cycles until the start range [lo, hi] opens, `since` cycles after the
    /// last edge: `None` when it is open now. Past `hi` it is the next
    /// refresh's `lo`; an edge that is late (`since` beyond that) gives 0.
    #[must_use]
    pub fn wait(since: u32, lo: u32, hi: u32) -> Option<u32> {
        if (lo..=hi).contains(&since) {
            None
        } else if since < lo {
            Some(lo - since)
        } else {
            Some((REFRESH_CYC + lo).saturating_sub(since))
        }
    }

    /// Whether a stream that could start `at` cycles after an edge (taken
    /// modulo the refresh) is in range, or at most `spin_ok` before it, in
    /// this refresh or the next.
    #[must_use]
    pub fn start_ok(at: u32, lo: u32, hi: u32, spin_ok: u32) -> bool {
        (at <= hi && at.saturating_add(spin_ok) >= lo) || at.saturating_add(spin_ok) >= REFRESH_CYC.saturating_add(lo)
    }

    /// For a frame that may not start now (`at`, as in [`start_ok`], is
    /// outside the start range [lo, hi] and its allowance): whether to wait
    /// for the next tick, expected `dt` cycles later. It should, unless that
    /// tick would land past the end of the range it is waiting for (this
    /// refresh's, or the next one's once `at` is past `hi`): then waiting
    /// skips the range and the frame should start now and spin instead.
    ///
    /// The busy film used `!start_ok(at + dt)` here, which also chose to
    /// draw now when the next tick merely would not be in range YET, so a
    /// frame whose first due tick was early always spun to its range (EVT
    /// 2026-10-22: 2.6 ms per frame, 95% of frames at least 2 ms early).
    #[must_use]
    pub fn wait_for_next_tick(at: u32, dt: u32, hi: u32) -> bool {
        let end = if at <= hi { hi } else { REFRESH_CYC.saturating_add(hi) };
        at.saturating_add(dt) <= end
    }

    /// Whether a CPU-bound film frame may start now, paced to every second
    /// TE refresh: `edges` refresh edges have passed since the previous
    /// frame's stream started, the latest `since` cycles ago, and `hi` ends
    /// the start range of the frame's window (`None`: not known). Never in
    /// the refresh right after the previous frame's, unless that refresh's
    /// start range has already passed: the stream then starts in the next
    /// one, two refreshes on, like every other frame.
    #[must_use]
    pub fn second_refresh_due(edges: u32, since: u32, hi: Option<u32>) -> bool {
        match edges {
            0 => false,
            1 => hi.is_some_and(|hi| since > hi),
            _ => true,
        }
    }

    /// A finished stream into window [xa, xend) checked against the scan
    /// model, for the dev tearing readout: it started `since` cycles after a
    /// TE edge and left the wire `dur` cycles later. Returns whether it
    /// started before the beam had passed `xa` (the faster beam then
    /// overtakes the write inside this refresh), and its margin in cycles
    /// against the next refresh's beam reaching `xend`; negative means that
    /// beam overtook the write pointer. Both are tears by the model.
    #[must_use]
    pub fn tear_check(xa: i32, xend: i32, since: u32, dur: u32) -> (bool, i64) {
        let beam_at = |row: i32| i64::from(row - TE_SCANLINE) * i64::from(BEAM_ROWS_DEN) / i64::from(BEAM_ROWS_NUM);
        let early = i64::from(since) < beam_at(xa);
        let margin = i64::from(REFRESH_CYC) + beam_at(xend) - (i64::from(since) + i64::from(dur));
        (early, margin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_before_completion_waits_for_the_wire() {
        let mut q = BandQueue::new(3);
        assert_eq!(q.queue(), Some(Step::Start(0)));
        assert_eq!(q.queue(), Some(Step::Idle), "band 0 is on the wire");
        assert_eq!(q.queue(), Some(Step::Idle));
        assert_eq!(q.sent(), Some(Step::Start(1)));
        assert_eq!(q.sent(), Some(Step::Start(2)));
        assert_eq!(q.sent(), Some(Step::Finished));
        assert!(q.finished());
    }

    #[test]
    fn completion_before_queue_lets_the_queue_start_it() {
        // The thread is still rendering band 1 when band 0 leaves the wire:
        // the completion finds nothing queued, and the queue starts it.
        let mut q = BandQueue::new(2);
        assert_eq!(q.queue(), Some(Step::Start(0)));
        assert_eq!(q.sent(), Some(Step::Idle));
        assert_eq!(q.queue(), Some(Step::Start(1)));
        assert_eq!(q.sent(), Some(Step::Finished));
    }

    #[test]
    fn refuses_overqueue_and_spurious_completions() {
        let mut q = BandQueue::new(1);
        assert_eq!(q.sent(), None, "nothing on the wire");
        assert_eq!(q.queue(), Some(Step::Start(0)));
        assert_eq!(q.queue(), None, "all bands already queued");
        assert_eq!(q.sent(), Some(Step::Finished));
        assert_eq!(q.sent(), None);
    }

    #[test]
    fn a_buffer_is_reused_only_after_its_band_left_the_wire() {
        let mut q = BandQueue::new(6);
        for k in 0..4 {
            assert!(q.buffer_free(k, 4));
        }
        assert!(!q.buffer_free(4, 4), "band 0 still holds buffer 0");
        let _ = q.queue();
        let _ = q.sent();
        assert!(q.buffer_free(4, 4));
        assert!(!q.buffer_free(5, 4));
    }

    /// Every interleaving of the two sides, for every frame size the film
    /// can stream: one band on the wire at most, bands started in order and
    /// only once queued, buffers never reused early, and `Finished` exactly
    /// once, after the last band.
    #[test]
    fn every_interleaving_keeps_the_invariants() {
        const N_BUF: u8 = 4;
        for total in 1..=9u8 {
            // Event strings over {q, s}: explore all of them breadth-first.
            let mut frontier = std::vec![(BandQueue::new(total), std::vec::Vec::<u8>::new(), 0u8, false)];
            while let Some((q, starts, rendered, done)) = frontier.pop() {
                assert!(q.sent <= q.started && q.started <= q.queued && q.queued <= q.total);
                assert!(q.started - q.sent <= 1, "one band on the wire");
                assert_eq!(starts.len(), q.started as usize);
                assert!(starts.iter().enumerate().all(|(i, &n)| n as usize == i), "in order");
                if done {
                    assert!(q.finished());
                    continue;
                }
                // The thread renders band `rendered` only when its buffer is
                // free, then queues it.
                if rendered < total && q.buffer_free(rendered, N_BUF) {
                    // The band that last used this buffer has left the wire.
                    assert!(rendered < N_BUF || rendered - N_BUF < q.sent);
                    let mut q2 = q;
                    let mut s2 = starts.clone();
                    match q2.queue().expect("not over-queued") {
                        Step::Start(n) => s2.push(n),
                        Step::Idle => {}
                        Step::Finished => panic!("queue never finishes"),
                    }
                    frontier.push((q2, s2, rendered + 1, false));
                }
                // The wire completes a band, if one is on it.
                if q.started > q.sent {
                    let mut q2 = q;
                    let mut s2 = starts.clone();
                    let fin = match q2.sent().expect("a band was on the wire") {
                        Step::Start(n) => {
                            s2.push(n);
                            false
                        }
                        Step::Idle => false,
                        Step::Finished => {
                            assert_eq!(q2.sent, total, "finished only after the last band");
                            true
                        }
                    };
                    frontier.push((q2, s2, rendered, fin));
                }
                // No deadlock: something can always happen until done.
                assert!(
                    (rendered < total && q.buffer_free(rendered, N_BUF)) || q.started > q.sent,
                    "stuck at {q:?}, rendered {rendered}"
                );
            }
        }
    }

    /// Every window the film can stream and every time since an edge up to
    /// the stale limit: no arithmetic overflows (tests build with overflow
    /// checks, as the device does), the range keeps the presenter's
    /// tear-free conditions, and `wait` is `None` exactly inside it.
    #[test]
    fn phase_math_never_overflows_and_keeps_the_start_conditions() {
        use super::phase::*;
        use crate::raster::W;
        let mut windows = 0;
        for xa in (0..W).step_by(48) {
            for xend in (xa + 1)..=W {
                let Some((lo, hi)) = start_window(xa, xend) else { continue };
                windows += 1;
                assert!(lo <= hi && hi < REFRESH_CYC);
                // Back to beam rows (rounding down): the start conditions hold.
                let row = |c: u32| TE_SCANLINE + (c * BEAM_ROWS_NUM / BEAM_ROWS_DEN) as i32;
                assert!(row(lo) >= xa, "the write trails the beam ({xa}..{xend})");
                let w = f64::from(xend - xa);
                let lap = f64::from(W + xend) - 26.75 / 15.3 * w;
                assert!(f64::from(row(hi)) < lap, "no lap before the end ({xa}..{xend})");
                for since in (0..=STAMP_STALE_CYC).step_by(997).chain([0, lo, hi, REFRESH_CYC, REFRESH_CYC + 1, STAMP_STALE_CYC]) {
                    match wait(since, lo, hi) {
                        None => assert!((lo..=hi).contains(&since)),
                        Some(d) => {
                            assert!(!(lo..=hi).contains(&since));
                            assert!(d <= REFRESH_CYC + lo);
                        }
                    }
                    for spin in [0, 320_000, REFRESH_CYC] {
                        let _ = start_ok(since % REFRESH_CYC, lo, hi, spin);
                        let _ = start_ok(since, lo, hi, spin);
                    }
                }
            }
        }
        assert!(windows > 1000, "the sweep reached the real windows ({windows})");
        // Not a window: refused rather than computed.
        assert_eq!(start_window(10, 10), None);
        assert_eq!(start_window(-48, 48), None);
        assert_eq!(start_window(0, W + 1), None);
    }

    /// Waiting for the next tick is chosen exactly when that tick does not
    /// skip the range being waited for: early frames wait (however far the
    /// range), a frame whose next tick would overshoot starts now.
    #[test]
    fn wait_for_next_tick_waits_unless_the_tick_would_skip_the_range() {
        use super::phase::*;
        let (lo, hi) = start_window(96, 240).expect("a film window");
        // Far before the range, ticks 0.3 ms apart: wait.
        assert!(wait_for_next_tick(lo / 4, 48_000, hi));
        // Just before it, the next tick inside it: wait.
        assert!(wait_for_next_tick(lo - 10_000, 48_000, hi));
        // Sparse ticks that would jump past the whole range: start now.
        assert!(!wait_for_next_tick(lo - 10_000, hi - lo + 20_000, hi));
        // Past this refresh's range: wait for the next refresh's, unless the
        // next tick would overshoot that one too.
        assert!(wait_for_next_tick(hi + 1, 48_000, hi));
        assert!(!wait_for_next_tick(hi + 1, REFRESH_CYC, hi));
        // Sweep: the answer is exactly "the next tick lands no later than the
        // end of the range ahead".
        for at in (0..REFRESH_CYC).step_by(7_919) {
            for dt in [1, 48_000, 160_000, 960_000, REFRESH_CYC] {
                let end = if at <= hi { hi } else { REFRESH_CYC + hi };
                assert_eq!(wait_for_next_tick(at, dt, hi), at + dt <= end, "at={at} dt={dt}");
            }
        }
    }

    /// The tearing readout's model agrees with the measured full sweep and
    /// with the start range: #790 measured a full frame, started at the TE
    /// edge, at 27.9 ms of wire against a 31.40 ms bound, i.e. 3.5 ms inside.
    #[test]
    fn tear_check_matches_the_measured_sweep_and_the_start_range() {
        use super::phase::*;
        use crate::raster::W;
        const MS: u32 = 160_000;
        let (early, margin) = tear_check(0, W, 0, 27_900 * (MS / 1000));
        assert!(!early);
        assert!((margin - i64::from(3_500 * (MS / 1000))).abs() < i64::from(MS / 20), "{margin}");
        // A stall of 4 ms more on the same frame is a tear.
        assert!(tear_check(0, W, 0, 31_900 * (MS / 1000)).1 < 0);
        // Every start range, entered anywhere in it with the wire at the
        // speed the range assumes (15.3 rows/ms), is tear-free with most of
        // the 27-row (~1 ms) margin left at its late end.
        let mut windows = 0;
        for xa in (0..W).step_by(48) {
            for xend in (xa + 1)..=W {
                let Some((lo, hi)) = start_window(xa, xend) else { continue };
                windows += 1;
                let dur = ((xend - xa) as u32 * MS * 10).div_ceil(153);
                for since in [lo, (lo + hi) / 2, hi] {
                    let (early, margin) = tear_check(xa, xend, since, dur);
                    assert!(!early, "{xa}..{xend} at {since}");
                    assert!(margin > i64::from(MS * 3 / 4), "{xa}..{xend} at {since}: {margin}");
                }
                // Starting before the beam has passed `xa` is early.
                if xa > TE_SCANLINE + 1 {
                    assert!(tear_check(xa, xend, 0, dur).0, "{xa}..{xend}");
                }
            }
        }
        assert!(windows > 1000);
    }

    /// CPU-bound frames go every second refresh: the one after the previous
    /// frame's is skipped until its start range has passed (EVT 2026-10-21: a
    /// 28 ms time floor drew 35 fps with 28/32/48 ms gaps, seen as stutter).
    #[test]
    fn cpu_frames_skip_exactly_one_refresh() {
        use super::phase::*;
        let (lo, hi) = start_window(96, 366).expect("a spin-sized window");
        // Still in the previous frame's refresh: never.
        for since in [0, lo, hi, REFRESH_CYC - 1] {
            assert!(!second_refresh_due(0, since, Some(hi)));
        }
        // The next refresh: not while its start range is open or ahead...
        for since in [0, lo, hi] {
            assert!(!second_refresh_due(1, since, Some(hi)), "{since}");
        }
        // ...only once it has passed (the stream then lands two on).
        assert!(second_refresh_due(1, hi + 1, Some(hi)));
        assert!(!second_refresh_due(1, REFRESH_CYC, None), "no window known: wait for the edge");
        // Two or more refreshes on: always.
        for since in [0, lo, hi, REFRESH_CYC] {
            assert!(second_refresh_due(2, since, Some(hi)));
            assert!(second_refresh_due(7, since, None));
        }
    }

    /// The device panic of 2026-10-19: a TE edge arriving a little after
    /// 16.0 ms put `since` past the refresh while waiting for the next start
    /// range, and `REFRESH_CYC - since + lo` underflowed.
    #[test]
    fn a_late_edge_is_a_zero_wait_not_an_underflow() {
        use super::phase::*;
        let (lo, hi) = start_window(96, 336).expect("a real window");
        // The crashing input: one cycle past the refresh, before the next
        // range opens. The old `REFRESH_CYC - since + lo` underflowed here.
        assert_eq!(wait(REFRESH_CYC + 1, lo, hi), Some(lo - 1));
        assert_eq!(wait(STAMP_STALE_CYC, lo, hi), Some(REFRESH_CYC + lo - STAMP_STALE_CYC));
        // Later than the next range's opening (a very late edge): no wait.
        assert_eq!(wait(REFRESH_CYC + lo + 5, lo, hi), Some(0));
        assert_eq!(wait(hi + 1, lo, hi), Some(REFRESH_CYC + lo - hi - 1));
    }
}

//! Dev-only (`ui-px-film-gaps`, NEVER ship; fenced in `nsc/mod.rs` and the
//! Makefile's PROD_FORBIDDEN): how smoothly the busy film ran during
//! provisioning (owner 2026-10-16: the orbit lagged at first, then froze).
//!
//! `crypto::provision_from_mnemonic` brackets the run with [`start`] and
//! [`stop`]; `lcd::film_start_with` / `lcd::film_tick` report every presented
//! frame through [`frame`]; `screens::progress` reports the percent through
//! [`note_pct`]. Kept: the frame count, the run's length, and the longest
//! pauses between two frames (the first one counted from [`start`], the last
//! one up to [`stop`]), each tagged with the percent when it began — 50 is
//! the chip writes, below it the key derivation. `seed_wizard::finish_setup`
//! shows them on a 16x4 page after HELP.

use crate::timeout;
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

/// Longest pauses kept: two per row on the three rows under the totals.
const KEPT: usize = 2 * (DISPLAY_ROWS - 1);

#[derive(Clone, Copy)]
struct Rec {
    on: bool,
    t0: u32,
    /// The previous frame (or `t0`) and the percent at that moment.
    last: u32,
    last_pct: u8,
    /// The latest percent reported.
    pct: u8,
    frames: u32,
    total: u32,
    /// `(ms, percent, ended by, ms of I2C inside)`, longest first. The tick
    /// that ended a pause: `P` progress report, `H` hash driver, `C` chip
    /// wait, `S` the film's opening frame, `X` the recording's end.
    gaps: [(u32, u8, u8, u16); KEPT],
    /// Per kept pause, its ms inside each [`Phase`] (`PHASES` order).
    where_: [[u16; PHASES.len()]; KEPT],
    /// Cycles spent in I2C transactions since the previous frame.
    i2c_cyc: u32,
    /// Cycles spent in each [`Phase`] since the previous frame.
    phase_cyc: [u32; PHASES.len()],
    /// The cycle count at the previous frame: a [`Phase`] counts only its
    /// time inside each pause it spans.
    pause_c0: u32,
    /// Per [`Phase`] tag, the open phases (nested ones of the same tag count
    /// once) and when the outermost one began.
    depth: [u8; PHASES.len()],
    open_c0: [u32; PHASES.len()],
    /// Per kept pause, and since the previous frame, the [`count`]s.
    cnts: [[u16; COUNTS.len()]; KEPT],
    cnt: [u16; COUNTS.len()],
    /// Pauses of 500 ms or more, all of them (only `KEPT` are listed).
    long: u32,
    /// Per I2C bus (0 = OPTIGA, 1 = SE050): transactions that took 100 ms or
    /// more, the longest one, and the waits that ran out (`I2cError::Timeout`).
    buses: [Bus; 2],
    /// `dual_se::provision`: salt + credentials, split-half RNG, OPTIGA
    /// write, SE050 write (ms), and the step now running with its start.
    steps: [u32; STEPS],
    step: usize,
    step_at: u32,
    tear: Tear,
}

/// Every film frame's stream checked against the panel's scan model
/// (`pqsigner_ui_px::stream::phase::tear_check`): the tearing hunt of
/// 2026-10-21 (owner: vertical tear lines while the opening's two discs
/// close in, on a first sign's slot keygen).
#[derive(Clone, Copy)]
struct Tear {
    /// Streams checked, and those with no fresh TE stamp to check against.
    frames: u32,
    unsynced: u32,
    /// Started before the beam passed the window; overtaken by the next
    /// refresh's beam.
    early: u32,
    lapped: u32,
    /// The smallest lap margin seen (cycles; negative is a tear).
    min_margin: i64,
    /// The longest time the wire sat idle mid-stream, waiting for a band.
    max_stall: u32,
    /// When the first torn frame streamed (ms after the recording began;
    /// `u32::MAX` while none).
    first_bad: u32,
}

impl Tear {
    const ZERO: Self = Self {
        frames: 0,
        unsynced: 0,
        early: 0,
        lapped: 0,
        min_margin: i64::MAX,
        max_stall: 0,
        first_bad: u32::MAX,
    };
}

/// The `dual_se::provision` steps timed on the second page.
const STEPS: usize = 4;

#[derive(Clone, Copy)]
struct Bus {
    slow: u32,
    max: u32,
    timeouts: u32,
    /// STOPF drains after a NACK that ran out (they break silently).
    drains: u32,
}

impl Bus {
    const ZERO: Self = Self {
        slow: 0,
        max: 0,
        timeouts: 0,
        drains: 0,
    };
}

impl Rec {
    const OFF: Self = Self {
        on: false,
        t0: 0,
        last: 0,
        last_pct: 0,
        pct: 0,
        frames: 0,
        total: 0,
        gaps: [(0, 0, 0, 0); KEPT],
        where_: [[0; PHASES.len()]; KEPT],
        i2c_cyc: 0,
        phase_cyc: [0; PHASES.len()],
        pause_c0: 0,
        depth: [0; PHASES.len()],
        open_c0: [0; PHASES.len()],
        cnts: [[0; COUNTS.len()]; KEPT],
        cnt: [0; COUNTS.len()],
        long: 0,
        buses: [Bus::ZERO; 2],
        steps: [0; STEPS],
        step: STEPS,
        step_at: 0,
        tear: Tear::ZERO,
    };

    /// Close the pause that `src` ends at `now`; keep it if it is among the
    /// longest.
    fn gap(&mut self, now: u32, src: u8) {
        let i2c_ms = u16::try_from(self.i2c_cyc / 160_000).unwrap_or(u16::MAX);
        self.i2c_cyc = 0;
        // A phase still open at this frame (the frame is usually drawn from a
        // chip poll inside one) gives this pause its time so far; its drop
        // credits the rest to the pause it ends in. Without this, a phase
        // spanning a frame lost its whole pre-frame part (where2: `E` read 24
        // of a ~53 ms draw, `O` read 0).
        let c_now = crate::hw::lcd_te::cycles();
        for (k, c) in self.phase_cyc.iter_mut().enumerate() {
            if self.depth[k] > 0 {
                let d = c_now.wrapping_sub(self.open_c0[k]).min(c_now.wrapping_sub(self.pause_c0));
                *c = c.wrapping_add(d);
            }
        }
        let mut ph = [0u16; PHASES.len()];
        for (m, c) in ph.iter_mut().zip(self.phase_cyc.iter_mut()) {
            *m = u16::try_from(*c / 160_000).unwrap_or(u16::MAX);
            *c = 0;
        }
        let mut cn = self.cnt;
        self.cnt = [0; COUNTS.len()];
        self.pause_c0 = c_now;
        let mut item = (now.wrapping_sub(self.last), self.last_pct, src, i2c_ms);
        if item.0 >= 500 {
            self.long = self.long.wrapping_add(1);
        }
        for ((slot, w), c) in self.gaps.iter_mut().zip(self.where_.iter_mut()).zip(self.cnts.iter_mut()) {
            if item.0 > slot.0 {
                core::mem::swap(slot, &mut item);
                core::mem::swap(w, &mut ph);
                core::mem::swap(c, &mut cn);
            }
        }
        self.last = now;
        self.last_pct = self.pct;
    }
}

/// The phases [`Phase`] times inside each pause: `T` the platform TRNG,
/// `O` an OPTIGA random draw, `E` an SE050 random draw, `F` a flash
/// controller busy-wait (program or erase); then inside an SE050 command,
/// `I` the session check (or the T=1' reset + SCP03 handshake), `W` the
/// SCP03 wrap, `K` the T=1' round trip, `U` the SCP03 unwrap. The second
/// sign on the WHERE page (2026-10-21) put 52-53 ms of each start pause in
/// `E` with only 6 ms of I2C; the second four split it. `Z`: an FI delay
/// that had to draw its own length (`fi::wait_random` outside a TRNG fill,
/// which runs a whole hardened 1-byte fill and its ~31 inner delays).
const PHASES: [u8; 9] = [b'T', b'O', b'E', b'F', b'I', b'W', b'K', b'U', b'Z'];

/// Events counted per pause: `Q` SE050 polls for a frame's start byte, `B`
/// chip-wait ticks (`ui::busy_poll` with ticks on), and the reasons such a
/// tick drew nothing: `D` not due yet, `R` the previous frame still
/// streaming, `P` the beam out of the start range, `N` no film set up or no
/// atlas (a nested tick is not counted). `Y`: an SE050 draw retried on a
/// fresh session. `Z`: FI delays that drew their own length (the `Z` phase).
const COUNTS: [u8; 8] = [b'Q', b'B', b'D', b'R', b'P', b'N', b'Y', b'Z'];

/// Thread mode only: SysTick's idle gate runs FI delays too, and an ISR must
/// not touch [`REC`] under the thread.
fn in_thread() -> bool {
    use cortex_m::peripheral::{scb::VectActive, SCB};
    SCB::vect_active() == VectActive::ThreadMode
}

/// Count one `tag` (one of [`COUNTS`]) into the pause running now.
pub fn count(tag: u8) {
    let r = rec();
    if !in_thread() {
        return;
    }
    if let (true, Some(k)) = (r.on, COUNTS.iter().position(|&c| c == tag)) {
        r.cnt[k] = r.cnt[k].saturating_add(1);
    }
}

/// Times a stretch of work as phase `tag` (one of [`PHASES`]) from creation
/// to drop, splitting it at every frame drawn inside it so each pause gets
/// exactly its own part: the hunt for the ~45 ms at a sign's start with no
/// I2C, no hash and no chip wait inside (2026-10-21). Inert outside a
/// recording and in an ISR.
pub struct Phase {
    k: usize,
}

impl Phase {
    #[must_use]
    pub fn new(tag: u8) -> Self {
        let r = rec();
        let k = PHASES.iter().position(|&p| p == tag).unwrap_or(PHASES.len());
        if k == PHASES.len() || !r.on || !in_thread() {
            return Self { k: PHASES.len() };
        }
        if r.depth[k] == 0 {
            r.open_c0[k] = crate::hw::lcd_te::cycles();
        }
        r.depth[k] = r.depth[k].saturating_add(1);
        Self { k }
    }
}

impl Drop for Phase {
    fn drop(&mut self) {
        let r = rec();
        // `start` clears the depths: a phase opened before it is dropped here.
        if self.k == PHASES.len() || r.depth[self.k] == 0 {
            return;
        }
        r.depth[self.k] -= 1;
        if r.on && r.depth[self.k] == 0 {
            let now = crate::hw::lcd_te::cycles();
            let d = now.wrapping_sub(r.open_c0[self.k]).min(now.wrapping_sub(r.pause_c0));
            r.phase_cyc[self.k] = r.phase_cyc[self.k].wrapping_add(d);
        }
    }
}

/// The fourth page: `WHERE T O E F`, then the three longest pauses as
/// `<ms>:<T> <O> <E> <F>`, each the pause's ms inside that phase.
pub fn rows4(out: &mut [[u8; DISPLAY_COLS]; DISPLAY_ROWS]) {
    rows_where(out, b"WHERE T O E F", 0);
}

/// The fifth page: `SE050 I W K U`, the same pauses inside an SE050
/// command's steps.
pub fn rows5(out: &mut [[u8; DISPLAY_COLS]; DISPLAY_ROWS]) {
    rows_where(out, b"SE050 I W K U", 4);
}

fn rows_where(out: &mut [[u8; DISPLAY_COLS]; DISPLAY_ROWS], title: &[u8], from: usize) {
    let r = *rec();
    for row in out.iter_mut() {
        *row = [b' '; DISPLAY_COLS];
    }
    let mut n = 0;
    for &b in title {
        push(&mut out[0], &mut n, b);
    }
    for (row, (gap, w)) in out[1..].iter_mut().zip(r.gaps.iter().zip(r.where_.iter())) {
        let mut n = 0;
        push_u32(row, &mut n, gap.0);
        push(row, &mut n, b':');
        for (k, &ms) in w[from..from + 4].iter().enumerate() {
            if k > 0 {
                push(row, &mut n, b' ');
            }
            push_u32(row, &mut n, u32::from(ms));
        }
    }
}

/// The sixth page: `Q B D R P N Y`, then the same three pauses' [`COUNTS`]
/// (no ms: the rows follow the WHERE page's order).
pub fn rows6(out: &mut [[u8; DISPLAY_COLS]; DISPLAY_ROWS]) {
    let r = *rec();
    for row in out.iter_mut() {
        *row = [b' '; DISPLAY_COLS];
    }
    let mut n = 0;
    for &b in b"Q B D R P N Y" {
        push(&mut out[0], &mut n, b);
    }
    for (row, c) in out[1..].iter_mut().zip(r.cnts.iter()) {
        let mut n = 0;
        // `Z` has its own page.
        for (k, &v) in c[..COUNTS.len() - 1].iter().enumerate() {
            if k > 0 {
                push(row, &mut n, b' ');
            }
            push_u32(row, &mut n, u32::from(v));
        }
    }
}

/// The seventh page: `FI WAIT ms n`, then the same three pauses as
/// `<ms>:<Z ms> <Z count>`, the FI delays that drew their own length.
pub fn rows7(out: &mut [[u8; DISPLAY_COLS]; DISPLAY_ROWS]) {
    let r = *rec();
    for row in out.iter_mut() {
        *row = [b' '; DISPLAY_COLS];
    }
    let mut n = 0;
    for &b in b"FI WAIT ms n" {
        push(&mut out[0], &mut n, b);
    }
    let rows = r.gaps.iter().zip(r.where_.iter()).zip(r.cnts.iter());
    for (row, ((gap, w), c)) in out[1..].iter_mut().zip(rows) {
        let mut n = 0;
        push_u32(row, &mut n, gap.0);
        push(row, &mut n, b':');
        push_u32(row, &mut n, u32::from(w[PHASES.len() - 1]));
        push(row, &mut n, b' ');
        push_u32(row, &mut n, u32::from(c[COUNTS.len() - 1]));
    }
}

static mut REC: Rec = Rec::OFF;

fn rec() -> &'static mut Rec {
    // SAFETY: single-threaded secure UI state; no ISR touches it, and every
    // caller drops the reference before returning.
    unsafe { &mut *core::ptr::addr_of_mut!(REC) }
}

/// Provisioning began.
pub fn start() {
    let now = timeout::now();
    *rec() = Rec {
        on: true,
        t0: now,
        last: now,
        pause_c0: crate::hw::lcd_te::cycles(),
        ..Rec::OFF
    };
}

/// Whether a run is being recorded.
pub fn recording() -> bool {
    rec().on
}

/// The progress callback's percent.
pub fn note_pct(percent: u8) {
    let r = rec();
    if r.on {
        r.pct = percent;
    }
}

/// A film frame reached the glass at `now`, drawn from tick `src`.
pub fn frame(now: u32, src: u8) {
    let r = rec();
    if r.on {
        r.frames = r.frames.wrapping_add(1);
        r.gap(now, src);
    }
}

/// A film frame's stream into window [xa, xend) left the wire: `since` is
/// the cycles from the last TE edge to its start (`None`: no fresh stamp),
/// `dur` its length and `stall` the longest wait for a band inside it.
pub fn stream(xa: i32, xend: i32, since: Option<u32>, dur: u32, stall: u32) {
    let r = rec();
    if !r.on {
        return;
    }
    let t = &mut r.tear;
    t.frames = t.frames.wrapping_add(1);
    t.max_stall = t.max_stall.max(stall);
    let Some(since) = since else {
        t.unsynced = t.unsynced.wrapping_add(1);
        return;
    };
    let (early, margin) = pqsigner_ui_px::stream::phase::tear_check(xa, xend, since, dur);
    t.min_margin = t.min_margin.min(margin);
    if early {
        t.early = t.early.wrapping_add(1);
    }
    if margin < 0 {
        t.lapped = t.lapped.wrapping_add(1);
    }
    if (early || margin < 0) && t.first_bad == u32::MAX {
        t.first_bad = timeout::now().wrapping_sub(r.t0);
    }
}

/// The third page: `TEAR F<frames> U<no stamp>`, then
/// `E<early> L<lapped> @<first torn, ms>`, the smallest lap margin and the
/// longest stall, in ms.
pub fn rows3(out: &mut [[u8; DISPLAY_COLS]; DISPLAY_ROWS]) {
    let t = rec().tear;
    for row in out.iter_mut() {
        *row = [b' '; DISPLAY_COLS];
    }
    let mut n = 0;
    for &b in b"TEAR F" {
        push(&mut out[0], &mut n, b);
    }
    push_u32(&mut out[0], &mut n, t.frames);
    for &b in b" U" {
        push(&mut out[0], &mut n, b);
    }
    push_u32(&mut out[0], &mut n, t.unsynced);
    let mut n = 0;
    push(&mut out[1], &mut n, b'E');
    push_u32(&mut out[1], &mut n, t.early);
    for &b in b" L" {
        push(&mut out[1], &mut n, b);
    }
    push_u32(&mut out[1], &mut n, t.lapped);
    if t.first_bad != u32::MAX {
        for &b in b" @" {
            push(&mut out[1], &mut n, b);
        }
        push_u32(&mut out[1], &mut n, t.first_bad);
    }
    let mut n = 0;
    for &b in b"lap " {
        push(&mut out[2], &mut n, b);
    }
    if t.min_margin == i64::MAX {
        push(&mut out[2], &mut n, b'-');
    } else {
        // Tenths of a ms, signed.
        let tenths = t.min_margin / 16_000;
        if t.min_margin < 0 {
            push(&mut out[2], &mut n, b'-');
        }
        push_tenths(&mut out[2], &mut n, tenths.unsigned_abs());
        for &b in b"ms" {
            push(&mut out[2], &mut n, b);
        }
    }
    let mut n = 0;
    for &b in b"stall " {
        push(&mut out[3], &mut n, b);
    }
    push_tenths(&mut out[3], &mut n, u64::from(t.max_stall / 16_000));
    for &b in b"ms" {
        push(&mut out[3], &mut n, b);
    }
}

/// Append `tenths` as `<whole>.<tenth>`.
fn push_tenths(row: &mut [u8; DISPLAY_COLS], n: &mut usize, tenths: u64) {
    push_u32(row, n, u32::try_from(tenths / 10).unwrap_or(u32::MAX));
    push(row, n, b'.');
    push(row, n, b'0' + (tenths % 10) as u8);
}

/// Provisioning ended (the chips hold the wallet).
pub fn stop() {
    let r = rec();
    if r.on {
        let now = timeout::now();
        r.gap(now, b'X');
        r.total = now.wrapping_sub(r.t0);
        r.on = false;
    }
}

/// `dual_se::provision` entered step `k` (0 salt + credentials, 1 split-half
/// RNG, 2 OPTIGA write, 3 SE050 write); `STEPS` or more closes the last one.
pub fn step(k: usize) {
    let r = rec();
    if !r.on {
        return;
    }
    let now = timeout::now();
    if r.step < STEPS {
        r.steps[r.step] = r.steps[r.step].wrapping_add(now.wrapping_sub(r.step_at));
    }
    r.step = k;
    r.step_at = now;
}

/// Times one I2C transaction on `bus` (0 = OPTIGA, 1 = SE050) from creation
/// to drop, while provisioning runs.
pub struct I2cWatch {
    bus: usize,
    t0: u32,
    c0: u32,
}

impl I2cWatch {
    #[must_use]
    pub fn new(bus: usize) -> Self {
        Self {
            bus,
            t0: timeout::now(),
            c0: crate::hw::lcd_te::cycles(),
        }
    }
}

impl Drop for I2cWatch {
    fn drop(&mut self) {
        let r = rec();
        if !r.on || self.bus > 1 {
            return;
        }
        r.i2c_cyc = r.i2c_cyc.wrapping_add(crate::hw::lcd_te::cycles().wrapping_sub(self.c0));
        let ms = timeout::now().wrapping_sub(self.t0);
        let b = &mut r.buses[self.bus];
        if ms >= 100 {
            b.slow = b.slow.wrapping_add(1);
        }
        if ms > b.max {
            b.max = ms;
        }
    }
}

/// An I2C wait on `bus` ran out (`I2cError::Timeout`) while provisioning ran.
pub fn i2c_timeout(bus: usize) {
    let r = rec();
    if r.on && bus <= 1 {
        r.buses[bus].timeouts = r.buses[bus].timeouts.wrapping_add(1);
    }
}

/// A post-NACK STOPF drain on `bus` ran out while provisioning ran.
pub fn i2c_drain_timeout(bus: usize) {
    let r = rec();
    if r.on && bus <= 1 {
        r.buses[bus].drains = r.buses[bus].drains.wrapping_add(1);
    }
}

/// The second page: `S<salt+cred> R<rng> L<pauses >= 500 ms>`, then
/// `O<optiga ms> E<se050 ms>`, then per bus
/// `<O|E> <slow>x<max ms> t<timeouts> d<drains>`.
pub fn rows2(out: &mut [[u8; DISPLAY_COLS]; DISPLAY_ROWS]) {
    let r = *rec();
    for row in out.iter_mut() {
        *row = [b' '; DISPLAY_COLS];
    }
    let mut n = 0;
    push(&mut out[0], &mut n, b'S');
    push_u32(&mut out[0], &mut n, r.steps[0]);
    push(&mut out[0], &mut n, b' ');
    push(&mut out[0], &mut n, b'R');
    push_u32(&mut out[0], &mut n, r.steps[1]);
    push(&mut out[0], &mut n, b' ');
    push(&mut out[0], &mut n, b'L');
    push_u32(&mut out[0], &mut n, r.long);
    let mut n = 0;
    push(&mut out[1], &mut n, b'O');
    push_u32(&mut out[1], &mut n, r.steps[2]);
    push(&mut out[1], &mut n, b' ');
    push(&mut out[1], &mut n, b'E');
    push_u32(&mut out[1], &mut n, r.steps[3]);
    // pq1's OPTIGA writes: steps that needed a throttle reset after all.
    #[cfg(all(feature = "stm32u585", feature = "board-pq1"))]
    {
        push(&mut out[1], &mut n, b' ');
        push(&mut out[1], &mut n, b'R');
        push_u32(
            &mut out[1],
            &mut n,
            crate::optiga::ON_DEMAND_RESETS.load(core::sync::atomic::Ordering::Relaxed),
        );
    }
    for (row, (tag, b)) in out[2..]
        .iter_mut()
        .zip([(b'O', r.buses[0]), (b'E', r.buses[1])])
    {
        let mut n = 0;
        push(row, &mut n, tag);
        push(row, &mut n, b' ');
        push_u32(row, &mut n, b.slow);
        push(row, &mut n, b'x');
        push_u32(row, &mut n, b.max);
        push(row, &mut n, b' ');
        push(row, &mut n, b't');
        push_u32(row, &mut n, b.timeouts);
        push(row, &mut n, b' ');
        push(row, &mut n, b'd');
        push_u32(row, &mut n, b.drains);
    }
}

/// The last run's frame count, length (ms) and longest pause (ms).
#[must_use]
pub fn summary() -> (u32, u32, u32) {
    let r = *rec();
    (r.frames, r.total, r.gaps[0].0)
}

/// Append `v` in decimal.
fn push_u32(row: &mut [u8; DISPLAY_COLS], n: &mut usize, v: u32) {
    let mut digits = [0u8; 10];
    let mut k = 0;
    let mut x = v;
    loop {
        digits[k] = b'0' + (x % 10) as u8;
        k += 1;
        x /= 10;
        if x == 0 {
            break;
        }
    }
    while k > 0 {
        k -= 1;
        push(row, n, digits[k]);
    }
}

fn push(row: &mut [u8; DISPLAY_COLS], n: &mut usize, b: u8) {
    if *n < DISPLAY_COLS {
        row[*n] = b;
        *n += 1;
    }
}

/// The 16x4 page: `F<frames> T<total>ms`, then the pauses as
/// `<ms>@<pct><ended by><ms of I2C>`, longest first, two per row.
pub fn rows(out: &mut [[u8; DISPLAY_COLS]; DISPLAY_ROWS]) {
    let r = *rec();
    for row in out.iter_mut() {
        *row = [b' '; DISPLAY_COLS];
    }
    let mut n = 0;
    push(&mut out[0], &mut n, b'F');
    push_u32(&mut out[0], &mut n, r.frames);
    push(&mut out[0], &mut n, b' ');
    push(&mut out[0], &mut n, b'T');
    push_u32(&mut out[0], &mut n, r.total);
    push(&mut out[0], &mut n, b'm');
    push(&mut out[0], &mut n, b's');
    for (row, pair) in out[1..].iter_mut().zip(r.gaps.chunks(2)) {
        let mut n = 0;
        for (k, &(ms, pct, src, i2c)) in pair.iter().enumerate() {
            if k > 0 {
                push(row, &mut n, b' ');
            }
            push_u32(row, &mut n, ms);
            push(row, &mut n, b'@');
            push_u32(row, &mut n, u32::from(pct));
            // What ended it, and its ms of I2C (`52@0C31`).
            if src != 0 {
                push(row, &mut n, src);
                push_u32(row, &mut n, u32::from(i2c));
            }
        }
    }
}

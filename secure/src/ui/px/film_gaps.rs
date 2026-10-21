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
    /// Cycles spent in I2C transactions since the previous frame.
    i2c_cyc: u32,
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
        i2c_cyc: 0,
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
        let mut item = (now.wrapping_sub(self.last), self.last_pct, src, i2c_ms);
        if item.0 >= 500 {
            self.long = self.long.wrapping_add(1);
        }
        for slot in &mut self.gaps {
            if item.0 > slot.0 {
                core::mem::swap(slot, &mut item);
            }
        }
        self.last = now;
        self.last_pct = self.pct;
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

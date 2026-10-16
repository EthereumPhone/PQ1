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
    /// `(ms, percent)`, longest first.
    gaps: [(u32, u8); KEPT],
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
        gaps: [(0, 0); KEPT],
        long: 0,
        buses: [Bus::ZERO; 2],
        steps: [0; STEPS],
        step: STEPS,
        step_at: 0,
    };

    /// Close the pause that ends at `now`; keep it if it is among the longest.
    fn gap(&mut self, now: u32) {
        let mut item = (now.wrapping_sub(self.last), self.last_pct);
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

/// The progress callback's percent.
pub fn note_pct(percent: u8) {
    let r = rec();
    if r.on {
        r.pct = percent;
    }
}

/// A film frame reached the glass at `now`.
pub fn frame(now: u32) {
    let r = rec();
    if r.on {
        r.frames = r.frames.wrapping_add(1);
        r.gap(now);
    }
}

/// Provisioning ended (the chips hold the wallet).
pub fn stop() {
    let r = rec();
    if r.on {
        let now = timeout::now();
        r.gap(now);
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
}

impl I2cWatch {
    #[must_use]
    pub fn new(bus: usize) -> Self {
        Self {
            bus,
            t0: timeout::now(),
        }
    }
}

impl Drop for I2cWatch {
    fn drop(&mut self) {
        let r = rec();
        if !r.on || self.bus > 1 {
            return;
        }
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

/// The 16x4 page: `F<frames> T<total>ms`, then the pauses as `<ms>@<pct>`,
/// longest first, two per row.
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
        for (k, &(ms, pct)) in pair.iter().enumerate() {
            if k > 0 {
                push(row, &mut n, b' ');
            }
            push_u32(row, &mut n, ms);
            push(row, &mut n, b'@');
            push_u32(row, &mut n, u32::from(pct));
        }
    }
}

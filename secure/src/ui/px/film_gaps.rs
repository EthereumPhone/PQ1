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
    };

    /// Close the pause that ends at `now`; keep it if it is among the longest.
    fn gap(&mut self, now: u32) {
        let mut item = (now.wrapping_sub(self.last), self.last_pct);
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

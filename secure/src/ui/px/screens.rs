//! Port step 4 presenter: the screens outside the sign dialog.
//!
//! `ui::show_status` / `ui::show_progress`, the PIN row, the seed wizard and
//! the boot fingerprint hand their record here instead of painting a 16×4
//! page. On the NV3007 the record plays through the pixel engine from its
//! arrival until it rests (a verdict's whole timeline, a static screen's one
//! frame) against a freshly verified atlas; everywhere the record is also
//! logged (`[UI-PXS]` / `[UI-PXSR]`, `debug-log`) and fingerprinted
//! (`ui-capture`), so the QEMU e2e and the catalogue see what the glass
//! shows. Every entry point returns `false` when the pixel path declined
//! (no verified atlas): the caller paints its legacy page, so the device
//! stays readable (fail-visible, like `lcd::paint_legacy`).
//!
//! Secrets never enter a record: the PIN row carries the masked entry the
//! page showed, the seed pages carry placeholders (the words are painted by
//! the constant-time run and passed separately), and the logged / hashed
//! copy of an entry row has its glyphs redacted.

use super::status_map::{self, Status};
use pqsigner_ui_px::{Kind, Screen};
#[cfg(any(feature = "debug-log", feature = "ui-capture"))]
use pqsigner_ui_px::SCREEN_BYTES;

/// The caption the next PIN row wears (set by its prompt). Single-threaded
/// secure UI state.
static mut PIN_CAPTION: &[u8] = b"ENTER PIN";

/// The caption of the PIN row about to be painted.
#[must_use]
pub fn pin_caption() -> &'static [u8] {
    // SAFETY: single-threaded secure UI state (no ISR touches it).
    unsafe { *core::ptr::addr_of!(PIN_CAPTION) }
}

fn set_pin_caption(c: &'static [u8]) {
    // SAFETY: single-threaded secure UI state (no ISR touches it).
    unsafe {
        *core::ptr::addr_of_mut!(PIN_CAPTION) = c;
    }
}

/// The copy of `s` that may be logged or hashed: an entry row's glyphs (the
/// active PIN digit, a typed seed-word prefix) become `#`.
fn redacted(s: &Screen) -> Screen {
    let mut r = *s;
    if s.kind() == Some(Kind::Entry) {
        // Line record 0 holds the glyphs: weight byte, then the text.
        const OFF_LINE0: usize = 64 + 1;
        for b in &mut r.0[OFF_LINE0..OFF_LINE0 + pqsigner_ui_px::screen::MAX_ENTRY_SLOTS] {
            if !matches!(*b, b'_' | b'*' | b' ') {
                *b = b'#';
            }
        }
    }
    r
}

/// Log / fingerprint a non-dialog screen (`[UI-PXS]` so the sign-dialog
/// transcript counts are untouched).
fn record(s: &Screen) {
    let r = redacted(s);
    #[cfg(feature = "debug-log")]
    {
        let mut line = [b' '; 120];
        let mut n = 0usize;
        let mut put = |b: &[u8]| {
            let k = b.len().min(line.len().saturating_sub(n));
            line[n..n + k].copy_from_slice(&b[..k]);
            n += k;
        };
        put(&r.0[..12]);
        put(b" id=");
        put(r.id());
        put(b" cap=\"");
        put(r.caption());
        put(b"\" lab=\"");
        put(r.label());
        put(b"\"");
        let shown = n;
        secure_log!("[UI-PXS] {}", crate::ui::ascii_str(&line[..shown]));
        let mut hex = [0u8; SCREEN_BYTES * 2];
        for (i, b) in r.0.iter().enumerate() {
            hex[i * 2] = nibble(b >> 4);
            hex[i * 2 + 1] = nibble(b & 0x0f);
        }
        secure_log!("[UI-PXSR] {}", crate::ui::ascii_str(&hex));
    }
    #[cfg(feature = "ui-capture")]
    {
        let mut buf = [0u8; SCREEN_BYTES + 1];
        buf[..SCREEN_BYTES].copy_from_slice(&r.0);
        crate::ui::capture::emit(&buf);
    }
    #[cfg(not(any(feature = "debug-log", feature = "ui-capture")))]
    let _ = r;
}

#[cfg(feature = "debug-log")]
const fn nibble(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }
}

/// Present `s` (and paint the `secret` grid cells over it with the
/// constant-time run). `false` = no verified atlas, paint the legacy page.
pub fn show_with(s: &Screen, secret: &[(usize, &[u8])]) -> bool {
    #[cfg(feature = "ui-lcd")]
    {
        let Ok(atlas) = super::assets::verify_atlas() else {
            return false;
        };
        record(s);
        super::lcd::play_screen(s, &atlas, secret);
        true
    }
    #[cfg(not(feature = "ui-lcd"))]
    {
        let _ = secret;
        record(s);
        true
    }
}

/// Present a record.
pub fn show(s: &Screen) -> bool {
    show_with(s, &[])
}

/// Work in progress (a one-off status before the work runs): the record
/// painted at rest at once — an entrance would only delay the work. With a
/// film already running (the signing film) the film keeps the glass and is
/// advanced instead.
pub fn busy(s: &Screen) -> bool {
    #[cfg(feature = "ui-lcd")]
    {
        if super::lcd::film_live() {
            super::lcd::film_tick(0);
            return true;
        }
        let Ok(atlas) = super::assets::verify_atlas() else {
            return false;
        };
        record(s);
        super::lcd::paint_rest(s, &atlas);
        true
    }
    #[cfg(not(feature = "ui-lcd"))]
    {
        record(s);
        true
    }
}

/// A run of progress callbacks (key generation, a sign outside the pixel
/// route): the first call starts the busy film on the record — its disc
/// seeds the qubits, its caption breathes over the orbit — later calls
/// advance it; a running film is never replaced.
fn progress_film(s: &Screen) -> bool {
    #[cfg(feature = "ui-lcd")]
    {
        if super::lcd::film_live() {
            super::lcd::film_tick(0);
            return true;
        }
        if super::assets::atlas().is_none() {
            return false;
        }
        record(s);
        super::lcd::film_start_with(s);
        true
    }
    #[cfg(not(feature = "ui-lcd"))]
    {
        record(s);
        true
    }
}

/// `ui::show_status` on the pixel UI.
pub fn status(title: &str, sub: &str) -> bool {
    match status_map::classify(title, sub) {
        Status::PinPrompt(c) => {
            set_pin_caption(c);
            true
        }
        Status::Show(s) => show(&s),
        Status::Busy(s) => busy(&s),
    }
}

/// `ui::show_progress` on the pixel UI: the first call of a run shows the
/// busy screen, later calls advance its film.
pub fn progress(title: &str, _percent: u8) -> bool {
    #[cfg(not(feature = "ui-lcd"))]
    {
        // Log each run once, not every percent.
        static mut LAST: [u8; 16] = [0; 16];
        let t = title.as_bytes();
        let mut key = [0u8; 16];
        let n = t.len().min(16);
        key[..n].copy_from_slice(&t[..n]);
        // SAFETY: single-threaded secure UI state.
        let last = unsafe { &mut *core::ptr::addr_of_mut!(LAST) };
        if *last == key && _percent != 0 {
            return true;
        }
        *last = key;
    }
    progress_film(&status_map::progress(title))
}

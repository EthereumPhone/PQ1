//! The text presenter: shows one `(screen, page)` without pixels.
//!
//! Three sinks, each independently gated:
//!
//! * `debug-log`: two log lines per shown page — a human-readable `[UI-PX]`
//!   summary and the machine-readable `[UI-PXR]` record hex — the shape the
//!   QEMU e2e captures, `tools/ui_screens_export.py --px` and the golden
//!   fixtures parse.
//! * `ui-capture`: a `[UI-FP]` SHA-256 over `record ‖ page`, so goldens are
//!   animation-independent and identical on QEMU and on hardware.
//!
//! On `ui-lcd` builds the pixel presenter (`px::lcd`) paints; this module
//! only logs and fingerprints there.

use pqsigner_ui_px::{Screen, SCREEN_BYTES};

/// Present `(screen, page)`; `idx`/`total` are the transcript position.
pub fn present(s: &Screen, page: u8, idx: usize, total: usize) {
    #[cfg(feature = "debug-log")]
    log_lines(s, page, idx, total);
    #[cfg(feature = "ui-capture")]
    {
        let mut buf = [0u8; SCREEN_BYTES + 1];
        buf[..SCREEN_BYTES].copy_from_slice(&s.0);
        buf[SCREEN_BYTES] = page;
        crate::ui::capture::emit(&buf);
    }
    #[cfg(not(any(feature = "debug-log", feature = "ui-capture")))]
    {
        let _ = (s, page, idx, total);
    }
}

#[cfg(feature = "debug-log")]
fn log_lines(s: &Screen, page: u8, idx: usize, total: usize) {
    // Human line: header bytes + label/caption + the shown page's lines.
    let mut line = [b' '; 200];
    let mut n = 0usize;
    let mut put = |b: &[u8]| {
        let k = b.len().min(line.len().saturating_sub(n));
        line[n..n + k].copy_from_slice(&b[..k]);
        n += k;
    };
    put(&s.0[..12]);
    put(b" id=");
    put(s.id());
    put(b" lab=\"");
    put(s.label());
    put(b"\" cap=\"");
    put(s.caption());
    put(b"\"");
    for i in 0..s.nlines(page) {
        if let Some((w, text)) = s.line(page, i) {
            put(b" | ");
            put(&[w.as_byte(), b':']);
            put(text);
        }
    }
    let shown = n;
    secure_log!(
        "[UI-PX] {:04x}/{:04x} p{} {}",
        idx,
        total,
        page,
        crate::ui::ascii_str(&line[..shown])
    );
    // Machine line: the full record as hex.
    let mut hex = [0u8; SCREEN_BYTES * 2];
    for (i, b) in s.0.iter().enumerate() {
        hex[i * 2] = nibble(b >> 4);
        hex[i * 2 + 1] = nibble(b & 0x0f);
    }
    secure_log!("[UI-PXR] {:04x} p{} {}", idx, page, crate::ui::ascii_str(&hex));
}

#[cfg(feature = "debug-log")]
const fn nibble(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }
}


//! Screenshot fingerprint capture for UI regression testing.
//!
//! Ported pattern from Trezor's `tests/ui_tests/common.py:131-132`
//! (`SHA-256(Image.tobytes())` per screen, stored in `fixtures.json`).
//! See `docs/trezor-comparison.md §2.3`.
//!
//! Why capture on-device instead of screenshotting from the host:
//!
//! * QEMU's `semihosting` backend has no pixel framebuffer — it prints
//!   chars to stdout. A screenshot tool would have to re-parse stdout,
//!   which is fragile. Hashing the cell grid directly is deterministic.
//! * The real OLED's 512-byte GDDRAM is stable, but pulling it off the
//!   probe adds a round-trip to every frame. An on-device SHA-256 is
//!   one peripheral write.
//! * Keeping the fingerprint producer inside the secure world means it
//!   hashes exactly what the trusted UI rendered, not what NS later
//!   massaged. A post-hoc screenshot could be altered by a rogue NS;
//!   an in-world fingerprint would be too, but only if S-world itself
//!   is compromised — same trust boundary as the display.
//!
//! Feature-gated behind `ui-capture`. Default OFF so CI runs stay
//! quiet. When ON, each `Display::flush()` emits a line like:
//!
//!     [UI-FP] 0000  a1b2c3d4e5f6...
//!
//! The host-side `tools/ui_fixture.py` parses these and manages the
//! `tests/ui_fixtures.json` lookup. First run regenerates; subsequent
//! runs fail on any hash diff.

#![cfg(feature = "ui-capture")]

use core::sync::atomic::{AtomicU16, Ordering};
use sha2::{Digest, Sha256};

/// Monotonic frame counter. Included as the prefix on every emitted
/// fingerprint so the host can line up N-th frame across runs.
static FRAME_COUNTER: AtomicU16 = AtomicU16::new(0);

/// Compute SHA-256 over the caller-supplied framebuffer bytes and emit
/// a fingerprint line over the secure log. Callers pass whichever
/// bytes best represent "the screen right now" — the semihosting
/// backend passes its 4×16 char grid, the OLED backend would pass
/// SSD1306 GDDRAM bytes. The hash is over the caller's bytes
/// verbatim, so any backend change that alters the fingerprint input
/// *intentionally* must be paired with a fixture regeneration.
pub fn emit(fb_bytes: &[u8]) {
    let idx = FRAME_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut h = Sha256::new();
    h.update(fb_bytes);
    let digest: [u8; 32] = h.finalize().into();

    // Emit as hex for easy parsing by the host tool. The `[UI-FP]`
    // prefix is the handshake — the host filter greps for this line
    // shape and nothing else.
    //
    // Format: "[UI-FP] <frame-idx-hex-4> <sha256-hex-64>"
    let mut hex = [0u8; 64];
    for (i, b) in digest.iter().enumerate() {
        let (hi, lo) = (b >> 4, b & 0x0f);
        hex[i * 2] = nibble_to_hex(hi);
        hex[i * 2 + 1] = nibble_to_hex(lo);
    }
    secure_log!("[UI-FP] {:04x}  {}", idx, super::ascii_str(&hex));
}

#[inline(always)]
const fn nibble_to_hex(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        10..=15 => b'a' + (n - 10),
        _ => b'?',
    }
}

/// Reset the frame counter. Useful between test cases so fingerprint
/// indices align against a clean fixture start marker.
pub fn reset_counter() {
    FRAME_COUNTER.store(0, Ordering::Relaxed);
}

//! Host mounts of `secure/` modules that are `#[cfg(not(test))]` inside the
//! firmware crate, so their genuine `static mut` / volatile-receipt `unsafe`
//! runs under Miri (`make miri`) and plain host `cargo test`.
//!
//! This lib is always compiled with `cfg(test)` FALSE (the tests live in
//! `tests/`, which link it as a normal dependency). That keeps the production
//! `#[cfg(all(not(test), not(feature = "mock-se")))]` arm of
//! `rng_strong::fill` intact: the strict three-source production path is what
//! runs here, against the controllable mock platform/SE draws below. `mock-se`
//! is deliberately absent from this crate's features.
//!
//! The `ui_lcd` mount additionally covers the NV3007 trusted-display
//! rasterizer (`secure/src/ui/lcd.rs`, `ui-lcd`-gated, never host-compiled by
//! the firmware crate): the recording `hw::lcd_nv3007` stub below lets the
//! tests reassemble the full native panel image from every
//! `set_window`/`write_pixels` the production blitter emits. The font table
//! it consumes comes from this crate's `build.rs`, a byte-identical copy of
//! `secure/build.rs::generate_font_flat`.

// The whole crate is `not(test)`: `cargo test` also builds a lib unit-test
// target with `cfg(test)` set, under which the mounted `rng_strong.rs` has no
// compilable `fill` arm (both of its `not(test)` blocks vanish). The real
// tests live in `tests/` and link this lib built with `cfg(test)` FALSE.
#![cfg(not(test))]
#![deny(unsafe_op_in_unsafe_fn)]
#![no_std]

// `secure_log!` — production expands this to the secure UART logger
// (`secure/src/main.rs`); on host it is a no-op. `macro_rules!` textual scope
// requires this to sit BEFORE every module that uses the macro.
macro_rules! secure_log {
    ($($arg:tt)*) => {{}};
}

// ── fi shim ──────────────────────────────────────────────────────────────
// Mirrors the `crate::fi` API surface used by the mounted secure modules,
// backed by the real `pqsigner-fi` primitives (already exercised by the
// `pqsigner-fi` Miri leg). The delay-length byte is a fixed constant,
// matching `secure/src/fi.rs`'s own `#[cfg(test)]` arm.
pub mod fi {
    pub use pqsigner_fi::{FAIL_SENTINEL, OK_SENTINEL};

    #[inline(never)]
    pub fn wait_random() {
        pqsigner_fi::wait_random_loop(|| 7);
    }

    #[inline(never)]
    pub fn check_true_into_sentinel<F: FnMut() -> bool>(cond: F) -> u32 {
        pqsigner_fi::check_true_into_sentinel(cond, wait_random)
    }

    pub fn zeroize_barrier() {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

// ── platform TRNG mock ───────────────────────────────────────────────────
// `crate::rng::fill` is the only platform-RNG entry the mounted `rng_strong`
// calls. Deterministic xorshift stream (nonzero by construction) with
// failure / stuck-zero modes for the negative tests.
pub mod rng {
    use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

    const MODE_OK: u8 = 0;
    const MODE_FAIL: u8 = 1;
    const MODE_ZERO: u8 = 2;

    static MODE: AtomicU8 = AtomicU8::new(MODE_OK);
    static STATE: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);

    pub fn set_ok() {
        MODE.store(MODE_OK, Ordering::SeqCst);
    }
    pub fn set_fail() {
        MODE.store(MODE_FAIL, Ordering::SeqCst);
    }
    pub fn set_zero() {
        MODE.store(MODE_ZERO, Ordering::SeqCst);
    }

    pub fn fill(buf: &mut [u8]) -> Result<(), ()> {
        match MODE.load(Ordering::SeqCst) {
            MODE_FAIL => return Err(()),
            MODE_ZERO => {
                buf.fill(0);
                return Ok(());
            }
            _ => {}
        }
        for b in buf.iter_mut() {
            let mut x = STATE.load(Ordering::Relaxed);
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            STATE.store(x, Ordering::Relaxed);
            *b = (x >> 32) as u8;
        }
        Ok(())
    }
}

// ── secure-element TRNG mocks ────────────────────────────────────────────
// The production arm of `rng_strong::fill` calls `crate::se_random_optiga` /
// `crate::se_random_se050`. Per-source modes: unique counter stream (default;
// always differs from any repetition history), a fixed constant stream
// (stuck-chip / equal-stream tests), all-zero, and failure.
mod se_mock {
    use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

    pub const OPTIGA: usize = 0;
    pub const SE050: usize = 1;

    pub const MODE_UNIQUE: u8 = 0;
    pub const MODE_CONST: u8 = 1;
    pub const MODE_ZERO: u8 = 2;
    pub const MODE_FAIL: u8 = 3;
    /// When drawing, attempt a re-entrant `rng_strong::fill` and return its
    /// result — the busy guard must reject it while the outer fill is live.
    pub const MODE_REENTRANT: u8 = 4;

    static MODE: [AtomicU8; 2] = [AtomicU8::new(MODE_UNIQUE), AtomicU8::new(MODE_UNIQUE)];
    static CONST_BYTE: [AtomicU8; 2] = [AtomicU8::new(0x11), AtomicU8::new(0x22)];
    static COUNTER: AtomicU32 = AtomicU32::new(1);
    /// 255 = no re-entrant attempt yet, 0 = inner fill rejected, 1 = succeeded.
    static REENTRANT_RESULT: AtomicU8 = AtomicU8::new(255);

    pub fn reentrant_result() -> Option<bool> {
        match REENTRANT_RESULT.load(Ordering::SeqCst) {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    pub fn set(source: usize, mode: u8, const_byte: u8) {
        MODE[source].store(mode, Ordering::SeqCst);
        CONST_BYTE[source].store(const_byte, Ordering::SeqCst);
    }

    pub fn draw(source: usize, buf: &mut [u8]) -> Result<(), ()> {
        match MODE[source].load(Ordering::SeqCst) {
            MODE_FAIL => Err(()),
            MODE_ZERO => {
                buf.fill(0);
                Ok(())
            }
            MODE_CONST => {
                buf.fill(CONST_BYTE[source].load(Ordering::SeqCst));
                Ok(())
            }
            MODE_REENTRANT => {
                // Attempt a nested fill while the outer one holds the busy
                // guard; record and propagate the inner verdict.
                let mut scratch = [0u8; 16];
                let inner = crate::rng_strong::fill(&mut scratch);
                REENTRANT_RESULT.store(
                    if inner.is_ok() { 1 } else { 0 },
                    Ordering::SeqCst,
                );
                inner
            }
            _ => {
                // Distinct, never-all-equal per-source streams: OPTIGA blocks
                // are the forward counter bytes, SE050 the complemented bytes,
                // so the pairwise-differ health checks always have signal.
                for b in buf.iter_mut() {
                    let c = COUNTER.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
                    *b = if source == OPTIGA { c as u8 } else { !(c as u8) };
                }
                Ok(())
            }
        }
    }
}

/// Mock control surface for the integration tests.
pub mod mock {
    pub const OPTIGA: usize = crate::se_mock::OPTIGA;
    pub const SE050: usize = crate::se_mock::SE050;

    /// Fresh, pairwise-distinct streams on every draw (the healthy case).
    pub fn se_ok_unique(source: usize) {
        crate::se_mock::set(source, crate::se_mock::MODE_UNIQUE, 0);
    }
    /// Every draw returns the same constant block (stuck chip).
    pub fn se_stuck_const(source: usize, byte: u8) {
        crate::se_mock::set(source, crate::se_mock::MODE_CONST, byte);
    }
    pub fn se_zero(source: usize) {
        crate::se_mock::set(source, crate::se_mock::MODE_ZERO, 0);
    }
    pub fn se_fail(source: usize) {
        crate::se_mock::set(source, crate::se_mock::MODE_FAIL, 0);
    }
    /// On the next draw, attempt a re-entrant `rng_strong::fill` (busy-guard
    /// probe); pair with [`reentrant_result`].
    pub fn se_reentrant(source: usize) {
        crate::se_mock::set(source, crate::se_mock::MODE_REENTRANT, 0);
    }
    /// `Some(false)` = the nested fill was rejected (guard held), `Some(true)`
    /// = it succeeded (guard breached), `None` = no nested attempt ran.
    pub fn reentrant_result() -> Option<bool> {
        crate::se_mock::reentrant_result()
    }
}

pub unsafe fn se_random_optiga(buf: &mut [u8]) -> Result<(), ()> {
    se_mock::draw(se_mock::OPTIGA, buf)
}

pub unsafe fn se_random_se050(buf: &mut [u8]) -> Result<(), ()> {
    se_mock::draw(se_mock::SE050, buf)
}

/// Test-facing shim: the mounted `fill_with_store` is `pub(crate)` inside
/// `rng_strong`, so integration tests (a separate crate) cannot name it.
/// This crate-internal wrapper re-exposes the strict store-driven fill.
pub fn fill_with_store(
    buf: &mut [u8],
    store: &mut impl secure_element::WalletStore,
) -> Result<(), ()> {
    rng_strong::fill_with_store(buf, store)
}

// ── minimal WalletStore surface ──────────────────────────────────────────
// `rng_strong::fill_with_store` only calls the two random-draw methods; the
// real `secure/src/secure_element.rs` trait pulls in `crate::crypto` /
// `crate::pin` and is not mountable on host. Defaults fail, mirroring the
// production trait's contract (only a backend exposing both physical chips
// may succeed).
pub mod secure_element {
    #[derive(Debug)]
    pub enum SeError {
        Failed,
    }

    pub trait WalletStore {
        fn random_optiga(&mut self, _buf: &mut [u8]) -> Result<(), SeError> {
            Err(SeError::Failed)
        }
        fn random_se050(&mut self, _buf: &mut [u8]) -> Result<(), SeError> {
            Err(SeError::Failed)
        }
    }
}

// ── the mounted production modules (unmodified) ─────────────────────────
#[path = "../../secure/src/rng_exact.rs"]
pub mod rng_exact;
#[path = "../../secure/src/rng_strong_fold.rs"]
pub mod rng_strong_fold;
#[path = "../../secure/src/rng_strong.rs"]
pub mod rng_strong;

// ── secure_log! is defined at the top of this file (textual macro scope) ──

// ── hw stubs for the ui_lcd mount ────────────────────────────────────────
pub mod hw {
    /// Recording stand-in for the NV3007 driver (`secure/src/hw/lcd_nv3007.rs`).
    ///
    /// The production `ui::lcd` blitter renders by `set_window` + `write_pixels`
    /// per glyph cell. This stub keeps the driver's public constants, applies
    /// the panel's RAMWR auto-increment order (native-X inner, native-Y outer,
    /// wrapping inside the window) into a full native framebuffer image, and
    /// logs every call so the tests can (a) reassemble exactly what the panel
    /// would show and (b) bounds-check every window the rasterizer programs.
    /// Geometry constants mirror the real driver (pinned there by its own
    /// host unit tests); `X_OFFSET` is applied inside the real `set_window`,
    /// so the coords recorded here are the LOGICAL 0..142 / 0..428 ones the
    /// rasterizer computes.
    pub mod lcd_nv3007 {
        /// Visible pixel width (X axis). Mirrors the real driver.
        pub const FRAME_WIDTH: u16 = 142;
        /// Visible pixel height (Y axis). Mirrors the real driver.
        pub const FRAME_HEIGHT: u16 = 428;
        /// X offset the real `set_window` adds internally (not applied here —
        /// the recorded coords are pre-offset logical ones).
        pub const X_OFFSET: u16 = 12;
        /// Y offset. The production driver uses 0.
        pub const Y_OFFSET: u16 = 0;

        const W: usize = FRAME_WIDTH as usize;
        const H: usize = FRAME_HEIGHT as usize;
        const FB_LEN: usize = W * H;
        const OP_CAP: usize = 4096;

        /// One recorded driver call. For `SetWindow` the window is in
        /// `x0..=x1, y0..=y1`; for the pixel writes the SAME fields carry the
        /// window that was active when the write happened, and `arg` is the
        /// pixel count (or the RGB565 color for `WritePixelsSolid`).
        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        pub enum OpKind {
            Init,
            SetWindow,
            WritePixels,
            WritePixelsSolid,
        }

        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        pub struct Op {
            pub kind: OpKind,
            pub x0: u16,
            pub y0: u16,
            pub x1: u16,
            pub y1: u16,
            pub arg: u32,
        }

        const NO_OP: Op = Op { kind: OpKind::Init, x0: 0, y0: 0, x1: 0, y1: 0, arg: 0 };

        struct State {
            fb: [u16; FB_LEN],
            ops: [Op; OP_CAP],
            op_count: usize,
            cur: (u16, u16, u16, u16),
        }

        static mut STATE: State = State {
            fb: [0u16; FB_LEN],
            ops: [NO_OP; OP_CAP],
            op_count: 0,
            cur: (0, 0, 0, 0),
        };

        /// Exclusive access to the recording state.
        /// SAFETY: host test crate only — every test holds its SERIAL mutex
        /// (and the Miri leg runs `--test-threads=1`), so no concurrent
        /// access exists; a fresh pointer is derived from the static per call,
        /// so no stale reference can alias a later mutation.
        fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
            unsafe { f(&mut *core::ptr::addr_of_mut!(STATE)) }
        }

        fn record(op: Op) {
            with(|s| {
                if s.op_count < OP_CAP {
                    s.ops[s.op_count] = op;
                }
                s.op_count += 1;
            });
        }

        /// Consume `n` pixels into the current window in NV3007 RAMWR order:
        /// native-X auto-increments fastest and wraps to `x0`, then native-Y
        /// advances (wrapping to `y0`), exactly how the controller's address
        /// counters behave within CASET/RASET.
        fn blit(n: usize, px: impl Fn(usize) -> u16) {
            let (x0, y0, x1, y1) = with(|s| s.cur);
            let w = usize::from(x1 - x0) + 1;
            let h = usize::from(y1 - y0) + 1;
            with(|s| {
                for i in 0..n {
                    let nx = usize::from(x0) + (i % w);
                    let ny = usize::from(y0) + ((i / w) % h);
                    s.fb[ny * W + nx] = px(i);
                }
            });
        }

        /// No-op beyond recording: the real init does SPI/GPIO setup, the
        /// vendor init sequence, and a black `fill_screen` — tests reset the
        /// stub explicitly instead of relying on init side effects.
        pub fn init() {
            record(Op { kind: OpKind::Init, x0: 0, y0: 0, x1: 0, y1: 0, arg: 0 });
        }

        pub fn set_window(x0: u16, y0: u16, x1: u16, y1: u16) {
            with(|s| s.cur = (x0, y0, x1, y1));
            record(Op { kind: OpKind::SetWindow, x0, y0, x1, y1, arg: 0 });
        }

        pub fn write_pixels(buf: &[u16]) {
            let (x0, y0, x1, y1) = with(|s| s.cur);
            record(Op { kind: OpKind::WritePixels, x0, y0, x1, y1, arg: buf.len() as u32 });
            blit(buf.len(), |i| buf[i]);
        }

        pub fn write_pixels_solid(color: u16, n: u32) {
            let (x0, y0, x1, y1) = with(|s| s.cur);
            record(Op { kind: OpKind::WritePixelsSolid, x0, y0, x1, y1, arg: n });
            blit(n as usize, |_| color);
        }

        /// Mirrors the real driver: full-window `set_window` + solid write.
        pub fn fill_screen(color: u16) {
            set_window(0, 0, FRAME_WIDTH - 1, FRAME_HEIGHT - 1);
            write_pixels_solid(color, u32::from(FRAME_WIDTH) * u32::from(FRAME_HEIGHT));
        }

        // ── test introspection (not part of the production API) ──

        /// Black framebuffer, empty op log. Call before every render.
        pub fn reset() {
            with(|s| {
                s.fb = [0u16; FB_LEN];
                s.op_count = 0;
                s.cur = (0, 0, 0, 0);
            });
        }

        /// Total number of driver calls since the last reset (may exceed
        /// `op_cap()`; only the first `op_cap()` are retrievable).
        pub fn op_count() -> usize {
            with(|s| s.op_count)
        }

        pub fn op_cap() -> usize {
            OP_CAP
        }

        pub fn op_at(i: usize) -> Op {
            with(|s| {
                assert!(
                    i < s.op_count && i < OP_CAP,
                    "op {i} not recorded (count={}, cap={OP_CAP})",
                    s.op_count
                );
                s.ops[i]
            })
        }

        pub const fn framebuffer_len() -> usize {
            FB_LEN
        }

        /// Copy the full native panel image (row-major, native-Y outer).
        pub fn copy_framebuffer(out: &mut [u16]) {
            assert_eq!(out.len(), FB_LEN, "framebuffer slice must be {FB_LEN} px");
            with(|s| out.copy_from_slice(&s.fb));
        }
    }

    /// Stand-in for `secure/src/hw/buttons.rs`. The mounted `ui::lcd` only
    /// references these under `feature = "gpio-buttons"` (OFF in this crate);
    /// they exist so the mount stays compilable if that feature is ever
    /// enabled here. Signatures mirror the real driver.
    pub mod buttons {
        /// # Safety
        /// Matches the real `init`'s contract; a no-op on host.
        pub unsafe fn init() {}

        pub fn wait_event(
            _idle_check: &mut dyn FnMut() -> bool,
        ) -> Option<(crate::Button, crate::Press)> {
            None
        }
    }
}

// ── ui shim (mirrors the `secure/src/ui/mod.rs` surface ui::lcd imports) ──
// Mounted at the crate root (same style as the rng mounts above), so the
// production file's `use super::{…}` resolves to these items. Values and
// enum shapes are copied verbatim from `secure/src/ui/mod.rs`.

/// Logical display dimensions (cells, not pixels).
/// 16 columns × 4 rows: fits 5×8 font on 128×32 OLED, 8×13 on 128×64.
pub const DISPLAY_COLS: usize = 16;
pub const DISPLAY_ROWS: usize = 4;

/// Two-button input event.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Button {
    Left,
    Right,
}

/// Press duration. Long press is detected when the button is held for at
/// least ~500 ms; the exact threshold is backend-defined.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Press {
    Short,
    Long,
}

// ── the mounted trusted-display modules (unmodified) ────────────────────
#[path = "../../secure/src/ui/secret_text.rs"]
pub mod secret_text;
#[path = "../../secure/src/ui/lcd.rs"]
pub mod ui_lcd;

// ── test-facing glyph shims ──────────────────────────────────────────────
// `secret_glyph_cols`/`public_glyph_cols` are `pub(crate)` inside the mounted
// `secret_text`, so integration tests (a separate crate) cannot name them.
// These wrappers re-expose them for the independent in-test rasterizer and
// the CT-vs-public agreement test. The `[u8; 5]` return pins FONT_GLYPH_W.
pub fn public_glyph_cols(ch: u8) -> [u8; 5] {
    secret_text::public_glyph_cols(ch)
}

pub fn secret_glyph_cols(ch: u8) -> [u8; 5] {
    secret_text::secret_glyph_cols(ch)
}

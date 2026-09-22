//! Host-compilable render substrate for the ERC-7730 (and shared) display path.
//!
//! This module owns the pure-logic pieces of the trusted-display renderer so
//! they can be host-linked (and fuzzed) instead of being trapped behind the
//! secure crate's `#[cfg(not(test))]`-gated `tx::display` tree — which is gated
//! only because its parent `mod.rs` imports the hardware-only
//! `crate::ui::confirm::Page`. It holds:
//!
//! * [`Page`] / [`Pages`] / [`MAX_PAGES`] — the fixed-capacity page buffer every
//!   renderer fills and hands to `crate::ui::confirm`. The secure crate
//!   re-exports `Pages`/`MAX_PAGES` (`tx::display::mod.rs`), so its ~415 direct
//!   `.buf`/`.len` accessors across the display tree keep compiling cross-crate.
//! * [`primitives`] — the row-buffer byte-writers (amount/decimal scaling,
//!   address truncation, hex, chain/ticker naming). `overflow-checks = true` in
//!   the firmware profile turns any arithmetic slip in the amount writers on an
//!   attacker-controlled `U256` (the value comes from calldata) into a panic =
//!   DoS; `fuzz/fuzz_targets/erc7730_display_primitives.rs` hammers them.
//! * [`ascii_str`] — the `no_std` ASCII-by-construction `&str` helper the
//!   renderers use in place of `from_utf8_unchecked`.
//!
//! The per-`FormatOp` ERC-7730 render (dispatch → field iteration → page
//! emission) lives in [`crate::render`]'s sibling `render_pages` module and is
//! fuzzed via `fuzz/fuzz_targets/erc7730_render_dispatch.rs`.
//!
//! `DISPLAY_COLS`/`DISPLAY_ROWS` are redeclared here (= the secure `crate::ui`
//! constants). Since they are equal, `Page` = `[[u8; 16]; 4]` is the SAME
//! concrete type on both sides, so the secure `ui::confirm::Page` and the row
//! buffers callers pass need no re-export — only the named `Pages`/`MAX_PAGES`
//! struct does.

pub mod primitives;
pub mod render;

/// ERC-8213 trusted-display layout constants consumed by the secure renderer
/// and the generated companion semantic manifest.
pub mod erc8213_contract {
    /// Banner plus complete-hash page.  Appending is atomic: either both fit or
    /// the signing caller refuses.
    pub const FINGERPRINT_PAGES: usize = 2;
    /// ERC-8213 fingerprint width surfaced on the trusted display.
    pub const HASH_BYTES: usize = 32;
    /// Bytes encoded as hex on each 16-column row.
    pub const HASH_BYTES_PER_ROW: usize = 8;

    const _: () = assert!(HASH_BYTES_PER_ROW * super::DISPLAY_ROWS == HASH_BYTES);
}

/// Logical display dimensions (cells, not pixels). MUST equal the secure
/// crate's `crate::ui::{DISPLAY_COLS, DISPLAY_ROWS}` — pinned by the asserts
/// below and by `secure/src/ui_under_test`, so the two sides can never drift
/// unnoticed (a mismatch is a hard type error at the re-export, not silent).
pub const DISPLAY_COLS: usize = 16;
/// See [`DISPLAY_COLS`].
pub const DISPLAY_ROWS: usize = 4;

const _: () = assert!(DISPLAY_COLS == 16);
const _: () = assert!(DISPLAY_ROWS == 4);

/// A single confirm-dialog page: [`DISPLAY_ROWS`] rows of [`DISPLAY_COLS`]
/// ASCII cells. Structurally identical to the secure `crate::ui::confirm::Page`
/// (`[[u8; 16]; 4]`), so the two are the same concrete type.
pub type Page = [[u8; DISPLAY_COLS]; DISPLAY_ROWS];

/// Hard cap on the number of pages any renderer may emit. Bumped only
/// deliberately: 22 → 24 with multiSend clear-sign; 24 → 27 with the Safe
/// gas-refund magnitude page + the Safe/CoW gas/fee splice; 27 → 28 with the
/// Safe `safeTxGas` page (conditional on `safeTxGas != 0`; audit 2026-06-26);
/// 28 → 29 for the mandatory full UserOp signer account/address page
/// (audit 2026-07-10); 29 → 30 for the mandatory full outer target-contract
/// page on every single transaction / batch member; 30 → 31 for the
/// conditional full 192-bit EntryPoint nonce-lane page (audit finding #3,
/// 2026-07-10). The Safe multiSend sign-gate reserves all handler pages, so
/// the budget still fails closed (refuse, never truncate).
pub const MAX_PAGES: usize = 31;

/// Non-display byte used to separate two renders that reuse one [`Pages`]
/// allocation. No valid renderer page contains this value because every
/// trusted-display byte is printable ASCII.
pub const TRANSCRIPT_POISON: u8 = 0xA5;

/// A buffer of up to [`MAX_PAGES`] pre-rendered confirmation pages.
///
/// Owned-by-value: every renderer returns a fresh `Pages` on the stack and the
/// caller hands `pages.as_slice()` to `crate::ui::confirm::confirm` for the
/// navigation loop. The buffer is always allocated for the full [`MAX_PAGES`]
/// so that only `len` changes between renderers — callers must never index past
/// `len`.
///
/// The fields are `pub` (not `pub(super)`) so the on-device renderers that stay
/// in the secure crate can keep writing them directly cross-crate. This is a
/// code-hygiene surface, not a security boundary: `Pages` is internal firmware
/// plumbing with no attacker-reachable constructor, and the sanctioned builders
/// remain [`Pages::empty_with_len`] / [`Pages::with_len`] / [`Pages::push_blank`]
/// (the last two enforce the `MAX_PAGES` cap).
pub struct Pages {
    /// The full `MAX_PAGES`-sized page buffer. Renderers write directly into
    /// their own slots; external callers must use [`Pages::as_slice`].
    pub buf: [Page; MAX_PAGES],
    /// Number of currently-visible pages (`0..=MAX_PAGES`).
    pub len: usize,
}

impl Pages {
    /// View the visible pages (indices `0..len`) as a slice. This is what
    /// `confirm()` consumes.
    #[must_use]
    pub fn as_slice(&self) -> &[Page] {
        &self.buf[..self.len]
    }

    /// Construct a page bundle with exactly `len` visible pages, pre-filled with
    /// ASCII space.
    #[must_use]
    pub fn empty_with_len(len: usize) -> Self {
        assert!(len <= MAX_PAGES, "Pages::empty_with_len: len > MAX_PAGES");
        Pages {
            buf: [[[b' '; DISPLAY_COLS]; DISPLAY_ROWS]; MAX_PAGES],
            len,
        }
    }

    /// Mutable access to a single row within a single page. Bounds-checked;
    /// panics on out-of-range indices (a firmware bug — both indices come from
    /// compile-time constants).
    pub fn row_mut(&mut self, page: usize, row: usize) -> &mut [u8; DISPLAY_COLS] {
        assert!(page < self.len);
        assert!(row < DISPLAY_ROWS);
        &mut self.buf[page][row]
    }

    /// Mutable access to the full row array of one page. Used by renderers that
    /// mutate two rows of the same page simultaneously (via `split_at_mut`).
    pub fn page_mut(&mut self, page: usize) -> &mut [[u8; DISPLAY_COLS]; DISPLAY_ROWS] {
        assert!(page < self.len);
        &mut self.buf[page]
    }

    /// Shortcut for [`Pages::empty_with_len`].
    #[must_use]
    pub fn with_len(len: usize) -> Self {
        Self::empty_with_len(len)
    }

    /// Bump `len` by one and return the index of the newly-visible page. Returns
    /// `Err(())` when the buffer is already full; renderers map that to
    /// `RenderErr::PageBudget`, which hard-refuses an authenticated known call
    /// rather than falling through to a less complete rendering. The returned
    /// page is pre-cleared to ASCII space.
    pub fn push_blank(&mut self) -> Result<usize, ()> {
        if self.len >= MAX_PAGES {
            return Err(());
        }
        // Re-clear the slot so dynamic-push renderers don't inherit prior
        // content (older renderers overran past `len` and bumped it).
        self.buf[self.len] = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
        let idx = self.len;
        self.len += 1;
        Ok(idx)
    }

    /// Volatile-poison the full fixed buffer and reset its visible length.
    ///
    /// The secure ERC-7730 dispatcher calls this between two complete renders
    /// into the same allocation. Volatile writes prevent LLVM from deleting
    /// the poison as dead stores before the second render. If the second render
    /// is skipped, the empty/poisoned buffer cannot match the first receipt; if
    /// this reset is skipped, the independently rendered second pass still
    /// clears every page it publishes.
    #[inline(never)]
    pub fn volatile_poison_and_reset(&mut self) {
        for page in &mut self.buf {
            for row in page {
                volatile_poison_bytes(row);
            }
        }
        // Write the length last: a skipped second render then exposes either a
        // zero count or poison bytes, both of which fail the transcript proof.
        volatile_reset_len(&mut self.len);
    }

    /// Readback used before granting the reset CFI step.
    #[must_use]
    #[inline(never)]
    pub fn is_transcript_poisoned(&self) -> bool {
        self.len == 0
            && self
                .buf
                .iter()
                .flat_map(|page| page.iter())
                .flat_map(|row| row.iter())
                .all(|byte| *byte == TRANSCRIPT_POISON)
    }
}

/// Volatile-fill a display byte buffer with [`TRANSCRIPT_POISON`].
///
/// Shared by [`Pages::volatile_poison_and_reset`] and the pixel-UI `Screens`
/// transcript in `pqsigner-ui-px` (whose records are printable ASCII by
/// construction, exactly like `Page`, so the same poison byte is unreachable
/// there too). Lives here so that crate can stay 100% safe Rust: this file is
/// one of the three documented host-verified `unsafe` exceptions in the
/// `no-unsafe-in-pure-logic-crates` semgrep gate. Volatile writes prevent LLVM
/// from deleting the poison as dead stores before the next render.
#[inline(never)]
pub fn volatile_poison_bytes(buf: &mut [u8]) {
    for byte in buf {
        // SAFETY: `byte` comes from this unique mutable borrow of a live slice
        // element; a volatile write of a `u8` through it is always valid.
        unsafe { core::ptr::write_volatile(byte, TRANSCRIPT_POISON) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Volatile-zero a byte buffer and fence (the alignment-free twin of
/// [`volatile_reset_len`] for byte-encoded length fields).
#[inline(never)]
pub fn volatile_zero_bytes(buf: &mut [u8]) {
    for byte in buf {
        // SAFETY: `byte` is a unique live mutable borrow of a slice element.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Volatile-zero a transcript length word and fence, so a skipped re-render
/// exposes a zero count (or the poison bytes) to the transcript proof.
#[inline(never)]
pub fn volatile_reset_len(len: &mut usize) {
    // SAFETY: `len` is a unique live mutable borrow; a volatile store through
    // it is always valid.
    unsafe { core::ptr::write_volatile(len, 0) };
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Convert an ASCII-by-construction byte buffer into a `&str` without `unsafe`.
///
/// All call sites build their buffers from printable ASCII (digits, hex, BIP-39
/// words, fixed labels). The `from_utf8` validator is O(n) over a ≤64-byte
/// buffer — negligible. The `"?"` fallback is structurally unreachable; it
/// exists only so this helper is safe (no `from_utf8_unchecked`).
#[inline]
#[must_use]
pub fn ascii_str(buf: &[u8]) -> &str {
    core::str::from_utf8(buf).unwrap_or("?")
}

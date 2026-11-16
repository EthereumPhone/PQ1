//! Pixel-UI assets: a VERIFIED view over the atlas container the NON-SECURE
//! image carries (`ui-px` + `ui-lcd`).
//!
//! Owner decision 2026-09-23 (port plan § Flash): the glyph atlas + disc
//! marks (~74 KB, `nonsecure/assets/ui-px/atlas.pq1a`, baked by
//! `tools/ui_px_assets.py`) no longer live in the secure A/B slot. The NS
//! image parks them at a fixed slot-relative offset (`ATLAS_SLOT_OFFSET`,
//! `nonsecure/memory-stm32u585-px.x`), inside the region the FSBL measures
//! at boot (invariant #10). The secure world holds only the container's
//! SHA-256 (`ATLAS_ROOT`, generated into `atlas_root.rs` by the bake) and
//! treats the NS bytes as untrusted until proven:
//!
//! * [`verify_atlas`] copies the window into secure RAM (SRAM3), hashes the
//!   COPY and requires `ct_eq(ATLAS_ROOT)` through a sentinel gate BEFORE a
//!   pixel dialog; every paint reads the copy, never the flash (#1133: flash
//!   can be reprogrammed during a dialog and programmed back before a second
//!   hash, so hashing the flash twice did not bind what was drawn);
//! * [`atlas_root_proof`] re-hashes the copy AFTER the dialog, and the sign
//!   handler refuses to release a signature unless it is `OK_SENTINEL` again
//!   — a faulted or overwritten copy is caught before release;
//! * the non-dialog painters (status / progress text through the engine)
//!   use [`atlas`], a once-verified cached view; a bad atlas at boot makes
//!   them fall back to the legacy glyph blitter and every pixel dialog
//!   refuse (fail-visible at boot, fail-closed for signing).
//!
//! A wrong font could turn a `0` into an `8` on the trusted display, so the
//! atlas is a WYSIWYS input and gets the same verify-before-release
//! discipline as the transcript. Licences: `secure/assets/ui-px/LICENSES/`.

use core::sync::atomic::{AtomicU8, Ordering};

use pqsigner_ui_px::font::Font;
use pqsigner_ui_px::pq1a::{self, Atlas};
use pqsigner_ui_px::scene::{parse_mark, Marks};
use subtle::ConstantTimeEq;

#[path = "atlas_root.rs"]
mod atlas_root;
pub use atlas_root::{ATLAS_LEN, ATLAS_ROOT};

/// Slot-relative offset of the container in the NS image
/// (`nonsecure/memory-stm32u585-px.x`: `.pq1a` at `ORIGIN(FLASH) + 0x1000`).
pub const ATLAS_SLOT_OFFSET: u32 = 0x1000;
/// The window the NS linker script reserves for it (its `_pq1a_span`).
pub const ATLAS_SPAN: u32 = 0x1_3000;
const _: () = assert!(ATLAS_LEN <= ATLAS_SPAN as usize);
const _: () = assert!(ATLAS_LEN >= pq1a::HEADER_LEN);

/// Base of the NS image the secure world booted (`main.rs` boots NS from the
/// same constant). Single site: becomes `slot_ns_addr(running_slot())` when
/// the v6 geometry (#540) moves the NS slots off `0x0810_0000`.
fn ns_image_base() -> u32 {
    crate::NS_FLASH_BASE
}

/// Secure RAM the container is copied into before it is hashed or drawn
/// (#1133): the start of SRAM3 through its secure alias. SRAM3 (512 KiB) has
/// no other user, MPCBB3 leaves it secure (reset default), and the SAU does
/// not cover it, so the non-secure world can neither read nor write it.
const ATLAS_RAM_BASE: u32 = 0x3004_0000;
const SRAM3_LEN: usize = 512 * 1024;
const _: () = assert!(ATLAS_LEN <= SRAM3_LEN);

/// Copy the non-secure window into secure RAM (volatile reads, one pass).
///
/// Until 2026-11-10 every frame of a dialog was drawn straight from the
/// non-secure flash, between a hash before the dialog and a hash after it.
/// Non-secure exception handlers run while a dialog is up, and flash can be
/// reprogrammed and then programmed back, so both hashes could pass around
/// frames drawn with other glyphs. Now the hash and every paint read this
/// copy, which only the secure world can write.
#[inline(never)]
fn load_copy() {
    let src = ns_image_base().wrapping_add(ATLAS_SLOT_OFFSET) as *const u8;
    let dst = ATLAS_RAM_BASE as *mut u8;
    for i in 0..ATLAS_LEN {
        // SAFETY: `src + i` lies inside the NS flash alias window (bank 2,
        // always mapped and readable from the secure world; nothing in the
        // secure world writes it). `dst + i` lies inside SRAM3, which no
        // linker region, static or stack uses; the only reference ever made
        // to it is the shared slice `window()` returns. This function runs
        // only from `verify_atlas`, before it hands out a new view, and that
        // has two callers: (a) the gateway call that owns the glass, in
        // thread mode with the gateway gate held (one at a time), and
        // (b) PendSV, for the idle re-unlock dialog ("Locked", the PIN entry).
        // No #1154 landing path reaches it: landing frames, the finish and
        // the deferred Ready all read `atlas_film_frame` (pinned in
        // `film_landing_pure_tests`). In (b), a preempted gateway call can
        // still hold a view over these bytes only if the idle wipe fired
        // during a NON-busy call that draws; sign and unlock hold
        // `HandlerGuard`, which defers the wipe. That is the #152 overlap,
        // older than #1154, and the copy then rewrites the bytes with what
        // non-secure flash holds at that moment.
        unsafe { core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i))) };
    }
}

/// The secure-RAM copy as a slice. The bytes are UNTRUSTED until hashed.
fn window() -> &'static [u8] {
    // SAFETY: `[ATLAS_RAM_BASE, +ATLAS_LEN)` is inside SRAM3 (asserted
    // above), always mapped, initialised (zero after reset, then
    // `load_copy`), and written only by `load_copy`. The contents are NOT
    // trusted on address alone: every consumer goes through
    // `atlas_root_proof`.
    unsafe { core::slice::from_raw_parts(ATLAS_RAM_BASE as *const u8, ATLAS_LEN) }
}

/// A verified view: `data` hashed to `ATLAS_ROOT` and structurally parsed.
/// Not `Copy`/`Clone`: each dialog obtains its own through [`verify_atlas`].
pub struct AtlasRef {
    atlas: Atlas<'static>,
}

impl AtlasRef {
    /// The glyph atlas. A malformed atlas renders no glyphs (the bake and the
    /// root pin make this unreachable; belt and braces).
    #[must_use]
    pub fn font(&self) -> Font<'static> {
        self.atlas
            .entry(pq1a::NAME_FONTS)
            .and_then(Font::parse)
            .unwrap_or(Font::empty())
    }

    /// The disc marks (the disc itself is drawn procedurally).
    #[must_use]
    pub fn marks(&self) -> Marks<'static> {
        self.atlas.marks()
    }
}

/// Re-hash the secure-RAM copy (volatile reads) and compare with the pinned
/// root: `OK_SENTINEL` iff the bytes the painters read are the exact
/// container the secure image was built against. It does NOT re-read the
/// non-secure flash: what is in flash after the copy no longer matters.
#[inline(never)]
pub fn atlas_root_proof() -> u32 {
    let hash = crate::fw_update::verify::hash_flash(ATLAS_RAM_BASE, ATLAS_LEN as u32);
    crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(bool::from(hash[..].ct_eq(&ATLAS_ROOT[..])))
    })
}

/// Fresh verification for a pixel dialog: root proof, then a structural
/// parse of the container and each entry it must carry. `Err` = refuse the
/// dialog (never a fall-back to unverified glyphs).
#[inline(never)]
pub fn verify_atlas() -> Result<AtlasRef, ()> {
    // Latch the verdict on BOTH outcomes. Before 2026-09-24 only the
    // `atlas()` miss-path wrote `BOOT_STATE`, so a failure here left a
    // previously cached `BOOT_OK` standing for ever — and because a
    // tampered atlas makes THIS function fail, the tamper itself forced
    // every caller onto the legacy paint, which then rendered through that
    // stale `BOOT_OK`. Fail-open, in the one place that must fail closed.
    //
    // #1154 re-review N1: a Signed landing still live plays out FIRST, on
    // the copy `film_resolve` verified (only `load_copy` below writes it).
    // Every dialog verifies before it draws, so otherwise a non-secure atlas
    // swap after the sign made this verify fail, latch `BOOT_BAD`, and leave
    // the landing's film view refused: the landing ended without its check,
    // a way to replace SIGNED that is not a lock. A locked device cuts here
    // instead (the PendSV re-unlock dialog verifies too).
    #[cfg(not(feature = "ui-px-landing-blocking"))]
    super::lcd::landing_yield();
    match verify_atlas_inner() {
        Ok(a) => {
            BOOT_STATE.store(BOOT_OK, Ordering::Relaxed);
            Ok(a)
        }
        Err(()) => {
            BOOT_STATE.store(BOOT_BAD, Ordering::Relaxed);
            Err(())
        }
    }
}

#[inline(never)]
fn verify_atlas_inner() -> Result<AtlasRef, ()> {
    load_copy();
    crate::fi::scrub_sentinel_register();
    if atlas_root_proof() != crate::fi::OK_SENTINEL {
        return Err(());
    }
    crate::fi::scrub_sentinel_register();
    let atlas = Atlas::parse(window()).ok_or(())?;
    let fonts = atlas.entry(pq1a::NAME_FONTS).ok_or(())?;
    Font::parse(fonts).ok_or(())?;
    for name in pq1a::MARK_NAMES {
        parse_mark(atlas.entry(name).ok_or(())?).ok_or(())?;
    }
    Ok(AtlasRef { atlas })
}

const BOOT_UNKNOWN: u8 = 0;
const BOOT_OK: u8 = 1;
const BOOT_BAD: u8 = 2;
/// Once-verified verdict for the non-dialog painters.
static BOOT_STATE: AtomicU8 = AtomicU8::new(BOOT_UNKNOWN);

/// A FRESHLY VERIFIED view — re-copies and re-hashes the NS window on every call, so the
/// bytes are the authority rather than a cached verdict. This is what every
/// paint the user READS AND ACTS ON must use, including `lcd::paint_legacy`,
/// which is where `ui::confirm`'s pages land under `ui-px`.
///
/// Costs one `hash_flash` over `ATLAS_LEN` (75 KB) per call. That is fine
/// for page-rate paints; it is NOT fine per animation frame — see
/// [`atlas_film_frame`].
pub fn atlas_verified() -> Option<AtlasRef> {
    match verify_atlas() {
        Ok(a) => Some(a),
        Err(()) => {
            secure_log!("[S] UI_PX_ATLAS_BAD: NS atlas window does not match ATLAS_ROOT; pixel dialogs will refuse");
            None
        }
    }
}

/// The loading film's IN-BETWEEN FRAMES ONLY. Returns a view WITHOUT
/// re-hashing, so it is sound only inside a window that a successful
/// [`atlas_verified`] opened (`film_start_with`) and a later one closes
/// (`film_resolve`) — the same verify-before-and-after bracket the sign
/// dialogs use. Refused for ever once any verification has failed.
///
/// Also the Signed film's landing frames after the sign returned (#1154),
/// drawn from PendSV or a later gateway call: `film_resolve`'s verify opens
/// that window and the next dialog's verify closes it. The non-secure world
/// runs inside it, which is sound only because the bytes are this secure
/// SRAM3 copy (#1133), written by [`load_copy`] alone, never non-secure
/// flash.
///
/// The film is an orbit animation and a fixed caption; it carries nothing
/// the user authorises. NEVER use this for a paint that does.
pub fn atlas_film_frame() -> Option<AtlasRef> {
    match BOOT_STATE.load(Ordering::Relaxed) {
        BOOT_OK => Atlas::parse(window()).map(|atlas| AtlasRef { atlas }),
        _ => None,
    }
}

/// Asset bytes embedded in the SECURE image (for the size report): none —
/// the container lives in the NS slot.
pub const ASSET_BYTES: usize = 0;

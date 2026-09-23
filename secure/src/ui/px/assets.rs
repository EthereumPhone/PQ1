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
//! * [`verify_atlas`] re-hashes the window with volatile reads and requires
//!   `ct_eq(ATLAS_ROOT)` through a sentinel gate BEFORE a pixel dialog;
//! * [`atlas_root_proof`] re-hashes AFTER the dialog, and the sign handler
//!   refuses to release a signature unless it is `OK_SENTINEL` again — a
//!   glyph swap during the dialog (an NS world reprogramming its own flash)
//!   is caught before release, the same way a faulted page is;
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

/// The fixed window as a slice. The bytes are UNTRUSTED until hashed.
fn window() -> &'static [u8] {
    let base = ns_image_base().wrapping_add(ATLAS_SLOT_OFFSET) as *const u8;
    // SAFETY: `[NS_FLASH_BASE + ATLAS_SLOT_OFFSET, +ATLAS_LEN)` lies inside
    // the STM32U585 NS flash alias (bank 2, `sau::SAU_NS_FLASH_BASE..END`),
    // which is always mapped and readable from the secure world (the
    // fw-update image check reads it the same way); nothing in the secure
    // world ever writes it, and `ATLAS_LEN <= ATLAS_SPAN` keeps the slice
    // inside the reserved window. The slice's contents are NOT trusted on
    // address alone — every consumer goes through `atlas_root_proof`.
    unsafe { core::slice::from_raw_parts(base, ATLAS_LEN) }
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
        Marks {
            safe: self.atlas.entry(pq1a::NAME_SAFE).and_then(parse_mark),
            mainnet: self.atlas.entry(pq1a::NAME_MAINNET).and_then(parse_mark),
            base: self.atlas.entry(pq1a::NAME_BASE).and_then(parse_mark),
            fingerprint: None,
        }
    }
}

/// Re-hash the whole window (volatile reads, like the fw-update image check)
/// and compare with the pinned root: `OK_SENTINEL` iff the NS bytes are the
/// exact container the secure image was built against.
#[inline(never)]
pub fn atlas_root_proof() -> u32 {
    let hash = crate::fw_update::verify::hash_flash(
        ns_image_base().wrapping_add(ATLAS_SLOT_OFFSET),
        ATLAS_LEN as u32,
    );
    crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(bool::from(hash[..].ct_eq(&ATLAS_ROOT[..])))
    })
}

/// Fresh verification for a pixel dialog: root proof, then a structural
/// parse of the container and each entry it must carry. `Err` = refuse the
/// dialog (never a fall-back to unverified glyphs).
#[inline(never)]
pub fn verify_atlas() -> Result<AtlasRef, ()> {
    crate::fi::scrub_sentinel_register();
    if atlas_root_proof() != crate::fi::OK_SENTINEL {
        return Err(());
    }
    crate::fi::scrub_sentinel_register();
    let atlas = Atlas::parse(window()).ok_or(())?;
    let fonts = atlas.entry(pq1a::NAME_FONTS).ok_or(())?;
    Font::parse(fonts).ok_or(())?;
    for name in [pq1a::NAME_SAFE, pq1a::NAME_MAINNET, pq1a::NAME_BASE] {
        parse_mark(atlas.entry(name).ok_or(())?).ok_or(())?;
    }
    Ok(AtlasRef { atlas })
}

const BOOT_UNKNOWN: u8 = 0;
const BOOT_OK: u8 = 1;
const BOOT_BAD: u8 = 2;
/// Once-verified verdict for the non-dialog painters.
static BOOT_STATE: AtomicU8 = AtomicU8::new(BOOT_UNKNOWN);

/// The cached view for status / progress paints: verified on first use
/// (boot), `None` forever after a failed verification. Dialogs never use
/// this — they call [`verify_atlas`] fresh and re-prove afterwards.
pub fn atlas() -> Option<AtlasRef> {
    match BOOT_STATE.load(Ordering::Relaxed) {
        BOOT_OK => Atlas::parse(window()).map(|atlas| AtlasRef { atlas }),
        BOOT_BAD => None,
        _ => match verify_atlas() {
            Ok(a) => {
                BOOT_STATE.store(BOOT_OK, Ordering::Relaxed);
                Some(a)
            }
            Err(()) => {
                BOOT_STATE.store(BOOT_BAD, Ordering::Relaxed);
                secure_log!("[S] UI_PX_ATLAS_BAD: NS atlas window does not match ATLAS_ROOT; pixel dialogs will refuse");
                None
            }
        },
    }
}

/// Asset bytes embedded in the SECURE image (for the size report): none —
/// the container lives in the NS slot.
pub const ASSET_BYTES: usize = 0;

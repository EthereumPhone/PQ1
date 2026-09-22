//! Baked pixel-UI assets embedded in the secure image (`ui-px` + `ui-lcd`).
//!
//! Produced by `tools/ui_px_assets.py` from the vendored PQ-UI fonts and
//! marks; `secure/build.rs` re-validates the headers, sizes and the manifest
//! before every build (`make ui-px-assets-check` proves reproducibility).
//! Licences: `secure/assets/ui-px/LICENSES/`.

use pqsigner_ui_px::font::Font;
use pqsigner_ui_px::raster::Mask;
use pqsigner_ui_px::scene::{parse_mark, Marks};

/// Aileron glyph atlases (4-bit alpha, the pilot's eight tiers).
pub static FONTS: &[u8] = include_bytes!("../../../assets/ui-px/fonts.bin");
/// Safe logo mark (alpha mask; the disc is drawn procedurally).
pub static SAFE_MARK: &[u8] = include_bytes!("../../../assets/ui-px/safe.a4");
/// Mainnet (ETH) chain mark.
pub static MAINNET_MARK: &[u8] = include_bytes!("../../../assets/ui-px/mainnet.a4");
/// Base chain mark.
pub static BASE_MARK: &[u8] = include_bytes!("../../../assets/ui-px/base.a4");

/// The parsed atlas; a malformed atlas renders no glyphs (the build script
/// refuses such an image, so this is belt-and-braces).
#[must_use]
pub fn font() -> Font<'static> {
    Font::parse(FONTS).unwrap_or(Font::empty())
}

#[must_use]
pub fn marks() -> Marks<'static> {
    Marks {
        safe: parse_mark(SAFE_MARK),
        mainnet: parse_mark(MAINNET_MARK),
        base: parse_mark(BASE_MARK),
        fingerprint: None,
    }
}

/// Total embedded asset bytes (for the size report).
pub const ASSET_BYTES: usize = FONTS.len() + SAFE_MARK.len() + MAINNET_MARK.len() + BASE_MARK.len();

#[allow(dead_code)]
fn _mask_type_check(_m: Mask<'static>) {}

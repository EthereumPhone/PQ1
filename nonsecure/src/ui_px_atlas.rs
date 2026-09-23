//! The pixel trusted-UI asset container, carried by the NON-SECURE image.
//!
//! `assets/ui-px/atlas.pq1a` (baked by `tools/ui_px_assets.py`: the Aileron
//! glyph tiers + the disc marks, ~74 KB) is placed by
//! `memory-stm32u585-px.x` in its own output section at a FIXED offset from
//! the slot base (`.pq1a` at `ORIGIN(FLASH) + 0x1000`, right after the vector
//! table), so the secure world can find it at the same slot-relative address
//! in either A/B slot without any NS-supplied pointer. It lives here, not in
//! the secure A/B slot, because the secure image cannot hold it (port plan
//! § Flash) and the NS slot is already measured by the FSBL at boot
//! (invariant #10).
//!
//! Nothing on the NS side reads these bytes. The secure world treats them as
//! untrusted until it has hashed the whole window against the root pinned
//! into ITS image (`secure/src/ui/px/atlas_root.rs`), and re-hashes after
//! every pixel dialog before releasing a signature.
#[link_section = ".pq1a"]
#[used]
pub static PQ1A_BLOB: [u8; include_bytes!("../assets/ui-px/atlas.pq1a").len()] =
    *include_bytes!("../assets/ui-px/atlas.pq1a");

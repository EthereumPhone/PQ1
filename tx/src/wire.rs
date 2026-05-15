//! Shared wire-decoding helpers for the bundle parsers.
//!
//! All three trust bundles (`erc20`, `names`, `selectors`) consume the
//! same little-endian primitives and the same printable-ASCII gate, so
//! the helpers live here rather than being copy-pasted into each
//! parser. Kept crate-private — the public API is the per-bundle
//! `verify_*_bundle` functions.

/// Read a little-endian `u32` at `off`. Returns `None` if the slice is
/// too short.
#[inline]
pub(crate) fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let bytes: [u8; 4] = buf.get(off..off + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// Read a little-endian `u64` at `off`. Returns `None` if the slice is
/// too short.
#[inline]
pub(crate) fn read_u64_le(buf: &[u8], off: usize) -> Option<u64> {
    let bytes: [u8; 8] = buf.get(off..off + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// Printable-ASCII gate (0x20..=0x7e). Rejects control bytes and any
/// byte ≥ 0x7f. The OLED only renders printable ASCII anyway, and
/// anything outside this range is a spoofing foothold (homoglyphs,
/// zero-width joiners, etc.).
#[inline]
pub(crate) fn is_clean_ascii(s: &[u8]) -> bool {
    s.iter().all(|&b| (0x20..0x7f).contains(&b))
}

//! `PQ1A` — the shipped pixel-UI asset container (glyph atlas + disc marks).
//!
//! `tools/ui_px_assets.py` packs `fonts.bin` and the `*.a4` marks into one
//! blob that the NON-SECURE image carries at a fixed slot offset; the secure
//! world hashes that window against a pinned root (`ATLAS_ROOT`) and only
//! then hands the entries to [`crate::font::Font::parse`] / [`crate::scene::parse_mark`].
//! This module is the pure, bounds-checked reader of that container — every
//! offset it returns lies inside the slice it was given, so a corrupt table
//! yields `None`, never an out-of-range read.
//!
//! Layout (little-endian):
//!
//! ```text
//! Header   magic b"PQ1A" | version u16 | n_entries u16 | total_len u32 | reserved[20]   (32 B)
//! Entry[n] name[8] (ASCII, NUL-padded) | off u32 | len u32                             (16 B)
//! Payload  each entry's bytes at `off` from the container start
//! ```

/// Container magic.
pub const MAGIC: &[u8; 4] = b"PQ1A";
/// The only format version this reader accepts.
pub const VERSION: u16 = 1;
/// Fixed header size.
pub const HEADER_LEN: usize = 32;
/// Size of one entry-table record.
pub const ENTRY_LEN: usize = 16;
/// Upper bound on entries (the table walk is bounded by this, not by the
/// header's claim).
pub const MAX_ENTRIES: usize = 16;

/// Entry names as written by the bake script.
pub const NAME_FONTS: &[u8; 8] = b"fonts\0\0\0";
pub const NAME_SAFE: &[u8; 8] = b"safe\0\0\0\0";
pub const NAME_MAINNET: &[u8; 8] = b"mainnet\0";
pub const NAME_BASE: &[u8; 8] = b"base\0\0\0\0";

/// A parsed container: the whole blob plus a validated entry count.
#[derive(Clone, Copy, Debug)]
pub struct Atlas<'a> {
    data: &'a [u8],
    n_entries: usize,
}

fn le_u16(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*d.get(at)?, *d.get(at + 1)?]))
}

fn le_u32(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *d.get(at)?,
        *d.get(at + 1)?,
        *d.get(at + 2)?,
        *d.get(at + 3)?,
    ]))
}

impl<'a> Atlas<'a> {
    /// Parse and validate the header and the whole entry table. Every entry
    /// must lie inside `data` and `total_len` must equal `data.len()` exactly
    /// (a truncated or padded blob is refused; the caller's hash check is the
    /// authority on the bytes, this is the authority on the shape).
    #[must_use]
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < HEADER_LEN || &data[..4] != MAGIC {
            return None;
        }
        if le_u16(data, 4)? != VERSION {
            return None;
        }
        let n_entries = usize::from(le_u16(data, 6)?);
        if n_entries == 0 || n_entries > MAX_ENTRIES {
            return None;
        }
        let total = le_u32(data, 8)? as usize;
        if total != data.len() {
            return None;
        }
        let table_end = HEADER_LEN.checked_add(n_entries.checked_mul(ENTRY_LEN)?)?;
        if table_end > data.len() {
            return None;
        }
        let atlas = Self { data, n_entries };
        // Validate every entry now so `entry()` can never index out of range.
        for i in 0..n_entries {
            let (off, len) = atlas.entry_span(i)?;
            let end = off.checked_add(len)?;
            if off < table_end || end > data.len() {
                return None;
            }
        }
        Some(atlas)
    }

    /// Number of entries in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.n_entries
    }

    /// `true` when the table is empty (never, for a parsed container).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.n_entries == 0
    }

    fn entry_span(&self, i: usize) -> Option<(usize, usize)> {
        let rec = HEADER_LEN + i * ENTRY_LEN;
        let off = le_u32(self.data, rec + 8)? as usize;
        let len = le_u32(self.data, rec + 12)? as usize;
        Some((off, len))
    }

    /// The bytes of the entry called `name` (exact 8-byte match), if present.
    #[must_use]
    pub fn entry(&self, name: &[u8; 8]) -> Option<&'a [u8]> {
        for i in 0..self.n_entries {
            let rec = HEADER_LEN + i * ENTRY_LEN;
            if self.data.get(rec..rec + 8)? == name {
                let (off, len) = self.entry_span(i)?;
                return self.data.get(off..off.checked_add(len)?);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn container(entries: &[(&[u8; 8], &[u8])]) -> std::vec::Vec<u8> {
        let hdr = HEADER_LEN + ENTRY_LEN * entries.len();
        let mut off = (hdr + 3) & !3;
        let mut table = std::vec::Vec::new();
        let mut payload = std::vec::Vec::new();
        for (name, blob) in entries {
            while (off + payload.len()) % 4 != 0 {
                payload.push(0);
            }
            let start = off + payload.len();
            table.extend_from_slice(*name);
            table.extend_from_slice(&(start as u32).to_le_bytes());
            table.extend_from_slice(&(blob.len() as u32).to_le_bytes());
            payload.extend_from_slice(blob);
        }
        let total = off + payload.len();
        let mut out = std::vec::Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out.extend_from_slice(&[0u8; 20]);
        out.extend_from_slice(&table);
        while out.len() < off {
            out.push(0);
        }
        off = out.len();
        let _ = off;
        out.extend_from_slice(&payload);
        out
    }

    #[test]
    fn round_trip_and_lookup() {
        let c = container(&[(NAME_FONTS, b"PQ1F....."), (NAME_SAFE, b"PQ1M")]);
        let a = Atlas::parse(&c).unwrap();
        assert_eq!(a.len(), 2);
        assert_eq!(a.entry(NAME_FONTS).unwrap(), b"PQ1F.....");
        assert_eq!(a.entry(NAME_SAFE).unwrap(), b"PQ1M");
        assert!(a.entry(NAME_BASE).is_none());
    }

    #[test]
    fn refuses_bad_magic_version_and_length() {
        let c = container(&[(NAME_FONTS, b"x")]);
        let mut bad = c.clone();
        bad[0] = b'Q';
        assert!(Atlas::parse(&bad).is_none());
        let mut bad = c.clone();
        bad[4] = 2;
        assert!(Atlas::parse(&bad).is_none());
        assert!(Atlas::parse(&c[..c.len() - 1]).is_none());
        let mut padded = c.clone();
        padded.push(0);
        assert!(Atlas::parse(&padded).is_none());
        assert!(Atlas::parse(&c[..HEADER_LEN - 1]).is_none());
    }

    #[test]
    fn refuses_entries_outside_the_blob_or_inside_the_table() {
        let c = container(&[(NAME_FONTS, b"abcd")]);
        // Length past the end.
        let mut bad = c.clone();
        bad[HEADER_LEN + 12] = 0xff;
        assert!(Atlas::parse(&bad).is_none());
        // Offset inside the header/table.
        let mut bad = c.clone();
        bad[HEADER_LEN + 8] = 0;
        assert!(Atlas::parse(&bad).is_none());
        // Zero or too many entries.
        let mut bad = c.clone();
        bad[6] = 0;
        assert!(Atlas::parse(&bad).is_none());
        let mut bad = c.clone();
        bad[6] = (MAX_ENTRIES + 1) as u8;
        assert!(Atlas::parse(&bad).is_none());
    }

    #[test]
    fn the_real_bake_parses() {
        let blob = include_bytes!("../../nonsecure/assets/ui-px/atlas.pq1a");
        let a = Atlas::parse(blob).unwrap();
        assert_eq!(a.len(), 4);
        assert!(a.entry(NAME_FONTS).unwrap().starts_with(b"PQ1F"));
        for n in [NAME_SAFE, NAME_MAINNET, NAME_BASE] {
            assert!(a.entry(n).unwrap().starts_with(b"PQ1M"));
        }
    }
}

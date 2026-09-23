//! Host-side rendering helpers (`std` feature): a full-frame render exactly
//! as the firmware does it (16-row strips) and a minimal PNG writer (stored
//! deflate), shared by the frame goldens and the `render_record` example
//! that `tools/ui_screens_export.py --px` uses to draw the QEMU transcripts.
//!
//! Never compiled into the firmware: it needs `std` and allocates.

extern crate std;

use std::io::Write;
use std::vec;
use std::vec::Vec;

use crate::font::Font;
use crate::raster::{render_strip, Frame, Rgb, Strip, H, W};
use crate::scene::{Anim, Marks};

/// Render the current pose in 16-row strips into a full RGB565 frame (the
/// bytes the panel receives on the device).
///
/// # Panics
/// Never for the fixed 428×142 geometry (every strip is 1..=16 rows).
#[must_use]
pub fn render_full(anim: &Anim, marks: &Marks<'_>, font: &Font<'_>) -> Vec<u16> {
    let mut frame = Frame::new();
    anim.build(marks, font, &mut frame);
    let mut out = vec![0u16; (W * H) as usize];
    let mut strip_buf = vec![0u16; (W * 16) as usize];
    let mut y0 = 0;
    while y0 < H {
        let h = 16.min(H - y0);
        let mut s = Strip::new(y0, h, &mut strip_buf).expect("strip");
        render_strip(&frame, font, &mut s);
        out[(y0 * W) as usize..((y0 + h) * W) as usize].copy_from_slice(&s.buf[..(W * h) as usize]);
        y0 += h;
    }
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
        }
    }
    !c
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &d in data {
        a = (a + u32::from(d)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

fn chunk(out: &mut Vec<u8>, kind: [u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    let mut c = Vec::with_capacity(4 + data.len());
    c.extend_from_slice(&kind);
    c.extend_from_slice(data);
    out.extend_from_slice(&c);
    out.extend_from_slice(&crc32(&c).to_be_bytes());
}

/// Encode a 428×142 RGB565 frame as a PNG (RGB8, stored deflate).
#[must_use]
pub fn png_bytes(px: &[u16]) -> Vec<u8> {
    let mut raw = Vec::with_capacity((H * (W * 3 + 1)) as usize);
    for y in 0..H {
        raw.push(0u8);
        for x in 0..W {
            let c = Rgb::from565(px[(y * W + x) as usize]);
            raw.extend_from_slice(&[c.r, c.g, c.b]);
        }
    }
    let mut z = vec![0x78u8, 0x01];
    for (i, block) in raw.chunks(65535).enumerate() {
        let last = (i + 1) * 65535 >= raw.len();
        z.push(u8::from(last));
        z.extend_from_slice(&(block.len() as u16).to_le_bytes());
        z.extend_from_slice(&(!(block.len() as u16)).to_le_bytes());
        z.extend_from_slice(block);
    }
    z.extend_from_slice(&adler32(&raw).to_be_bytes());
    let mut out = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&(W as u32).to_be_bytes());
    ihdr.extend_from_slice(&(H as u32).to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    chunk(&mut out, *b"IHDR", &ihdr);
    chunk(&mut out, *b"IDAT", &z);
    chunk(&mut out, *b"IEND", &[]);
    out
}

/// Write `px` as a PNG at `path` (parent directories created).
///
/// # Errors
/// Any I/O error creating or writing the file.
pub fn write_png(path: &std::path::Path, px: &[u16]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut f = std::fs::File::create(path)?;
    f.write_all(&png_bytes(px))
}

/// Decode one `[UI-PXR]` record (512 lowercase hex characters) into a screen.
#[must_use]
pub fn screen_from_hex(hex: &str) -> Option<crate::Screen> {
    let hex = hex.trim();
    if hex.len() != 2 * crate::SCREEN_BYTES {
        return None;
    }
    let mut raw = [0u8; crate::SCREEN_BYTES];
    for (i, b) in raw.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    let s = crate::Screen(raw);
    s.is_well_formed().then_some(s)
}

//! Dev-only (`ui-px-dma2d-bench`, NEVER ships: fenced in `nsc/mod.rs` and the
//! Makefile's PROD_FORBIDDEN): Chrom-ART (DMA2D) against the CPU rasteriser on
//! the work DMA2D could take from a busy-film frame, and whether its blend
//! matches `blend_over` bit for bit (the goldens hash what the panel
//! receives). Runs after the film recorder's pages on the idle band buffers;
//! no secure-element traffic. Owner 2026-10-22: "start the DMA2D work".
//!
//! Three timings, CPU then DMA2D, each over one 48-column band (6,816 px):
//! the band clear, a whole-band 4-bit alpha blend, and real glyph runs from
//! the atlas. DMA2D cannot rotate, so its glyphs are transposed here first
//! (untimed): each landscape column becomes one DMA2D line, bottom row first
//! (the band's wire order runs y downwards in address), low nibble first
//! (RM0456 Table 159, A4), padded to an even line (an odd A4 line is a
//! configuration error). In a driver the atlas would be baked that way.
//!
//! DMA2D is already secure-only (`sau.rs`, TZSC_SECCFGR3 bit 5): its master
//! issues secure transactions, so it reaches the secure band buffers, and
//! the non-secure world cannot program it. Secret text is not used here.

use crate::board;
use crate::hw::mmio::Reg32;
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};
use pqsigner_ui_px::font::{Align, Font, TextRun, TierId};
use pqsigner_ui_px::raster::{blend_over, Rgb, Strip, H};

/// DMA2D, secure alias (NS 0x4002_B000), AHB1. RM0456 memory map.
const DMA2D_S: u32 = 0x5002_B000;
/// `RCC_AHB1ENR.DMA2DEN`.
const RCC_AHB1ENR_DMA2DEN: u32 = 1 << 18;

struct Dma2dRegs {
    rcc_ahb1enr: Reg32,
    cr: Reg32,
    isr: Reg32,
    ifcr: Reg32,
    fgmar: Reg32,
    fgor: Reg32,
    bgmar: Reg32,
    bgor: Reg32,
    fgpfccr: Reg32,
    fgcolr: Reg32,
    bgpfccr: Reg32,
    opfccr: Reg32,
    ocolr: Reg32,
    omar: Reg32,
    oor: Reg32,
    nlr: Reg32,
}

// SAFETY: every address is a real DMA2D or RCC register on the secure alias,
// from RM0456 (DMA2D register map, offsets 0x00-0x44) and `board::RCC_S`.
const REG: Dma2dRegs = unsafe {
    Dma2dRegs {
        rcc_ahb1enr: Reg32::new(board::RCC_S + 0x088),
        cr: Reg32::new(DMA2D_S + 0x00),
        isr: Reg32::new(DMA2D_S + 0x04),
        ifcr: Reg32::new(DMA2D_S + 0x08),
        fgmar: Reg32::new(DMA2D_S + 0x0C),
        fgor: Reg32::new(DMA2D_S + 0x10),
        bgmar: Reg32::new(DMA2D_S + 0x14),
        bgor: Reg32::new(DMA2D_S + 0x18),
        fgpfccr: Reg32::new(DMA2D_S + 0x1C),
        fgcolr: Reg32::new(DMA2D_S + 0x20),
        bgpfccr: Reg32::new(DMA2D_S + 0x24),
        opfccr: Reg32::new(DMA2D_S + 0x34),
        ocolr: Reg32::new(DMA2D_S + 0x38),
        omar: Reg32::new(DMA2D_S + 0x3C),
        oor: Reg32::new(DMA2D_S + 0x40),
        nlr: Reg32::new(DMA2D_S + 0x44),
    }
};

const CR_START: u32 = 1 << 0;
const CR_ABORT: u32 = 1 << 2;
/// `DMA2D_CR.MODE[2:0]` (bits 18:16).
const MODE_M2M_BLEND: u32 = 0b010 << 16;
const MODE_R2M: u32 = 0b011 << 16;
const ISR_TEIF: u32 = 1 << 0;
const ISR_TCIF: u32 = 1 << 1;
const ISR_CAEIF: u32 = 1 << 3;
const ISR_CEIF: u32 = 1 << 5;
const ISR_ERR: u32 = ISR_TEIF | ISR_CAEIF | ISR_CEIF;
const IFCR_ALL: u32 = 0x3F;
/// `DMA2D_FGPFCCR.CM` / `DMA2D_BGPFCCR.CM` (4 bits) and `DMA2D_OPFCCR.CM` (3).
const CM_A4: u32 = 0b1010;
const CM_RGB565: u32 = 0b0010;
const OCM_RGB565: u32 = 0b010;
/// Polls before a transfer counts as hung (and is aborted).
const POLL_LIMIT: u32 = 2_000_000;

/// The band the bench works in: 48 landscape columns, all 142 rows.
const BAND_COLS: i32 = 48;
const BAND_PX: usize = (BAND_COLS * H) as usize;

/// What the bench measured. Cycles at 160 MHz.
pub struct Results {
    /// `(cpu, dma2d)`: the band clear, a whole-band A4 blend, the glyph runs.
    fill: (u32, u32),
    blend: (u32, u32),
    text: (u32, u32),
    glyphs: u32,
    /// Pixels that differ, pixels compared, the largest channel difference
    /// (8-bit units): glyphs over black, glyphs over a colour, the
    /// whole-band pattern.
    exact: [(u32, u32, u8); 3],
    /// Every DMA2D error flag seen (`TEIF`/`CAEIF`/`CEIF`), OR-ed, plus bit 31
    /// for a transfer that never ended and bit 30 for a fill that read back
    /// wrong.
    err: u32,
    /// Glyphs in the runs (DMA2D drew `glyphs` of them).
    glyphs_all: u32,
    /// The two register-to-memory fills (the first transfer after the clock
    /// enable, and one after the blends): `CR` read back after completion,
    /// the first pixel that is not 0 (`u32::MAX`: none) and its value.
    r2m: [(u32, u32, u16); 2],
}

/// Fill the band with `0x1234`, clear it with register-to-memory, and report
/// `(CR after, first non-zero pixel, its value)`.
fn r2m_probe(hw: &mut [u16], err: &mut u32) -> (u32, u32, u16, u32) {
    hw.fill(0x1234);
    let t = cycles();
    *err |= hw_fill(hw.as_mut_ptr(), H as u32, BAND_COLS as u32, 0, 0);
    let dt = cycles().wrapping_sub(t);
    let cr = REG.cr.read();
    match hw.iter().position(|&p| p != 0) {
        Some(i) => {
            *err |= 1 << 30;
            (cr, i as u32, hw[i], dt)
        }
        None => (cr, u32::MAX, 0, dt),
    }
}

fn cycles() -> u32 {
    crate::hw::lcd_te::cycles()
}

/// Start the programmed transfer and wait for it; the flags it ended on.
fn go(mode: u32) -> u32 {
    cortex_m::asm::dsb();
    REG.ifcr.write(IFCR_ALL);
    REG.cr.write(mode | CR_START);
    for _ in 0..POLL_LIMIT {
        let isr = REG.isr.read();
        if isr & (ISR_TCIF | ISR_ERR) != 0 {
            REG.ifcr.write(IFCR_ALL);
            // Order the caller's reads of the output after the completion.
            cortex_m::asm::dsb();
            return isr & ISR_ERR;
        }
    }
    REG.cr.write(CR_ABORT);
    1 << 31
}

/// Register-to-memory: `nl` lines of `pl` pixels of `c`, `oor` pixels apart.
fn hw_fill(dst: *mut u16, pl: u32, nl: u32, oor: u32, c: u16) -> u32 {
    REG.opfccr.write(OCM_RGB565);
    REG.ocolr.write(u32::from(c));
    REG.omar.write(dst as u32);
    REG.oor.write(oor);
    REG.nlr.write((pl << 16) | nl);
    go(MODE_R2M)
}

/// Blend an A4 source (`nl` lines of `pl` pixels, packed, low nibble first)
/// in `color` over the RGB565 pixels at `dst`, in place.
fn hw_blend_a4(src: *const u8, dst: *mut u16, pl: u32, nl: u32, oor: u32, color: Rgb) -> u32 {
    REG.fgmar.write(src as u32);
    REG.fgor.write(0);
    // AM = 00: the A4 alpha as it is (expanded n * 17).
    REG.fgpfccr.write(CM_A4);
    REG.fgcolr.write((u32::from(color.r) << 16) | (u32::from(color.g) << 8) | u32::from(color.b));
    REG.bgmar.write(dst as u32);
    REG.bgor.write(oor);
    REG.bgpfccr.write(CM_RGB565);
    REG.opfccr.write(OCM_RGB565);
    REG.omar.write(dst as u32);
    REG.oor.write(oor);
    REG.nlr.write((pl << 16) | nl);
    go(MODE_M2M_BLEND)
}

/// The CPU twin of [`hw_blend_a4`] over the same layout, with `blit_glyph`'s
/// inner loop (zero skip, the over-black table, `blend_over` otherwise).
fn cpu_blend_a4(src: &[u8], dst: &mut [u16], pl: usize, nl: usize, color: Rgb) {
    let mut lut = [0u8; 16];
    let mut over_black = [0u16; 16];
    for n in 0..16 {
        lut[n] = (n * 17) as u8;
        over_black[n] = blend_over(0, color, lut[n]);
    }
    for l in 0..nl {
        for p in 0..pl {
            let k = l * pl + p;
            let b = src[k / 2];
            let n = usize::from(if k % 2 == 0 { b & 0x0F } else { b >> 4 });
            if n != 0 {
                let i = l * H as usize + p;
                let d = dst[i];
                dst[i] = if d == 0 { over_black[n] } else { blend_over(d, color, lut[n]) };
            }
        }
    }
}

/// `(differing pixels, pixels, largest channel difference)` of two bands.
fn compare(a: &[u16], b: &[u16]) -> (u32, u32, u8) {
    let mut diff = 0u32;
    let mut max = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        if x != y {
            diff += 1;
            let (p, q) = (Rgb::from565(x), Rgb::from565(y));
            max = max.max(p.r.abs_diff(q.r)).max(p.g.abs_diff(q.g)).max(p.b.abs_diff(q.b));
        }
    }
    (diff, a.len().min(b.len()) as u32, max)
}

/// The glyph runs: six lines of three, inside the band's 48 columns so the
/// CPU and DMA2D draw the same glyphs (four overran it on 2026-10-22).
const LINES: [&[u8]; 6] = [b"Sig", b"0.2", b"ETH", b"abc", b"XYZ", b"snd"];
const TEXT_COLOR: Rgb = Rgb::new(0xE8, 0xE4, 0xDC);

fn run_at(text: &[u8], line: usize) -> TextRun<'_> {
    TextRun {
        text,
        tier: TierId::regular(18),
        x: 2,
        y: 24 + 20 * line as i32,
        align: Align::Left,
        baseline: true,
        ls_q6: 0,
        alpha: 255,
    }
}

/// One glyph prepared for DMA2D: where its transposed bitmap starts in the
/// scratch, its line length and count, and its first destination pixel.
#[derive(Clone, Copy, Default)]
struct HwGlyph {
    src: usize,
    pl: u32,
    nl: u32,
    dst: usize,
}

/// Transpose every glyph of the runs into `scratch` (untimed: a driver's
/// atlas would be baked this way) and place them as `blit_run` would.
fn prepare(font: &Font<'_>, scratch: &mut [u8], out: &mut [HwGlyph; 32]) -> usize {
    let mut n = 0;
    let mut at = 0usize;
    for (line, text) in LINES.iter().enumerate() {
        let run = run_at(text, line);
        let Some(t) = font.tier(run.tier) else { continue };
        let mut x_q6 = run.x << 6;
        for &c in run.text {
            let Some(g) = t.glyph(c) else { continue };
            let gx = ((x_q6 + 32) >> 6) + i32::from(g.bearing_x);
            let gy = run.y - i32::from(g.bearing_top);
            x_q6 += i32::from(g.advance_q6);
            let (w, h) = (usize::from(g.w), usize::from(g.h));
            if w == 0 || h == 0 || n == out.len() {
                continue;
            }
            // An even line, padded ABOVE the glyph (y = gy - 1, alpha 0).
            let pl = (h + 1) & !1;
            let bytes = w * pl / 2;
            if gx < 0 || gx + w as i32 > BAND_COLS || gy - 1 < 0 || gy + h as i32 > H || at + bytes > scratch.len() {
                continue;
            }
            let stride = (w + 1) / 2;
            let blk = &mut scratch[at..at + bytes];
            blk.fill(0);
            for x in 0..w {
                for k in 0..h {
                    // Line pixel k is glyph row h-1-k: bottom row first.
                    let y = h - 1 - k;
                    let b = g.rows[y * stride + x / 2];
                    let a = if x % 2 == 0 { b >> 4 } else { b & 0x0F };
                    let p = x * pl + k;
                    blk[p / 2] |= if p % 2 == 0 { a } else { a << 4 };
                }
            }
            out[n] = HwGlyph {
                src: at,
                pl: pl as u32,
                nl: w as u32,
                dst: gx as usize * H as usize + (H - (gy + h as i32)) as usize,
            };
            at += bytes;
            n += 1;
        }
    }
    n
}

/// Draw the runs on the CPU, through the real `blit_run`.
fn cpu_text(font: &Font<'_>, buf: &mut [u16]) {
    let Some(mut s) = Strip::new(0, BAND_COLS, buf) else { return };
    for (line, text) in LINES.iter().enumerate() {
        font.blit_run(&run_at(text, line), TEXT_COLOR, &mut s);
    }
}

/// Run the bench. `cpu`, `hw` and `scratch` are three idle band buffers.
pub fn run(font: &Font<'_>, cpu: &mut [u16], hw: &mut [u16], scratch: &mut [u16]) -> Results {
    REG.rcc_ahb1enr.set_bits(RCC_AHB1ENR_DMA2DEN);
    let _ = REG.rcc_ahb1enr.read();
    cortex_m::asm::dsb();
    let mut err = 0u32;
    let (cpu, hw) = (&mut cpu[..BAND_PX], &mut hw[..BAND_PX]);
    // SAFETY: a `u16` band reinterpreted as its bytes: same allocation,
    // alignment 2 >= 1, length doubled, no other live reference to it.
    let scratch: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(scratch.as_mut_ptr().cast::<u8>(), scratch.len() * 2) };

    // 1. The band clear: `Strip::clear` (what `render_strip` runs first)
    //    against register-to-memory.
    cpu.fill(0x1234);
    let t = cycles();
    if let Some(mut s) = Strip::new(0, BAND_COLS, cpu) {
        s.clear();
    }
    let fill_cpu = cycles().wrapping_sub(t);
    let (cr0, i0, v0, fill_hw) = r2m_probe(hw, &mut err);

    // 2. A whole-band A4 blend over black: a glyph-like pattern, about half
    //    the pixels transparent, one DMA2D line per landscape column.
    let half = BAND_PX / 2;
    for (i, b) in scratch[..half].iter_mut().enumerate() {
        let lvl = |k: usize| -> u8 { if (k * 37 + k / 142 * 11) % 7 < 3 { 0 } else { ((k * 13 + 5) % 16) as u8 } };
        *b = lvl(2 * i) | (lvl(2 * i + 1) << 4);
    }
    cpu.fill(0);
    hw.fill(0);
    let t = cycles();
    cpu_blend_a4(&scratch[..half], cpu, H as usize, BAND_COLS as usize, TEXT_COLOR);
    let blend_cpu = cycles().wrapping_sub(t);
    let t = cycles();
    err |= hw_blend_a4(scratch.as_ptr(), hw.as_mut_ptr(), H as u32, BAND_COLS as u32, 0, TEXT_COLOR);
    let blend_hw = cycles().wrapping_sub(t);
    let pattern = compare(cpu, hw);

    // 3. Real glyph runs, over black and then over a colour.
    let mut glyphs = [HwGlyph::default(); 32];
    let n = prepare(font, scratch, &mut glyphs);
    let mut text = (0, 0);
    let mut exact = [(0, 0, 0); 3];
    for (pass, bg) in [0u16, 0x2945].into_iter().enumerate() {
        cpu.fill(bg);
        hw.fill(bg);
        let t = cycles();
        cpu_text(font, cpu);
        let c = cycles().wrapping_sub(t);
        let t = cycles();
        for g in &glyphs[..n] {
            // SAFETY: `prepare` kept every glyph inside the band and its
            // bitmap inside the scratch.
            let (src, dst) = unsafe { (scratch.as_ptr().add(g.src), hw.as_mut_ptr().add(g.dst)) };
            err |= hw_blend_a4(src, dst, g.pl, g.nl, H as u32 - g.pl, TEXT_COLOR);
        }
        let h = cycles().wrapping_sub(t);
        if pass == 0 {
            text = (c, h);
        }
        exact[pass] = compare(cpu, hw);
    }
    exact[2] = pattern;
    // The clear again, now that DMA2D has run blends.
    let (cr1, i1, v1, _) = r2m_probe(hw, &mut err);
    let glyphs_all = LINES.iter().flat_map(|l| l.iter()).filter(|&&c| c != b' ').count() as u32;
    REG.rcc_ahb1enr.clear_bits(RCC_AHB1ENR_DMA2DEN);
    Results {
        fill: (fill_cpu, fill_hw),
        blend: (blend_cpu, blend_hw),
        text,
        glyphs: n as u32,
        exact,
        err,
        glyphs_all,
        r2m: [(cr0, i0, v0), (cr1, i1, v1)],
    }
}

fn push(row: &mut [u8; DISPLAY_COLS], n: &mut usize, s: &[u8]) {
    for &b in s {
        if *n < DISPLAY_COLS {
            row[*n] = b;
            *n += 1;
        }
    }
}

fn push_hex(row: &mut [u8; DISPLAY_COLS], n: &mut usize, v: u32, digits: u32) {
    for k in (0..digits).rev() {
        let d = ((v >> (4 * k)) & 0xF) as u8;
        push(row, n, &[if d < 10 { b'0' + d } else { b'A' + d - 10 }]);
    }
}

fn push_u32(row: &mut [u8; DISPLAY_COLS], n: &mut usize, v: u32) {
    let mut d = [0u8; 10];
    let mut k = 0;
    let mut x = v;
    loop {
        d[k] = b'0' + (x % 10) as u8;
        k += 1;
        x /= 10;
        if x == 0 {
            break;
        }
    }
    while k > 0 {
        k -= 1;
        push(row, n, &d[k..=k]);
    }
}

impl Results {
    /// `DMA2D us cpu hw`, then the clear, the band blend and the glyph runs
    /// (with their glyph count), in microseconds.
    pub fn rows_speed(&self, out: &mut [[u8; DISPLAY_COLS]; DISPLAY_ROWS]) {
        for row in out.iter_mut() {
            *row = [b' '; DISPLAY_COLS];
        }
        let mut n = 0;
        push(&mut out[0], &mut n, b"DMA2D us cpu hw");
        let us = |c: u32| c / 160;
        let rows: [(&[u8], (u32, u32)); 3] = [(b"fill ", self.fill), (b"blnd ", self.blend), (b"text ", self.text)];
        for (row, (name, (c, h))) in out[1..].iter_mut().zip(rows) {
            let mut n = 0;
            push(row, &mut n, name);
            push_u32(row, &mut n, us(c));
            push(row, &mut n, b" ");
            push_u32(row, &mut n, us(h));
        }
        let mut n = 12;
        push(&mut out[3], &mut n, b"g");
        push_u32(&mut out[3], &mut n, self.glyphs);
        push(&mut out[3], &mut n, b"/");
        push_u32(&mut out[3], &mut n, self.glyphs_all);
    }

    /// `R2M m i v`, then per fill (first after the clock enable, then after
    /// the blends) `CR[23:16]` (the mode, hex), the first non-zero pixel
    /// (`-`: none) and its value (hex): 1234 means untouched.
    pub fn rows_r2m(&self, out: &mut [[u8; DISPLAY_COLS]; DISPLAY_ROWS]) {
        for row in out.iter_mut() {
            *row = [b' '; DISPLAY_COLS];
        }
        let mut n = 0;
        push(&mut out[0], &mut n, b"R2M m i v");
        for (k, (row, &(cr, i, v))) in out[1..].iter_mut().zip(self.r2m.iter()).enumerate() {
            let mut n = 0;
            push_u32(row, &mut n, k as u32 + 1);
            push(row, &mut n, b" ");
            push_hex(row, &mut n, cr >> 16, 2);
            push(row, &mut n, b" ");
            if i == u32::MAX {
                push(row, &mut n, b"-");
            } else {
                push_u32(row, &mut n, i);
                push(row, &mut n, b" ");
                push_hex(row, &mut n, u32::from(v), 4);
            }
        }
    }

    /// `D2D ex e<err, hex>`, then per comparison `<diff>/<px> d<max>`: glyphs
    /// over black, over a colour, the band pattern.
    pub fn rows_exact(&self, out: &mut [[u8; DISPLAY_COLS]; DISPLAY_ROWS]) {
        for row in out.iter_mut() {
            *row = [b' '; DISPLAY_COLS];
        }
        let mut n = 0;
        push(&mut out[0], &mut n, b"D2D ex e");
        push_hex(&mut out[0], &mut n, self.err, 8);
        let names: [&[u8]; 3] = [b"blk ", b"col ", b"pat "];
        for (row, (name, (diff, px, max))) in out[1..].iter_mut().zip(names.iter().zip(self.exact)) {
            let mut n = 0;
            push(row, &mut n, name);
            push_u32(row, &mut n, diff);
            push(row, &mut n, b"/");
            push_u32(row, &mut n, px);
            push(row, &mut n, b" d");
            push_u32(row, &mut n, u32::from(max));
        }
    }
}

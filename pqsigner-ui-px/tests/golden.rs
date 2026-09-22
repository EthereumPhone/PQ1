//! Host golden renders of the pixel engine with the real baked atlas and
//! marks: full 428×142 frames rendered strip by strip exactly as the
//! firmware does, hashed, and (with `UI_PX_PNG=1`) written as PNGs under
//! `target/ui-px-golden/` for eyeballing against the PQ-UI reference renders.
//!
//! The renderer is integer-only, so these hashes are the bytes the panel
//! receives on the device. Re-bless after an intentional visual change.

use pqsigner_ui_px::driver::Btn;
use pqsigner_ui_px::font::Font;
use pqsigner_ui_px::raster::{render_strip, Frame, Rgb, Strip, H, W};
use pqsigner_ui_px::scene::{parse_mark, Anim, Ending, Marks};
use pqsigner_ui_px::{Icon, Screen, ScreenBuilder, Side, Tier, Weight};
use sha2::{Digest, Sha256};
use std::io::Write;

const FONTS: &[u8] = include_bytes!("../../secure/assets/ui-px/fonts.bin");
const SAFE: &[u8] = include_bytes!("../../secure/assets/ui-px/safe.a4");
const MAINNET: &[u8] = include_bytes!("../../secure/assets/ui-px/mainnet.a4");

fn marks() -> Marks<'static> {
    Marks {
        safe: parse_mark(SAFE),
        mainnet: parse_mark(MAINNET),
        base: None,
        fingerprint: None,
    }
}

/// Render a frame in 16-row strips into a full RGB565 image (like the device).
fn render_full(anim: &Anim) -> Vec<u16> {
    let font = Font::parse(FONTS).expect("atlas");
    let mut frame = Frame::new();
    anim.build(&marks(), &font, &mut frame);
    let mut out = vec![0u16; (W * H) as usize];
    let mut strip_buf = vec![0u16; (W * 16) as usize];
    let mut y0 = 0;
    while y0 < H {
        let h = 16.min(H - y0);
        let mut s = Strip::new(y0, h, &mut strip_buf).unwrap();
        render_strip(&frame, &font, &mut s);
        out[(y0 * W) as usize..((y0 + h) * W) as usize].copy_from_slice(&s.buf[..(W * h) as usize]);
        y0 += h;
    }
    out
}

fn sha(px: &[u16]) -> String {
    let mut h = Sha256::new();
    for p in px {
        h.update(p.to_be_bytes());
    }
    hex::encode(h.finalize())
}

// ---- minimal PNG writer (stored deflate) ----------------------------------
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

fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    let mut c = Vec::with_capacity(4 + data.len());
    c.extend_from_slice(kind);
    c.extend_from_slice(data);
    out.extend_from_slice(&c);
    out.extend_from_slice(&crc32(&c).to_be_bytes());
}

fn write_png(path: &str, px: &[u16]) {
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
    chunk(&mut out, b"IHDR", &ihdr);
    chunk(&mut out, b"IDAT", &z);
    chunk(&mut out, b"IEND", &[]);
    std::fs::create_dir_all("../target/ui-px-golden").ok();
    let mut f = std::fs::File::create(format!("../target/ui-px-golden/{path}")).expect("png file");
    f.write_all(&out).unwrap();
}

fn check(name: &str, px: &[u16], expected: &str) {
    if std::env::var_os("UI_PX_PNG").is_some() {
        write_png(&format!("{name}.png"), px);
    }
    let got = sha(px);
    assert_eq!(got, expected, "{name}: frame golden changed — review target/ui-px-golden/{name}.png (UI_PX_PNG=1) and re-bless");
}

fn hero() -> Screen {
    ScreenBuilder::hero(b"APPROVE", Icon::Safe, b"APPROVE SAFE TX?").finish().unwrap()
}

fn detail_addr() -> Screen {
    ScreenBuilder::detail(b"SAFEACCT", Icon::Safe, Side::Left, b"SAFE ACCT")
        .tier(Tier::T22)
        .line(b"0x5aFE0000000000000000", Weight::Regular)
        .line(b"00000000000000000001", Weight::Regular)
        .finish()
        .unwrap()
}

#[test]
fn hero_at_rest() {
    let a = Anim::new(&hero(), 0, 0);
    let px = render_full(&a);
    // Something is drawn in the disc, the caption band and the chevron corners.
    assert_ne!(px[(72 * W + 214) as usize], 0, "disc centre");
    assert!((0..W).any(|x| px[(125 * W + x) as usize] != 0), "caption");
    assert!((10..30).any(|y| (14..34).any(|x| px[(y * W + x) as usize] != 0)), "left chevron");
    check("hero_rest", &px, GOLDEN_HERO_REST);
}

#[test]
fn detail_settled() {
    let mut a = Anim::new(&hero(), 0, 0);
    a.go_to(&detail_addr(), 0, 0);
    let mut t = 16;
    while a.step(t) && t < 4000 {
        t += 16;
    }
    let px = render_full(&a);
    assert_ne!(px[(72 * W + 74) as usize], 0, "disc docked left");
    check("detail_settled", &px, GOLDEN_DETAIL_SETTLED);
}

#[test]
fn mid_transition_and_hold() {
    let mut a = Anim::new(&hero(), 0, 0);
    a.go_to(&detail_addr(), 0, 0);
    for t in (16..=160).step_by(16) {
        a.step(t);
    }
    let px = render_full(&a);
    check("transition_160ms", &px, GOLDEN_TRANSITION);

    let mut h = Anim::new(&hero(), 0, 0);
    h.step(16);
    h.hold(Btn::Right, 1200, 16);
    h.step(32);
    let px = render_full(&h);
    check("hero_hold_half", &px, GOLDEN_HOLD);
}

#[test]
fn confirm_and_legacy_and_ending() {
    let c = ScreenBuilder::confirm(Icon::Safe).finish().unwrap();
    let a = Anim::new(&c, 0, 0);
    let px = render_full(&a);
    check("confirm", &px, GOLDEN_CONFIRM);

    let page: pqsigner_erc7730::display::Page = [*b"Fees: max / tip ", *b"10 gwei         ", *b"2 gwei          ", *b"> next      9/15"];
    let l = Anim::new(&Screen::legacy(&page), 0, 0);
    let px = render_full(&l);
    check("legacy_page", &px, GOLDEN_LEGACY);

    let mut e = Anim::new(&hero(), 0, 0);
    e.ending(Ending::Signed, 0);
    for t in (16..=1300).step_by(16) {
        e.step(t);
    }
    let px = render_full(&e);
    check("ending_signed", &px, GOLDEN_ENDING);
}

const GOLDEN_HERO_REST: &str = "5f500074a2b03fa16185ee065f8daa6a194f1e9b43f5f0a38f7c45fe77efb842";
const GOLDEN_DETAIL_SETTLED: &str = "c8dd2591cd71da03fd6999993314cdc0b9616ea707a4033b58cb39e9d3332d80";
const GOLDEN_TRANSITION: &str = "13faf48dbc034cba4d66f4c5c0a3b7378bcc3a68e5a03d40a917e93e7cb7d98a";
const GOLDEN_HOLD: &str = "c106d99f364d818fa0794713dc92cbe5d58810896fe608fdfcd96bce31f21db2";
const GOLDEN_CONFIRM: &str = "bcec64bf35da2468dbbf5ab543083a3ece0ad548f16c81fc5dfc1e7e9e87bfd7";
const GOLDEN_LEGACY: &str = "8329677829040e41857dc59f8d0480fa1f2653fca0783746238ead85aec2850f";
const GOLDEN_ENDING: &str = "357ca89d17cf2be77750b5f09d26a3702a4e9afcef6c292e9b6a778e5168799d";

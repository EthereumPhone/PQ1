//! Host micro-benchmark of the strip renderer: how much CPU a frame costs in
//! the poses the device actually draws (idle hero, mid-transition with the
//! trail spread, hold flood, ending). Relative numbers only — the M33 at
//! 160 MHz is far slower — but it exposes hot spots before a flash cycle.
//! `cargo run --release -p pqsigner-ui-px --example frame_bench`
use pqsigner_ui_px::driver::Btn;
use pqsigner_ui_px::font::Font;
use pqsigner_ui_px::raster::{render_strip, Frame, Strip, H, W};
use pqsigner_ui_px::scene::{parse_mark, Anim, Ending, Marks};
use pqsigner_ui_px::{Icon, Screen, ScreenBuilder, Side, Tier, Weight};
use std::time::Instant;

const FONTS: &[u8] = include_bytes!("../../secure/assets/ui-px/fonts.bin");
const SAFE: &[u8] = include_bytes!("../../secure/assets/ui-px/safe.a4");
const MAINNET: &[u8] = include_bytes!("../../secure/assets/ui-px/mainnet.a4");

fn marks() -> Marks<'static> {
    Marks { safe: parse_mark(SAFE), mainnet: parse_mark(MAINNET), ..Marks::default() }
}

fn render_full(anim: &Anim, font: &Font<'_>, strip_buf: &mut [u16]) -> u64 {
    let mut frame = Frame::new();
    anim.build(&marks(), font, &mut frame);
    let mut acc = 0u64;
    let mut y0 = 0;
    while y0 < H {
        let h = 16.min(H - y0);
        let mut s = Strip::new(y0, h, strip_buf).unwrap();
        render_strip(&frame, font, &mut s);
        acc = acc.wrapping_add(u64::from(s.buf[0])).wrapping_add(u64::from(s.buf[(W * h - 1) as usize]));
        y0 += h;
    }
    acc
}

fn hero() -> Screen {
    ScreenBuilder::hero(b"hero", Icon::Safe, b"APPROVE SAFE TX?").finish().unwrap()
}
fn detail() -> Screen {
    ScreenBuilder::detail(b"acct", Icon::Safe, Side::Left, b"SAFE ACCT")
        .tier(Tier::T22)
        .line(b"0x5aFe000000000000000", Weight::Regular)
        .line(b"000000000000000000001", Weight::Regular)
        .finish()
        .unwrap()
}

fn bench(name: &str, anim: &Anim, font: &Font<'_>, buf: &mut [u16]) {
    let n = 200;
    let mut acc = 0u64;
    let t = Instant::now();
    for _ in 0..n {
        acc = acc.wrapping_add(render_full(anim, font, buf));
    }
    let us = t.elapsed().as_micros() as f64 / n as f64;
    println!("{name:<28} {us:8.1} us/frame (host)   [{acc:x}]");
}

fn main() {
    let font = Font::parse(FONTS).expect("atlas");
    let mut buf = vec![0u16; (W * 16) as usize];
    let h = hero();
    let d = detail();

    let a = Anim::new(&h, 0, 1000);
    bench("hero idle (t=0)", &a, &font, &mut buf);

    let mut a = Anim::new(&h, 0, 1000);
    a.step(2600);
    bench("hero sweeping (t=1.6s)", &a, &font, &mut buf);

    let mut a = Anim::new(&h, 0, 1000);
    a.step(1000);
    a.go_to(&d, 0, 1000);
    a.step(1060);
    bench("transition +60ms (trail)", &a, &font, &mut buf);

    let mut a = Anim::new(&h, 0, 1000);
    a.step(1000);
    a.go_to(&d, 0, 1000);
    a.step(1200);
    bench("transition +200ms (fade)", &a, &font, &mut buf);

    let mut a = Anim::new(&d, 0, 1000);
    a.step(1000);
    bench("detail settled", &a, &font, &mut buf);

    let mut a = Anim::new(&h, 0, 1000);
    a.hold(Btn::Right, 1200, 2200);
    a.step(2200);
    bench("hero hold flood", &a, &font, &mut buf);

    let mut a = Anim::new(&h, 0, 1000);
    a.ending(Ending::Signed, 1000);
    a.step(1600);
    bench("ending +600ms", &a, &font, &mut buf);
}

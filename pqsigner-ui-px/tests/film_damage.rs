//! The busy film's partial redraw (#934, scoped 2026-10-16) is only sound if
//! every pixel outside the damage columns is unchanged. Renders the
//! provisioning film's full frames across its timeline at device-like
//! intervals, computes the damage from the item fingerprints exactly as the
//! device does, and checks every column outside it pixel for pixel.

use pqsigner_ui_px::damage::{Damage, FrameSigs};
use pqsigner_ui_px::font::Font;
use pqsigner_ui_px::raster::{Frame, H, W};
use pqsigner_ui_px::scene::{parse_mark, Anim, Marks};
use pqsigner_ui_px::{Icon, ResultMark, ScreenBuilder, State};

const FONTS: &[u8] = include_bytes!("../../secure/assets/ui-px/fonts.bin");
const SAFE: &[u8] = include_bytes!("../../secure/assets/ui-px/safe.a4");
const MAINNET: &[u8] = include_bytes!("../../secure/assets/ui-px/mainnet.a4");
const BASE: &[u8] = include_bytes!("../../secure/assets/ui-px/base.a4");
const ETH: &[u8] = include_bytes!("../../secure/assets/ui-px/eth.a4");
const BLIND: &[u8] = include_bytes!("../../secure/assets/ui-px/blind.a4");
const ROTATE: &[u8] = include_bytes!("../../secure/assets/ui-px/rotate.a4");
const USDC: &[u8] = include_bytes!("../../secure/assets/ui-px/usdc.a4");
const USDT: &[u8] = include_bytes!("../../secure/assets/ui-px/usdt.a4");
const DAI: &[u8] = include_bytes!("../../secure/assets/ui-px/dai.a4");
const COWSWAP: &[u8] = include_bytes!("../../secure/assets/ui-px/cowswap.a4");
const FPRINT: &[u8] = include_bytes!("../../secure/assets/ui-px/fprint.a4");

fn marks() -> Marks<'static> {
    Marks {
        safe: parse_mark(SAFE),
        mainnet: parse_mark(MAINNET),
        base: parse_mark(BASE),
        fingerprint: parse_mark(FPRINT),
        eth: parse_mark(ETH),
        usdc: parse_mark(USDC),
        usdt: parse_mark(USDT),
        dai: parse_mark(DAI),
        blind: parse_mark(BLIND),
        rotate: parse_mark(ROTATE),
        cowswap: parse_mark(COWSWAP),
    }
}

fn sigs(a: &Anim, marks: &Marks<'_>, font: &Font<'_>) -> FrameSigs {
    let mut f = Frame::new();
    a.build(marks, font, &mut f);
    FrameSigs::of(&f, font)
}

/// The film screens a film starts on: setup's (the dots disc) and the
/// signing film's default (the Safe disc).
fn film_screens() -> Vec<(&'static str, pqsigner_ui_px::Screen)> {
    vec![
        (
            "setup",
            ScreenBuilder::status(b"SETUP", Icon::Dots, b"SETTING UP YOUR PQ1", State::Awaiting, ResultMark::None)
                .finish()
                .unwrap(),
        ),
        (
            "signing",
            ScreenBuilder::status(b"SIGN", Icon::Safe, b"", State::Awaiting, ResultMark::None)
                .line(b"SIGNED SAFE TX", pqsigner_ui_px::Weight::Regular)
                .line(b"SAFE TX DECLINED", pqsigner_ui_px::Weight::Regular)
                .line(b"SAFE TX FAILED", pqsigner_ui_px::Weight::Regular)
                .finish()
                .unwrap(),
        ),
    ]
}

#[test]
fn every_pixel_outside_the_damage_is_unchanged() {
    let font = Font::parse(FONTS).expect("atlas");
    let marks = marks();
    for (name, screen) in film_screens() {
        for step_ms in [16u32, 23, 40, 52, 97] {
            let mut a = Anim::new(&screen, 0, 0);
            a.film_start(0);
            let mut prev_px = pqsigner_ui_px::png::render_full(&a, &marks, &font);
            let mut prev = sigs(&a, &marks, &font);
            let (mut partial, mut nothing, mut all, mut cols_total) = (0u32, 0u32, 0u32, 0i64);
            let mut t = step_ms;
            while t <= 20_000 {
                a.step(t);
                let cur = sigs(&a, &marks, &font);
                let px = pqsigner_ui_px::png::render_full(&a, &marks, &font);
                match cur.damage(&prev) {
                    Damage::All => all += 1,
                    Damage::Nothing => {
                        nothing += 1;
                        assert_eq!(px, prev_px, "{name} step {step_ms} t {t}: Nothing, but the frame changed");
                    }
                    Damage::Cols(x0, x1) => {
                        partial += 1;
                        cols_total += i64::from(x1 - x0 + 1);
                        for y in 0..H {
                            for x in (0..x0).chain(x1 + 1..W) {
                                let i = (y * W + x) as usize;
                                assert_eq!(
                                    px[i], prev_px[i],
                                    "{name} step {step_ms} t {t}: pixel ({x},{y}) changed outside the damage {x0}..={x1}"
                                );
                            }
                        }
                    }
                }
                prev_px = px;
                prev = cur;
                t += step_ms;
            }
            let avg = if partial > 0 { cols_total / i64::from(partial) } else { 0 };
            println!("{name} step {step_ms}: partial {partial} (avg {avg} cols), nothing {nothing}, all {all}");
            assert!(partial > all, "{name}: the film should mostly redraw partially");
        }
    }
}

/// The comparison is not vacuous: a frame whose items moved reports their
/// columns, and an unbounded kind forces a full repaint.
#[test]
fn damage_reports_moved_items_and_refuses_unbounded_kinds() {
    use pqsigner_ui_px::raster::{Item, Rgb};
    let font = Font::parse(FONTS).expect("atlas");
    let mut a = Frame::new();
    a.push(Item::Disc { cx: 100 << 8, cy: 70 << 8, r: 10 << 8, color: Rgb::WHITE });
    let mut b = Frame::new();
    b.push(Item::Disc { cx: 200 << 8, cy: 70 << 8, r: 10 << 8, color: Rgb::WHITE });
    let d = FrameSigs::of(&b, &font).damage(&FrameSigs::of(&a, &font));
    let Damage::Cols(x0, x1) = d else { panic!("{d:?}") };
    assert!(x0 <= 90 && x1 >= 210, "both the old and the new position: {x0}..={x1}");
    assert_eq!(FrameSigs::of(&a, &font).damage(&FrameSigs::of(&a, &font)), Damage::Nothing);
    assert_eq!(FrameSigs::of(&a, &font).damage(&FrameSigs::UNKNOWN), Damage::All);
    let mut c = Frame::new();
    c.push(Item::Check { cx: 100 << 8, cy: 70 << 8, r: 10 << 8, color: Rgb::WHITE, k: 0 });
    assert_eq!(FrameSigs::of(&c, &font).damage(&FrameSigs::of(&c, &font)), Damage::All);
}

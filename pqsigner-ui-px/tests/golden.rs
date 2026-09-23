//! Host golden renders of the pixel engine with the real baked atlas and
//! marks: full 428×142 frames rendered strip by strip exactly as the
//! firmware does, hashed, and (with `UI_PX_PNG=1`) written as PNGs under
//! `target/ui-px-golden/` for eyeballing against the PQ-UI reference renders.
//!
//! The renderer is integer-only, so these hashes are the bytes the panel
//! receives on the device. Re-bless after an intentional visual change.

use pqsigner_ui_px::driver::Btn;
use pqsigner_ui_px::font::Font;
use pqsigner_ui_px::raster::W;
use pqsigner_ui_px::scene::{parse_mark, Anim, Ending, Marks};
use pqsigner_ui_px::{Icon, Screen, ScreenBuilder, Side, Tier, Weight};
use sha2::{Digest, Sha256};

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

fn marks() -> Marks<'static> {
    Marks {
        safe: parse_mark(SAFE),
        mainnet: parse_mark(MAINNET),
        // The device draws Base's own mark on a Base NETWORK screen.
        base: parse_mark(BASE),
        fingerprint: None,
        eth: parse_mark(ETH),
        usdc: parse_mark(USDC),
        usdt: parse_mark(USDT),
        dai: parse_mark(DAI),
        blind: parse_mark(BLIND),
        rotate: parse_mark(ROTATE),
        cowswap: parse_mark(COWSWAP),
    }
}

/// Render a frame in 16-row strips into a full RGB565 image (like the device).
fn render_full(anim: &Anim) -> Vec<u16> {
    let font = Font::parse(FONTS).expect("atlas");
    pqsigner_ui_px::png::render_full(anim, &marks(), &font)
}

fn sha(px: &[u16]) -> String {
    let mut h = Sha256::new();
    for p in px {
        h.update(p.to_be_bytes());
    }
    hex::encode(h.finalize())
}

fn write_png(path: &str, px: &[u16]) {
    pqsigner_ui_px::png::write_png(std::path::Path::new(&format!("../target/ui-px-golden/{path}")), px).expect("png file");
}

fn check(name: &str, px: &[u16], expected: &str) {
    if std::env::var_os("UI_PX_PNG").is_some() {
        write_png(&format!("{name}.png"), px);
    }
    let got = sha(px);
    // An empty expectation is a golden being blessed: print it, do not fail.
    if expected.is_empty() {
        eprintln!("BLESS {name} = \"{got}\"");
        return;
    }
    assert_eq!(got, expected, "{name}: frame golden changed — review target/ui-px-golden/{name}.png (UI_PX_PNG=1) and re-bless");
}

/// Every fixture passes the design-rule checker before it is rendered.
fn checked(s: Screen) -> Screen {
    assert_eq!(pqsigner_ui_px::check::check_screens(&[s]), Ok(()));
    s
}

fn hero() -> Screen {
    checked(ScreenBuilder::hero(b"APPROVE", Icon::Safe, b"APPROVE SAFE TX?").finish().unwrap())
}

fn detail_addr() -> Screen {
    checked(
        ScreenBuilder::detail(b"SAFEACCT", Icon::Safe, Side::Left, b"SAFE ACCT")
            .tier(Tier::T22)
            // The design's 2 × 21 address split (`fit::split_address`).
            .line(b"0x5aFE000000000000000", Weight::Regular)
            .line(b"000000000000000000001", Weight::Regular)
            .finish()
            .unwrap(),
    )
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
const GOLDEN_DETAIL_SETTLED: &str = "2d225ec2e04e26a53e67abc7fec2807678a5562aae334cab8862523a8ba935a4";
const GOLDEN_TRANSITION: &str = "6419a6a0877ca9bb1bcf48db01d8cbb75a00b98fe733ff3e43494479557cb43e";
const GOLDEN_HOLD: &str = "c106d99f364d818fa0794713dc92cbe5d58810896fe608fdfcd96bce31f21db2";
const GOLDEN_CONFIRM: &str = "bcec64bf35da2468dbbf5ab543083a3ece0ad548f16c81fc5dfc1e7e9e87bfd7";
const GOLDEN_LEGACY: &str = "8329677829040e41857dc59f8d0480fa1f2653fca0783746238ead85aec2850f";
const GOLDEN_ENDING: &str = "9dd674e78b15221c8a5effedd5a5121c0fba5183741bdacf90a58cabc647da33";

/// The signing film at its beats (pq1/loading.py timeline): seed, split,
/// orbit (the loop), spiral, flash, the landed check, and the end of the
/// result hold. The film is started on the hero at t 0 and answered at
/// 3000 ms (inside the loop, so the stock timeline plays with no wraps).
#[test]
fn signing_film_frames() {
    let mut a = Anim::new(&hero(), 0, 0);
    a.film_start(0);
    assert!(a.film_live());
    let beats: [(&str, u32, &str); 7] = [
        ("film_seed_200", 200, GOLDEN_FILM_SEED),
        ("film_split_1000", 1000, GOLDEN_FILM_SPLIT),
        ("film_orbit_3000", 3000, GOLDEN_FILM_ORBIT),
        ("film_spiral_5000", 5000, GOLDEN_FILM_SPIRAL),
        ("film_flash_6000", 6000, GOLDEN_FILM_FLASH),
        ("film_check_6400", 6400, GOLDEN_FILM_CHECK),
        ("film_hold_end_8650", 8650, GOLDEN_FILM_HOLD_END),
    ];
    let mut t = 16;
    for (name, at, expected) in beats {
        while t < at {
            a.step(t);
            t += 16;
        }
        if at == 3000 {
            a.film_resolve(Ending::Signed, at);
        }
        a.step(at);
        t = at + 16;
        let px = render_full(&a);
        assert!((0..W).any(|x| px[(72 * W + x) as usize] != 0), "{name}: nothing drawn on the film's centre row");
        check(name, &px, expected);
        assert_eq!(a.film_done(at), at >= 8650, "{name}");
    }
}

const GOLDEN_FILM_SEED: &str = "33706780ad7bcce4de1763d5032a34a3340517055544914a23119caf16d98049";
const GOLDEN_FILM_SPLIT: &str = "4be77777e056380c6be53c6e5bbd0314fc0507efdeb46dbfa31da3942c757546";
const GOLDEN_FILM_ORBIT: &str = "4394b9eecf185d2520aeba0563489e9f3ed728fe7e4c50f07f52b46995935339";
const GOLDEN_FILM_SPIRAL: &str = "296ff6e3bd0ac87c1c4630d7658022709f2bb46dfe1ec18607c5eb69562c1623";
const GOLDEN_FILM_FLASH: &str = "e4574e263ed8452307cc7ac9871161e81d71ae5c42ed20d87efda605d75db810";
const GOLDEN_FILM_CHECK: &str = "1fc1479648e0fb9bd2fbb31423f6de392115c8c67af4e5bdfd2a0cc6894ab39c";
const GOLDEN_FILM_HOLD_END: &str = "9dd674e78b15221c8a5effedd5a5121c0fba5183741bdacf90a58cabc647da33";

/// The per-family transcript fixtures (`tests/fixtures/<family>/<name>.hex`,
/// one 512-hex record per line, exported by the secure host tests with
/// `UI_PX_EXPORT=1`): render the settled frame of every (screen, page) and
/// compare the hash list with `<name>.sha`. `UI_PX_BLESS=1` rewrites the
/// `.sha` files (`make ui-px-goldens-bless`); `UI_PX_PNG=1` writes the
/// frames under `target/ui-px-golden/<family>/<name>/`. (Named `safe_flows`
/// for the bless target's filter; it walks every family directory.)
#[test]
fn safe_flows() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut fixtures: Vec<(String, std::path::PathBuf)> = Vec::new();
    for fam in std::fs::read_dir(&root).expect("tests/fixtures exists").filter_map(Result::ok) {
        if !fam.path().is_dir() {
            continue;
        }
        let family = fam.file_name().to_string_lossy().into_owned();
        for e in std::fs::read_dir(fam.path()).unwrap().filter_map(Result::ok) {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "hex") {
                fixtures.push((family.clone(), p));
            }
        }
    }
    fixtures.sort();
    assert!(fixtures.iter().any(|(f, _)| f == "safe"), "no Safe transcript fixtures");
    let bless = std::env::var_os("UI_PX_BLESS").is_some();
    let font = Font::parse(FONTS).expect("atlas");
    let mut mismatches = Vec::new();
    for (family, path) in fixtures {
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(&path).unwrap();
        let mut hashes = Vec::new();
        for (i, line) in text.lines().enumerate() {
            let screen = pqsigner_ui_px::png::screen_from_hex(line).unwrap_or_else(|| panic!("{family}/{name}: record {i} malformed"));
            assert_eq!(pqsigner_ui_px::check::check_screens(&[screen]), Ok(()), "{family}/{name}: record {i}");
            for page in 0..screen.npages().max(1) {
                let mut a = Anim::new(&screen, page, 0);
                let mut t = 16;
                while a.step(t) && t < 4000 {
                    t += 16;
                }
                let px = pqsigner_ui_px::png::render_full(&a, &marks(), &font);
                if std::env::var_os("UI_PX_PNG").is_some() {
                    write_png(&format!("{family}/{name}/{i:02}-p{page}.png"), &px);
                }
                hashes.push(format!("{i:02} p{page} {}", sha(&px)));
            }
        }
        let got = hashes.join("\n") + "\n";
        let sha_path = path.with_extension("sha");
        if bless {
            std::fs::write(&sha_path, &got).unwrap();
            continue;
        }
        let want = std::fs::read_to_string(&sha_path).unwrap_or_default();
        if want != got {
            mismatches.push(format!("{family}/{name}"));
        }
    }
    assert!(mismatches.is_empty(), "frame goldens changed for {mismatches:?} — review target/ui-px-golden/<family>/ (UI_PX_PNG=1) and `make ui-px-goldens-bless`");
}

/// Every step-2 family disc at rest on its hero (the idle sweep settled at
/// t 0), one tinted placeholder disc, and the unbranded endings: the film on
/// a family status screen lands on a black disc with the state-colour ring
/// and mark, captioned from the screen's lines.
#[test]
fn family_discs_and_unbranded_endings() {
    let cases: [(&str, Icon, Option<u8>, &str); 8] = [
        ("disc_eth", Icon::Eth, None, GOLDEN_DISC_ETH),
        ("disc_usdc", Icon::Usdc, None, GOLDEN_DISC_USDC),
        ("disc_usdt", Icon::Usdt, None, GOLDEN_DISC_USDT),
        ("disc_dai", Icon::Dai, None, GOLDEN_DISC_DAI),
        ("disc_blind", Icon::Blind, None, GOLDEN_DISC_BLIND),
        ("disc_rotate", Icon::Rotate, None, GOLDEN_DISC_ROTATE),
        ("disc_cowswap", Icon::Cowswap, None, GOLDEN_DISC_COWSWAP),
        ("disc_eth_tint1", Icon::Eth, Some(1), GOLDEN_DISC_ETH_TINT1),
    ];
    for (name, icon, tint, expected) in cases {
        let mut b = ScreenBuilder::hero(b"ASK", icon, b"SEND 1 ETH?");
        if let Some(t) = tint {
            b = b.tint(t);
        }
        let s = checked(b.finish().unwrap());
        let a = Anim::new(&s, 0, 0);
        let px = render_full(&a);
        assert!((50..95).any(|y| (190..238).any(|x| px[(y * W + x) as usize] != 0)), "{name}: nothing in the disc");
        check(name, &px, expected);
    }
    for (name, ending, expected) in [
        ("ending_eth_signed", Ending::Signed, GOLDEN_ENDING_ETH_SIGNED),
        ("ending_eth_declined", Ending::Declined, GOLDEN_ENDING_ETH_DECLINED),
    ] {
        let film = ScreenBuilder::status(b"SIGN", Icon::Eth, b"", pqsigner_ui_px::State::Awaiting, pqsigner_ui_px::ResultMark::None)
            .line(b"TRANSACTION CONFIRMED", Weight::Regular)
            .line(b"TRANSACTION DECLINED", Weight::Regular)
            .finish()
            .unwrap();
        let mut e = Anim::new(&film, 0, 0);
        e.ending(ending, 0);
        for t in (16..=1300).step_by(16) {
            e.step(t);
        }
        let px = render_full(&e);
        check(name, &px, expected);
    }
}

const GOLDEN_DISC_ETH: &str = "cc80a3dc0b11d9c6f060876204baff547a335f1aa8ddce439ea106c4a806aaf6";
const GOLDEN_DISC_USDC: &str = "c89b71775c022d5ee3b91b078230bfa953e4c1d47adc024cc7de515e52318394";
const GOLDEN_DISC_USDT: &str = "2358fd40973c9f4a3680c9bd0dba506bbade5269ef5cc7035917b9f4cb2869b9";
const GOLDEN_DISC_DAI: &str = "0fba635333447ec0fc17a2855b79c872b8d1710a7a5abb578369b2882b77c618";
const GOLDEN_DISC_BLIND: &str = "36930052ebbd2027d35b3ac5b218b061f3cde9b1c9ee6b0db2d91aa4ecdab360";
const GOLDEN_DISC_ROTATE: &str = "cf46606c59634c6303b2e9419fa2230f35b8a20e51042259715a5ffca1a32376";
const GOLDEN_DISC_COWSWAP: &str = "eb145205606daddc8e5b2137571903e7a6f124a7cb459e326eab8f9e2954752f";
const GOLDEN_DISC_ETH_TINT1: &str = "ca430a1c37d82982f0a15894ac91d5b17a2c39df01b6113782b6488b51b3bfa7";
const GOLDEN_ENDING_ETH_SIGNED: &str = "5ad70f3d3d27ed7838565a182f3920f90fb095ac01ef81f9e27e06c86b065ec2";
const GOLDEN_ENDING_ETH_DECLINED: &str = "803a91483480bf4f9f19f2cf0193c1f7bf31bef9b951d2f8f537ba7489779b34";

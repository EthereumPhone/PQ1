//! Render the port-step-4 screens (verdicts, entry rows, words grids) at a
//! few moments each, for eyeballing: `lifecycle_sheet <out_dir>`.
use pqsigner_ui_px::font::Font;
use pqsigner_ui_px::png::{render_full, write_png};
use pqsigner_ui_px::pq1a::{self, Atlas};
use pqsigner_ui_px::scene::Anim;
use pqsigner_ui_px::{Icon, ResultMark, Screen, ScreenBuilder, Side, State, Tier, Weight};
use std::path::Path;

const ATLAS: &[u8] = include_bytes!("../../nonsecure/assets/ui-px/atlas.pq1a");

fn main() {
    let out = std::env::args().nth(1).expect("out dir");
    let atlas = Atlas::parse(ATLAS).expect("atlas");
    let font = Font::parse(atlas.entry(pq1a::NAME_FONTS).expect("fonts")).expect("font");
    let marks = atlas.marks();
    let v = |id: &[u8], i, c: &[u8], st, r| ScreenBuilder::verdict(id, i, c, st, r).finish().unwrap();
    let screens: Vec<(&str, Screen, Vec<u32>)> = vec![
        ("lock", v(b"LOCKED", Icon::Lock, b"LOCKED", State::Failed, ResultMark::None), vec![600, 800, 1100, 1400, 3000]),
        ("unlock", v(b"UNLOCKED", Icon::Unlock, b"UNLOCKED", State::Done, ResultMark::None), vec![700, 900, 1200, 1700, 3000]),
        ("tamper", v(b"TAMPER", Icon::Alert, b"TAMPER DETECTED", State::Failed, ResultMark::None), vec![800, 3000]),
        ("wipe", v(b"WIPED", Icon::Wipe, b"WALLET WIPED", State::Failed, ResultMark::None), vec![1200, 3000]),
        ("backup", v(b"BACKUP", Icon::Shield, b"BACKUP OK", State::Done, ResultMark::Check), vec![1000, 3000]),
        ("nomatch", v(b"NOMATCH", Icon::Shield, b"NO MATCH", State::Failed, ResultMark::Cross), vec![3000]),
        ("wrongpin", v(b"WRONGPIN", Icon::Pill, b"WRONG PIN", State::Failed, ResultMark::None), vec![700, 1000, 1300, 3000]),
        ("checking", v(b"CHECKPIN", Icon::Pill, b"CHECKING PIN", State::Awaiting, ResultMark::None), vec![3000]),
        ("rng", v(b"RNG", Icon::Die, b"RNG FAILED", State::Failed, ResultMark::None), vec![3000]),
        ("factory", v(b"FACTORY", Icon::Gear, b"FACTORY SIGNING", State::Awaiting, ResultMark::None), vec![1000, 3000]),
        ("canceled", v(b"CANCELED", Icon::ResultRing, b"CANCELED", State::Failed, ResultMark::Cross), vec![3000]),
        ("signed", v(b"SIGNED", Icon::ResultRing, b"SIGNED", State::Done, ResultMark::Check), vec![3000]),
        ("verified", v(b"VERIFIED", Icon::Verified, b"FIRMWARE VERIFIED", State::Done, ResultMark::Check), vec![3000]),
        (
            "sigerror",
            ScreenBuilder::verdict(b"ERROR", Icon::Alert, b"", State::Failed, ResultMark::None)
                .docked(Side::Left, b"SIGN REFUSED")
                .tier(Tier::T22)
                .line(b"gas unshown", Weight::Regular)
                .finish()
                .unwrap(),
            vec![3000],
        ),
        ("pin", ScreenBuilder::entry(b"PIN", b"ENTER PIN", b"***7____", b"EEEA____").finish().unwrap(), vec![500]),
        ("letters", ScreenBuilder::entry(b"WORD", b"WORD 3 OF 24", b"aba_", b"EEA_").finish().unwrap(), vec![500]),
        (
            "words",
            ScreenBuilder::words(b"FPRINT", b"OS FINGERPRINT", &[b"clos", b"agen", b"own", b"depu", b"grap", b"thou", b"sail", b"simp"]).finish().unwrap(),
            vec![500],
        ),
    ];
    // The seed page (secret run) and the candidate list.
    let seed = ScreenBuilder::words(b"SEED", b"", &[&b"*"[..]; 8]).first_number(9).finish().unwrap();
    let words: [&[u8; 8]; 8] = [b"mountain", b"abandon\0", b"zoo\0\0\0\0\0", b"withdraw", b"ill\0\0\0\0\0", b"jewel\0\0\0", b"quality\0", b"fix\0\0\0\0\0"];
    let list = ScreenBuilder::words(b"PICK", b"WORD 3 OF 24", &[b"*", b"@", b"*"]).first_number(0).finish().unwrap();
    let cands: [&[u8; 8]; 3] = [b"act\0\0\0\0\0", b"action\0\0", b"actor\0\0\0"];
    for (name, s, ws) in [("seed", seed, &words[..]), ("pick", list, &cands[..])] {
        let a = Anim::new(&s, 0, 0);
        let mut frame = pqsigner_ui_px::raster::Frame::new();
        a.build(&marks, &font, &mut frame);
        for (k, w) in ws.iter().enumerate() {
            pqsigner_ui_px::rows::push_secret_word(&mut frame, k, &w[..], 255);
        }
        let mut px = vec![0u16; (428 * 142) as usize];
        let mut sbuf = vec![0u16; 428 * 16];
        let mut y0 = 0;
        while y0 < 142 {
            let h = 16.min(142 - y0);
            let mut st = pqsigner_ui_px::raster::Strip::new(y0, h, &mut sbuf).unwrap();
            pqsigner_ui_px::raster::render_strip(&frame, &font, &mut st);
            px[(y0 * 428) as usize..((y0 + h) * 428) as usize].copy_from_slice(&st.buf[..(428 * h) as usize]);
            y0 += h;
        }
        write_png(Path::new(&format!("{out}/{name}.png")), &px).unwrap();
    }
    for (name, s, times) in screens {
        for t in times {
            let mut a = Anim::new(&s, 0, 0);
            let mut now = 16;
            while now < t {
                a.step(now);
                now += 16;
            }
            a.step(t);
            let px = render_full(&a, &marks, &font);
            write_png(Path::new(&format!("{out}/{name}_{t:04}.png")), &px).unwrap();
        }
    }
}

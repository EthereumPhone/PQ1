//! Render `[UI-PXR]` transcript records (from a QEMU `make e2e-px` log) to
//! PNGs with the real engine and the baked atlas — the faithful renderer
//! behind `tools/ui_screens_export.py --px`.
//!
//!     cargo run -p pqsigner-ui-px --features std --example render_record -- \
//!         <batch.txt>
//!
//! Every line of the batch file is `<out.png> <page> <512-hex record>`; the
//! settled pose of that (screen, page) is rendered. Lines that fail to parse
//! are reported on stderr and skipped (exit status 1 at the end).

use std::io::BufRead;
use std::path::Path;

use pqsigner_ui_px::font::Font;
use pqsigner_ui_px::png::{render_full, screen_from_hex, write_png};
use pqsigner_ui_px::pq1a::{self, Atlas};
use pqsigner_ui_px::scene::Anim;

const ATLAS: &[u8] = include_bytes!("../../nonsecure/assets/ui-px/atlas.pq1a");

fn main() {
    let Some(batch) = std::env::args().nth(1) else {
        eprintln!("usage: render_record <batch.txt>");
        std::process::exit(2);
    };
    let atlas = Atlas::parse(ATLAS).expect("atlas.pq1a parses");
    let font = Font::parse(atlas.entry(pq1a::NAME_FONTS).expect("fonts")).expect("font atlas");
    let marks = atlas.marks();
    let file = std::fs::File::open(&batch).expect("batch file");
    let mut bad = 0usize;
    let mut n = 0usize;
    for (ln, line) in std::io::BufReader::new(file).lines().enumerate() {
        let line = line.expect("line");
        let mut it = line.split_whitespace();
        let (Some(out), Some(page), Some(hex)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let (Some(screen), Ok(page)) = (screen_from_hex(hex), page.parse::<u8>()) else {
            eprintln!("line {}: unparsable record", ln + 1);
            bad += 1;
            continue;
        };
        // The settled pose: no transition, the trail collapsed.
        let mut anim = Anim::new(&screen, page, 0);
        let mut t = 16;
        while anim.step(t) && t < 4000 {
            t += 16;
        }
        let px = render_full(&anim, &marks, &font);
        if let Err(e) = write_png(Path::new(out), &px) {
            eprintln!("{out}: {e}");
            bad += 1;
            continue;
        }
        n += 1;
    }
    eprintln!("rendered {n} frames, {bad} failed");
    if bad > 0 {
        std::process::exit(1);
    }
}

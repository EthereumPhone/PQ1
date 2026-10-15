//! The setup flow's own screens (owner decisions 2026-10-15), as records.
//!
//! Pure: built from `pqsigner_ui_px` alone, so the host tests can pin them
//! and the lifecycle fixtures can carry them (the rest of the `ui` tree is
//! `cfg(not(test))`). `seed_wizard` walks them; on a build without the pixel
//! UI it paints each record's caption or label and lines as a 16x4 page.
//!
//! They wear the setup family's look from the design (`flows/setup`): the
//! 3 x 3 dots on the white disc, never the shield.

use pqsigner_ui_px::fit::{fit_tier, Region};
use pqsigner_ui_px::{Icon, Nav, Screen, ScreenBuilder, Side, Tier, Weight};

/// A setup hero (the dots on the white disc).
fn hero(id: &[u8], caption: &[u8]) -> ScreenBuilder {
    ScreenBuilder::hero(id, Icon::Dots, caption)
}

/// A setup detail: the dots docked right, `label` under them, `lines` at the
/// largest tier that fits.
fn detail(id: &[u8], label: &[u8], lines: &[&[u8]]) -> Screen {
    let mut l: [(&[u8], Weight); 3] = [(&[], Weight::Regular); 3];
    for (d, s) in l.iter_mut().zip(lines) {
        *d = (s, Weight::Regular);
    }
    let l = &l[..lines.len().min(3)];
    let tier = fit_tier(l, Region::Docked).unwrap_or(Tier::T22);
    let mut b = ScreenBuilder::detail(id, Icon::Dots, Side::Right, label).tier(tier);
    for &(s, w) in l {
        b = b.line(s, w);
    }
    b.finish().unwrap_or(Screen::BLANK)
}

/// Index of CREATE NEW WALLET? in [`intro`].
pub const CREATE: usize = 2;
/// Index of IMPORT WALLET? in [`intro`].
pub const IMPORT: usize = 3;

/// The setup intro: welcome (right arrow only), the buttons, then the two
/// asks (the last one with the left arrow only).
#[must_use]
pub fn intro() -> [Screen; 4] {
    [
        hero(b"WELCOME", b"WELCOME TO PQ1")
            .uncommitted()
            .nav(Nav::RightOnly)
            .finish()
            .unwrap_or(Screen::BLANK),
        detail(
            b"BUTTONS",
            b"BUTTONS",
            &[b"Left = back", b"Right = next", b"Both = select"],
        ),
        hero(b"CREATE", b"CREATE NEW WALLET?")
            .finish()
            .unwrap_or(Screen::BLANK),
        hero(b"IMPORT", b"IMPORT WALLET?")
            .nav(Nav::LeftOnly)
            .finish()
            .unwrap_or(Screen::BLANK),
    ]
}

/// What the PIN is for, before SET PIN.
#[must_use]
pub fn pin_help() -> Screen {
    detail(
        b"PINHELP",
        b"PIN",
        &[b"Choose 8 digits", b"to unlock PQ1,", b"then repeat it."],
    )
}

/// Before the words: an intro hero (a tap right shows them; it asks nothing).
#[must_use]
pub fn backup_intro() -> Screen {
    hero(b"BACKUP", b"WRITE DOWN 24 WORDS")
        .intro()
        .finish()
        .unwrap_or(Screen::BLANK)
}

/// After the last word page: a tap left goes back to the words, the click
/// moves on. Nothing lies to the right, so only the left arrow shows.
#[must_use]
pub fn written() -> Screen {
    hero(b"WRITTEN", b"WORDS WRITTEN DOWN?")
        .nav(Nav::LeftOnly)
        .finish()
        .unwrap_or(Screen::BLANK)
}

/// A seed page left five minutes without a press.
#[must_use]
pub fn hidden() -> Screen {
    detail(
        b"HIDDEN",
        b"HIDDEN",
        &[b"Words hidden after", b"5 minutes idle.", b"Press to show."],
    )
}

/// An entry row (the PIN, a check word, a word being typed in) left two
/// minutes without a press. The row leaves the glass, because a typed prefix
/// or a candidate list is seed material; any press brings it back.
#[must_use]
pub fn paused() -> Screen {
    detail(
        b"PAUSED",
        b"PAUSED",
        &[b"Paused after", b"2 minutes idle.", b"Press to go on."],
    )
}

/// Before the words are typed in.
#[must_use]
pub fn import_intro() -> Screen {
    hero(b"RESTORE", b"ENTER YOUR 24 WORDS")
        .intro()
        .finish()
        .unwrap_or(Screen::BLANK)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> std::vec::Vec<Screen> {
        let mut v = intro().to_vec();
        v.extend([
            pin_help(),
            backup_intro(),
            written(),
            hidden(),
            paused(),
            import_intro(),
        ]);
        v
    }

    /// Every record builds (a `BLANK` fallback would show an empty panel) and
    /// passes the design-rule checker.
    #[test]
    fn every_setup_screen_builds_and_fits() {
        for s in all() {
            assert_ne!(s.0, Screen::BLANK.0);
            assert!(s.is_well_formed(), "{s:?}");
            assert_eq!(
                pqsigner_ui_px::check::check_screens(core::slice::from_ref(&s)),
                Ok(()),
                "{s:?}"
            );
        }
    }

    /// The asks are exactly the two choices; the welcome, the buttons and the
    /// intros ask nothing, so the confirm gesture cannot select them.
    #[test]
    fn only_the_two_choices_ask() {
        let i = intro();
        let asking: std::vec::Vec<usize> = (0..i.len()).filter(|&k| i[k].commit()).collect();
        assert_eq!(asking, [CREATE, IMPORT]);
        assert_eq!(i[CREATE].caption(), b"CREATE NEW WALLET?");
        assert_eq!(i[IMPORT].caption(), b"IMPORT WALLET?");
        for s in [
            pin_help(),
            backup_intro(),
            hidden(),
            paused(),
            import_intro(),
        ] {
            assert!(!s.commit(), "{s:?}");
        }
        assert!(written().commit());
    }

    /// The arrows are the navigation indicators: the first screen points
    /// right only, the last left only.
    #[test]
    fn the_ends_of_the_intro_show_one_arrow() {
        let i = intro();
        assert_eq!(i[0].nav(), Some(Nav::RightOnly));
        assert_eq!(i[1].nav(), Some(Nav::Default));
        assert_eq!(i[CREATE].nav(), Some(Nav::Default));
        assert_eq!(i[IMPORT].nav(), Some(Nav::LeftOnly));
        assert_eq!(backup_intro().nav(), Some(Nav::Intro));
        assert_eq!(import_intro().nav(), Some(Nav::Intro));
        assert_eq!(written().nav(), Some(Nav::LeftOnly));
    }
}

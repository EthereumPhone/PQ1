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
    detail_on(id, Side::Right, Nav::Default, label, lines)
}

/// [`detail`] docked on `side`, in the navigation pose `nav`.
fn detail_on(id: &[u8], side: Side, nav: Nav, label: &[u8], lines: &[&[u8]]) -> Screen {
    let mut l: [(&[u8], Weight); 3] = [(&[], Weight::Regular); 3];
    for (d, s) in l.iter_mut().zip(lines) {
        *d = (s, Weight::Regular);
    }
    let l = &l[..lines.len().min(3)];
    let tier = fit_tier(l, Region::Docked).unwrap_or(Tier::T22);
    let mut b = ScreenBuilder::detail(id, Icon::Dots, side, label)
        .tier(tier)
        .nav(nav);
    for &(s, w) in l {
        b = b.line(s, w);
    }
    b.finish().unwrap_or(Screen::BLANK)
}

/// Index of the second buttons page (confirm, cancel) in [`intro`].
pub const CONFIRM_HELP: usize = 2;
/// Index of CREATE NEW WALLET? in [`intro`].
pub const CREATE: usize = 3;
/// Index of IMPORT WALLET? in [`intro`].
pub const IMPORT: usize = 4;

/// The setup intro: welcome (right arrow only), the buttons on two pages,
/// then the two asks (the last one with the left arrow only).
///
/// The second buttons page (owner 2026-10-15) docks the disc on the left and
/// plays the ask's arrow hint ([`Nav::Hint`]) beside "Both = confirm", so the
/// moving arrows are learned as "confirm works here". Its confirm does work:
/// it moves on to the choice, as a right tap does.
#[must_use]
pub fn intro() -> [Screen; 5] {
    [
        hero(b"WELCOME", b"WELCOME TO PQ1")
            .uncommitted()
            .nav(Nav::RightOnly)
            .finish()
            .unwrap_or(Screen::BLANK),
        detail(b"BUTTONS", b"BUTTONS", &[b"Left = back", b"Right = next"]),
        detail_on(
            b"CONFIRM",
            Side::Left,
            Nav::Hint,
            b"BUTTONS",
            &[b"Both = confirm", b"Hold left = cancel"],
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
        &[
            b"Secure your PQ1",
            b"with an 8-digit PIN.",
            b"Enter it twice.",
        ],
    )
}

/// The ask that ends every intro to a set of words: the click shows them.
/// Nothing lies to the right, so only the left arrow shows.
#[must_use]
pub fn show_words() -> Screen {
    hero(b"SHOWWRDS", b"CONFIRM TO SHOW WORDS")
        .nav(Nav::LeftOnly)
        .finish()
        .unwrap_or(Screen::BLANK)
}

/// Before the words: five pages in the buttons' style, the disc crossing the
/// panel on each, then [`show_words`] (owner wording, 2026-10-15). The first
/// has no way back (the PIN is set and the phrase is already drawn), so it
/// shows the right arrow only; only the last asks.
#[must_use]
pub fn backup_intro() -> [Screen; 6] {
    [
        detail_on(
            b"RECOVER",
            Side::Right,
            Nav::RightOnly,
            b"RECOVERY",
            &[
                b"Your PQ1 will now",
                b"generate a 24-word",
                b"recovery phrase.",
            ],
        ),
        detail_on(
            b"WRITEDWN",
            Side::Left,
            Nav::Default,
            b"WRITE DOWN",
            &[
                b"Write the words down",
                b"in the exact order",
                b"they are shown.",
            ],
        ),
        detail_on(
            b"ONLYBACK",
            Side::Right,
            Nav::Default,
            b"ONLY BACKUP",
            &[b"They are the only", b"way to restore", b"your wallet."],
        ),
        detail_on(
            b"KEEPSAFE",
            Side::Left,
            Nav::Default,
            b"KEEP SAFE",
            &[b"Store them safely", b"and never share", b"them."],
        ),
        detail_on(
            b"SAFETY",
            Side::Right,
            Nav::Default,
            b"SAFETY",
            &[
                b"Freedom Factory will",
                b"never ask for them.",
                b"Beware of impostors.",
            ],
        ),
        show_words(),
    ]
}

/// Between CONFIRM TO VERIFY WORDS and the first check: what the checks ask.
#[must_use]
pub fn quiz_intro() -> Screen {
    detail(
        b"QUIZ",
        b"QUIZ",
        &[
            b"Next, a quiz on 3 of",
            b"your words. Type the",
            b"first 4 letters.",
        ],
    )
}

/// Index of WIPE DEVICE? in [`duress_intro`].
#[cfg(any(feature = "duress-pin", feature = "duress-ui-test", test))]
pub const DURESS_WIPE: usize = 3;
/// Index of OPEN DECOY WALLET? in [`duress_intro`].
#[cfg(any(feature = "duress-pin", feature = "duress-ui-test", test))]
pub const DURESS_DECOY: usize = 4;

/// After the word quiz: the duress PIN explained, then what it does (owner
/// wording 2026-10-16). It cannot be skipped (owner decision, same date), so
/// the first page shows the right arrow only and the pages end on the two
/// choices, laid out like CREATE NEW WALLET? / IMPORT WALLET?.
#[cfg(any(feature = "duress-pin", feature = "duress-ui-test", test))]
#[must_use]
pub fn duress_intro() -> [Screen; 5] {
    [
        detail_on(
            b"DURESS",
            Side::Right,
            Nav::RightOnly,
            b"DURESS PIN",
            &[
                b"Great! Now set a",
                b"duress PIN, a second",
                b"PIN for emergencies.",
            ],
        ),
        detail_on(
            b"WIPEDCOY",
            Side::Left,
            Nav::Default,
            b"WIPE / DECOY",
            &[
                b"It can wipe your PQ1",
                b"or open a decoy",
                b"wallet instead.",
            ],
        ),
        detail_on(
            b"DECOY",
            Side::Right,
            Nav::Default,
            b"DECOY",
            &[
                b"A decoy holds real",
                b"funds and can sign,",
                b"separate from yours.",
            ],
        ),
        hero(b"DWIPE", b"WIPE DEVICE?")
            .finish()
            .unwrap_or(Screen::BLANK),
        hero(b"DDECOY", b"OPEN DECOY WALLET?")
            .nav(Nav::LeftOnly)
            .finish()
            .unwrap_or(Screen::BLANK),
    ]
}

/// Before the decoy wallet's words (owner wording 2026-10-16): two pages,
/// then [`show_words`]. The first has no way back (the choice is made and
/// the decoy's phrase drawn).
#[cfg(any(feature = "duress-pin", feature = "duress-ui-test", test))]
#[must_use]
pub fn decoy_intro() -> [Screen; 3] {
    [
        detail_on(
            b"DCYWORDS",
            Side::Right,
            Nav::RightOnly,
            b"DECOY WORDS",
            &[
                b"Your PQ1 will now",
                b"generate the decoy's",
                b"24-word phrase.",
            ],
        ),
        detail_on(
            b"DCYAPART",
            Side::Left,
            Nav::Default,
            b"KEEP APART",
            &[
                b"Write them down too,",
                b"apart from your real",
                b"recovery phrase.",
            ],
        ),
        show_words(),
    ]
}

/// After the last word page: a tap left goes back to the words, the click
/// moves on. Nothing lies to the right, so only the left arrow shows.
#[must_use]
pub fn written() -> Screen {
    hero(b"WRITTEN", b"CONFIRM TO VERIFY WORDS")
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

/// After the wallet is written and the explosion has played (owner wording
/// 2026-10-16): YOUR PQ1 IS READY, then HELP; a right tap off HELP ends
/// setup. Nothing asks.
#[must_use]
pub fn ready() -> [Screen; 2] {
    [
        hero(b"READY", b"YOUR PQ1 IS READY")
            .uncommitted()
            .nav(Nav::RightOnly)
            .finish()
            .unwrap_or(Screen::BLANK),
        detail(
            b"HELP",
            b"HELP",
            &[
                b"Questions? Email",
                b"hi@freedomfactory.io",
                b"Enjoy your PQ1 :)",
            ],
        ),
    ]
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
        v.extend(backup_intro());
        v.extend(duress_intro());
        v.extend(decoy_intro());
        v.extend(ready());
        v.extend([
            pin_help(),
            written(),
            quiz_intro(),
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

    /// The asks are the two choices; the welcome, the buttons and the intros
    /// ask nothing, so the confirm gesture cannot select them.
    #[test]
    fn only_the_two_choices_ask() {
        let i = intro();
        let asking: std::vec::Vec<usize> = (0..i.len()).filter(|&k| i[k].commit()).collect();
        assert_eq!(asking, [CREATE, IMPORT]);
        // The confirm page asks nothing, but its confirm moves on.
        let confirmable: std::vec::Vec<usize> =
            (0..i.len()).filter(|&k| i[k].confirmable()).collect();
        assert_eq!(confirmable, [CONFIRM_HELP, CREATE, IMPORT]);
        assert_eq!(i[CREATE].caption(), b"CREATE NEW WALLET?");
        assert_eq!(i[IMPORT].caption(), b"IMPORT WALLET?");
        for s in ready() {
            assert!(!s.confirmable(), "nothing after setup asks: {s:?}");
        }
        for s in [pin_help(), quiz_intro(), hidden(), paused(), import_intro()] {
            assert!(!s.commit(), "{s:?}");
        }
        // Each intro to a set of words asks once, on its last page: the
        // click that shows the words. Nothing before it can.
        for intro in [&backup_intro()[..], &decoy_intro()[..]] {
            let (last, before) = intro.split_last().unwrap();
            assert_eq!(last.caption(), b"CONFIRM TO SHOW WORDS");
            assert!(last.commit());
            for s in before {
                assert!(
                    !s.confirmable(),
                    "nothing on the way to the words asks: {s:?}"
                );
            }
        }
        assert!(written().commit());
        // The duress pages end on the two choices and nothing else asks: the
        // duress PIN cannot be skipped (owner 2026-10-16).
        let d = duress_intro();
        let asking: std::vec::Vec<usize> = (0..d.len()).filter(|&k| d[k].confirmable()).collect();
        assert_eq!(asking, [DURESS_WIPE, DURESS_DECOY]);
        assert_eq!(d[DURESS_WIPE].caption(), b"WIPE DEVICE?");
        assert_eq!(d[DURESS_DECOY].caption(), b"OPEN DECOY WALLET?");
    }

    /// The arrows are the navigation indicators: the first screen points
    /// right only, the last left only.
    #[test]
    fn the_ends_of_the_intro_show_one_arrow() {
        let i = intro();
        assert_eq!(i[0].nav(), Some(Nav::RightOnly));
        assert_eq!(i[1].nav(), Some(Nav::Default));
        assert_eq!(i[CONFIRM_HELP].nav(), Some(Nav::Hint));
        assert_eq!(i[CONFIRM_HELP].side(), Some(Side::Left));
        assert_eq!(i[CREATE].nav(), Some(Nav::Default));
        assert_eq!(i[IMPORT].nav(), Some(Nav::LeftOnly));
        let b = backup_intro();
        assert_eq!(
            b[0].nav(),
            Some(Nav::RightOnly),
            "no way back from the first"
        );
        let sides: std::vec::Vec<_> = b[..5].iter().map(|s| s.side()).collect();
        assert_eq!(
            sides,
            [
                Some(Side::Right),
                Some(Side::Left),
                Some(Side::Right),
                Some(Side::Left),
                Some(Side::Right)
            ],
            "the disc crosses the panel on every page before the ask"
        );
        assert_eq!(import_intro().nav(), Some(Nav::Intro));
        assert_eq!(written().nav(), Some(Nav::LeftOnly));
        // No way back into a step already done; the last ask, left only.
        for pages in [&backup_intro()[..], &duress_intro()[..], &decoy_intro()[..]] {
            assert_eq!(pages[0].nav(), Some(Nav::RightOnly), "{:?}", pages[0]);
            assert_eq!(pages[pages.len() - 1].nav(), Some(Nav::LeftOnly));
        }
    }
}

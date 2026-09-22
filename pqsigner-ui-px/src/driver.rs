//! The flow driver — DESIGN.md § Input's navigation grammar over a screen
//! transcript, as a pure state machine (a port of `tools/pq-ui/pq1/driver.py`).
//!
//! * **Left regresses, right progresses**; the mapping never flips.
//! * **The ask is the hub**: a hero has no left or right — either tap enters
//!   the details at their first screen, first page. From the returning ask
//!   (the last screen) any tap starts the details from the beginning again.
//! * **A tap turns the page first**: right shows the next page until the
//!   last, then the next screen; left the previous page until the first,
//!   then the previous screen, entered on its LAST page (left undoes right).
//! * **Declining is always cheap; signing is not**: hold-left is armed on
//!   every navigable screen; hold-right only where the screen carries
//!   `commit` (a hero or the `Confirm?`). A hold on an unarmed side is a
//!   no-op — never demoted into navigation, so a stray long press can neither
//!   sign nor skip content.
//! * Status screens are not part of a confirmation transcript; every screen
//!   here is navigable.
//!
//! The driver knows nothing about time, springs or the hold fill — the
//! presenter turns physical edges into [`Gesture`]s and animates; the driver
//! decides what they mean. The secure world wraps [`FlowDriver::apply`] with
//! its FI sentinel, the `seen_last` policy and the deadline / idle checks.

use crate::screen::{Kind, Screen};

/// A physical side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Btn {
    Left,
    Right,
}

/// What the presenter hands the driver (already debounced and timed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gesture {
    Tap(Btn),
    /// A hold that reached `HOLD_COMMIT_MS` and fired.
    HoldCommit(Btn),
}

/// What a gesture did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NavResult {
    /// Nothing (unarmed hold, tap at a bound).
    Ignored,
    /// Moved to another screen (its first or last page).
    Moved,
    /// Turned a page within the current screen.
    PageTurned,
    /// Hold-right on a commit-armed screen.
    Sign,
    /// Hold-left anywhere.
    Decline,
}

/// The gestures armed on the current screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Armed {
    pub back: bool,
    pub forward: bool,
    pub sign: bool,
    pub decline: bool,
}

/// Navigation state over a transcript.
#[derive(Clone, Copy, Debug)]
pub struct FlowDriver {
    cur: usize,
    page: u8,
    count: usize,
    /// The returning hero (last screen) has been displayed at least once.
    seen_last: bool,
}

impl FlowDriver {
    /// `None` unless the transcript opens on a hero.
    #[must_use]
    pub fn new(screens: &[Screen]) -> Option<Self> {
        let first = screens.first()?;
        if first.kind() != Some(Kind::Hero) {
            return None;
        }
        Some(Self {
            cur: 0,
            page: 0,
            count: screens.len(),
            seen_last: false,
        })
    }

    #[must_use]
    pub fn index(&self) -> usize {
        self.cur
    }

    #[must_use]
    pub fn page(&self) -> u8 {
        self.page
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.count
    }

    /// Whether the returning hero has been displayed (the revert hook for
    /// the scroll-to-end policy).
    #[must_use]
    pub fn seen_last(&self) -> bool {
        self.seen_last
    }

    /// The presenter calls this after painting the current screen.
    pub fn mark_rendered(&mut self) {
        if self.cur + 1 == self.count {
            self.seen_last = true;
        }
    }

    fn is_hero(&self, screens: &[Screen]) -> bool {
        screens.get(self.cur).and_then(Screen::kind) == Some(Kind::Hero)
    }

    fn pages_of(screens: &[Screen], i: usize) -> u8 {
        screens.get(i).map_or(1, Screen::npages).max(1)
    }

    /// The gesture set armed on the current screen.
    #[must_use]
    pub fn armed(&self, screens: &[Screen]) -> Armed {
        let Some(s) = screens.get(self.cur) else {
            return Armed {
                back: false,
                forward: false,
                sign: false,
                decline: false,
            };
        };
        let hero = s.kind() == Some(Kind::Hero);
        let last = self.cur + 1 == self.count;
        Armed {
            // A hero's taps both enter the details; a detail can always go
            // back (to the previous screen or the hero) and forward until
            // the returning hero.
            back: hero || self.cur > 0,
            forward: hero || !last,
            sign: s.kind().is_some_and(Kind::may_commit) && s.commit(),
            decline: true,
        }
    }

    /// Apply a gesture.
    pub fn apply(&mut self, screens: &[Screen], g: Gesture) -> NavResult {
        let n = screens.len().min(self.count);
        if n == 0 || self.cur >= n {
            return NavResult::Ignored;
        }
        match g {
            Gesture::HoldCommit(Btn::Left) => NavResult::Decline,
            Gesture::HoldCommit(Btn::Right) => {
                if self.armed(screens).sign {
                    NavResult::Sign
                } else {
                    NavResult::Ignored
                }
            }
            Gesture::Tap(btn) => {
                if self.is_hero(screens) {
                    // The hub: either tap enters the details at the first
                    // detail screen, first page (the ask itself when the
                    // transcript is just the hero pair).
                    if n <= 2 {
                        return NavResult::Ignored;
                    }
                    self.cur = 1;
                    self.page = 0;
                    return NavResult::Moved;
                }
                match btn {
                    Btn::Right => {
                        let pages = Self::pages_of(screens, self.cur);
                        if self.page + 1 < pages {
                            self.page += 1;
                            NavResult::PageTurned
                        } else if self.cur + 1 < n {
                            self.cur += 1;
                            self.page = 0;
                            NavResult::Moved
                        } else {
                            NavResult::Ignored
                        }
                    }
                    Btn::Left => {
                        if self.page > 0 {
                            self.page -= 1;
                            NavResult::PageTurned
                        } else if self.cur > 0 {
                            self.cur -= 1;
                            // Entered on its LAST page so left undoes right.
                            self.page = Self::pages_of(screens, self.cur) - 1;
                            NavResult::Moved
                        } else {
                            NavResult::Ignored
                        }
                    }
                }
            }
        }
    }
}

#[cfg(kani)]
mod kani_harnesses {
    use super::*;
    use crate::screen::{Icon, ScreenBuilder, Side, Weight};

    /// `Sign` is reachable only from a commit-armed hero / confirm, for any
    /// gesture sequence over any small transcript shape.
    #[kani::proof]
    #[kani::unwind(14)]
    fn sign_only_from_armed_screens() {
        let n: usize = kani::any();
        kani::assume((2..=6).contains(&n));
        let hero = ScreenBuilder::hero(b"ASK", Icon::Safe, b"ASK?").finish().unwrap();
        let detail = ScreenBuilder::detail(b"D", Icon::Safe, Side::Left, b"L")
            .line(b"x", Weight::Regular)
            .finish()
            .unwrap();
        let confirm = ScreenBuilder::confirm(Icon::Safe).finish().unwrap();
        let mut buf = [hero; 6];
        for i in 1..n - 1 {
            buf[i] = if kani::any() { detail } else { confirm };
        }
        let screens = &buf[..n];
        let mut d = FlowDriver::new(screens).unwrap();
        for _ in 0..12 {
            let g = match kani::any::<u8>() % 4 {
                0 => Gesture::Tap(Btn::Left),
                1 => Gesture::Tap(Btn::Right),
                2 => Gesture::HoldCommit(Btn::Left),
                _ => Gesture::HoldCommit(Btn::Right),
            };
            let before = d.index();
            let r = d.apply(screens, g);
            if r == NavResult::Sign {
                let s = &screens[before];
                assert!(s.kind().is_some_and(Kind::may_commit) && s.commit());
            }
            assert!(d.index() < n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screen::{Icon, ScreenBuilder, Side, Weight};

    fn hero() -> Screen {
        ScreenBuilder::hero(b"ASK", Icon::Safe, b"ASK?").finish().unwrap()
    }
    fn detail(pages: u8) -> Screen {
        let b = ScreenBuilder::detail(b"D", Icon::Safe, Side::Left, b"L").line(b"a", Weight::Regular);
        if pages == 2 {
            b.next_page().line(b"b", Weight::Regular).finish().unwrap()
        } else {
            b.finish().unwrap()
        }
    }
    fn confirm() -> Screen {
        ScreenBuilder::confirm(Icon::Safe).finish().unwrap()
    }

    /// hero, d1, d2(2 pages), confirm, d3, hero
    fn flow() -> [Screen; 6] {
        [hero(), detail(1), detail(2), confirm(), detail(1), hero()]
    }

    #[test]
    fn requires_an_opening_hero() {
        assert!(FlowDriver::new(&[detail(1)]).is_none());
        assert!(FlowDriver::new(&[]).is_none());
        assert!(FlowDriver::new(&flow()).is_some());
    }

    #[test]
    fn hub_and_page_first_taps() {
        let f = flow();
        let mut d = FlowDriver::new(&f).unwrap();
        // Either tap enters the details.
        assert_eq!(d.apply(&f, Gesture::Tap(Btn::Left)), NavResult::Moved);
        assert_eq!((d.index(), d.page()), (1, 0));
        assert_eq!(d.apply(&f, Gesture::Tap(Btn::Right)), NavResult::Moved);
        assert_eq!((d.index(), d.page()), (2, 0));
        // Page first, then the next screen.
        assert_eq!(d.apply(&f, Gesture::Tap(Btn::Right)), NavResult::PageTurned);
        assert_eq!((d.index(), d.page()), (2, 1));
        assert_eq!(d.apply(&f, Gesture::Tap(Btn::Right)), NavResult::Moved);
        assert_eq!((d.index(), d.page()), (3, 0));
        // Left undoes right: enters the previous screen on its last page.
        assert_eq!(d.apply(&f, Gesture::Tap(Btn::Left)), NavResult::Moved);
        assert_eq!((d.index(), d.page()), (2, 1));
        assert_eq!(d.apply(&f, Gesture::Tap(Btn::Left)), NavResult::PageTurned);
        assert_eq!((d.index(), d.page()), (2, 0));
        // Back to the ask from the first detail.
        assert_eq!(d.apply(&f, Gesture::Tap(Btn::Left)), NavResult::Moved);
        assert_eq!(d.apply(&f, Gesture::Tap(Btn::Left)), NavResult::Moved);
        assert_eq!(d.index(), 0);
        // From the returning ask any tap restarts the details.
        for _ in 0..6 {
            d.apply(&f, Gesture::Tap(Btn::Right));
        }
        assert_eq!(d.index(), 5);
        assert!(d.armed(&f).sign);
        assert_eq!(d.apply(&f, Gesture::Tap(Btn::Right)), NavResult::Moved);
        assert_eq!((d.index(), d.page()), (1, 0));
    }

    #[test]
    fn arming_follows_the_design() {
        let f = flow();
        let mut d = FlowDriver::new(&f).unwrap();
        // Opening hero arms sign.
        assert!(d.armed(&f).sign);
        assert_eq!(d.apply(&f, Gesture::HoldCommit(Btn::Right)), NavResult::Sign);
        // Details never do; the hold is a no-op, not navigation.
        d.apply(&f, Gesture::Tap(Btn::Right));
        assert!(!d.armed(&f).sign);
        let before = (d.index(), d.page());
        assert_eq!(d.apply(&f, Gesture::HoldCommit(Btn::Right)), NavResult::Ignored);
        assert_eq!((d.index(), d.page()), before);
        // Decline everywhere.
        assert!(d.armed(&f).decline);
        assert_eq!(d.apply(&f, Gesture::HoldCommit(Btn::Left)), NavResult::Decline);
        // Confirm? arms sign.
        d.apply(&f, Gesture::Tap(Btn::Right));
        d.apply(&f, Gesture::Tap(Btn::Right));
        d.apply(&f, Gesture::Tap(Btn::Right));
        assert_eq!(d.index(), 3);
        assert!(d.armed(&f).sign);
        assert_eq!(d.apply(&f, Gesture::HoldCommit(Btn::Right)), NavResult::Sign);
    }

    #[test]
    fn seen_last_tracks_the_returning_hero() {
        let f = flow();
        let mut d = FlowDriver::new(&f).unwrap();
        d.mark_rendered();
        assert!(!d.seen_last());
        for _ in 0..6 {
            d.apply(&f, Gesture::Tap(Btn::Right));
            d.mark_rendered();
        }
        assert_eq!(d.index(), 5);
        assert!(d.seen_last());
        // Sticky.
        d.apply(&f, Gesture::Tap(Btn::Left));
        assert!(d.seen_last());
    }

    #[test]
    fn hero_pair_only_flow_ignores_taps() {
        let f = [hero(), hero()];
        let mut d = FlowDriver::new(&f).unwrap();
        assert_eq!(d.apply(&f, Gesture::Tap(Btn::Right)), NavResult::Ignored);
        assert_eq!(d.apply(&f, Gesture::HoldCommit(Btn::Right)), NavResult::Sign);
    }
}

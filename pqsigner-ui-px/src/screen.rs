//! The `Screen` / `Screens` transcript — the semantic record the pixel UI
//! renders and the secure world proves.
//!
//! # Why bytes, not an enum
//!
//! The legacy trusted display is a `[[u8; 16]; 4]` page whose every byte is
//! printable ASCII. That single property is what the whole WYSIWYS proof
//! machinery leans on: the `0xA5` transcript poison can never appear in a
//! valid page, two renders can be compared byte-for-byte, exact-occurrence
//! uniqueness is a plain fold, and `ui-capture` hashes the bytes verbatim.
//! `Screen` keeps that shape — a fixed 256-byte record whose every field is
//! ASCII — so all of that carries over unchanged. Small enums are encoded as
//! single ASCII letters; numbers as ASCII digits.
//!
//! # Record layout (256 bytes)
//!
//! | off | len | field   | encoding |
//! |-----|-----|---------|----------|
//! |   0 |   1 | kind    | `H` hero, `D` detail, `V` value, `C` confirm, `S` status, `L` legacy |
//! |   1 |   1 | icon    | `S` safe, `N` chain, `F` fingerprint, `W` wallet, `E` ether, `U` USDC, `T` USDT, `D` DAI, `B` blind, `R` rotate, `C` CoW Swap, `-` none |
//! |   2 |   1 | side    | `L`, `R`, `-` (disc column on a detail screen) |
//! |   3 |   2 | tier    | `36` `32` `28` `22`, or `--` |
//! |   5 |   1 | commit  | `Y` / `N` — hold-right-to-sign armed; only on `H` / `C` |
//! |   6 |   1 | pulse   | `Y` / `N` — warning rings around the disc |
//! |   7 |   1 | state   | `d` done, `f` failed, `w` warning, `a` awaiting, `-` |
//! |   8 |   1 | result  | `c` check, `x` cross, `-` |
//! |   9 |   1 | npages  | `1` / `2` |
//! |  10 |   2 | nlines  | per page, `0`..`4` (`4` only on `L`) |
//! |  12 |   8 | id      | capture / export key, never drawn |
//! |  20 |  12 | label   | caps, 16 px `SemiBold` under the disc |
//! |  32 |  32 | caption | caps, the hero ask / confirm prompt / status caption |
//! |  64 | 192 | lines   | 6 × { weight `r`/`s`/`t`, 30 bytes text, 1 pad } |
//! |  95 |   1 | tint    | the pad of line record 0: ` ` = the icon's own look, `a`..`n` = placeholder ramp 0..13 |
//!
//! The tint is the design's token colour (DESIGN.md § Color, placeholder
//! ramps): a solid disc + trail on one of the fourteen ramps, hashed from the
//! token's identity ([`placeholder_ramp`]). It lives in a pad byte so every
//! record written before it existed (the Safe family) is byte-identical.
//! Design kinds address page `p` line `i` as record `p * 3 + i`; a legacy
//! screen stores its four 16-column rows in records `0..4` of page 0.
//! Unused text is space-padded, so a record is always fully defined.
//!
//! Builders are the only writers. They reject anything that is not printable
//! ASCII, anything overlong, `commit = Y` on a kind that cannot carry it, and
//! more than three lines on a non-legacy screen — every rejection is an
//! `Err`, never a truncation, because a clipped value on a signing screen is
//! a WYSIWYS defect.

use pqsigner_erc7730::display::{
    volatile_poison_bytes, volatile_zero_bytes, Page, DISPLAY_COLS, DISPLAY_ROWS, TRANSCRIPT_POISON,
};

/// Size of one record in bytes.
pub const SCREEN_BYTES: usize = 256;
/// Bytes reserved for the capture/export id.
pub const ID_LEN: usize = 8;
/// Bytes reserved for the label under the disc.
pub const LABEL_LEN: usize = 12;
/// Bytes reserved for the caption (hero ask / confirm prompt / status).
pub const CAPTION_LEN: usize = 32;
/// Text bytes per line record (the full-width 22-tier budget).
pub const LINE_LEN: usize = 30;
/// Bytes per line record: weight byte + text + pad.
pub const LINE_REC: usize = 32;
/// Line records available in one screen.
pub const MAX_LINE_RECS: usize = 6;
/// Lines per page on a design screen.
pub const LINES_PER_PAGE: usize = 3;
/// Lines on a legacy (16×4) screen.
pub const LEGACY_LINES: usize = DISPLAY_ROWS;
/// Pages a single screen may turn through.
pub const PAGES_PER_SCREEN: usize = 2;
/// Hard cap on the number of screens in one confirmation transcript. Sized
/// for the worst Safe-UI case (a multiSend batch of ERC-20 records, refund
/// block, safeTxGas, the eleven native trailer slots, `Confirm?`, returning
/// hero) plus headroom; the secure world overlays the transcript on the sign
/// snapshot buffer's tail, whose const assert bounds this. The budget gate
/// refuses beyond it — never truncates.
pub const MAX_SCREENS: usize = 48;

const OFF_KIND: usize = 0;
const OFF_ICON: usize = 1;
const OFF_SIDE: usize = 2;
const OFF_TIER: usize = 3;
const OFF_COMMIT: usize = 5;
const OFF_PULSE: usize = 6;
const OFF_STATE: usize = 7;
const OFF_RESULT: usize = 8;
const OFF_NPAGES: usize = 9;
const OFF_NLINES: usize = 10;
const OFF_ID: usize = 12;
const OFF_LABEL: usize = 20;
const OFF_CAPTION: usize = 32;
const OFF_LINES: usize = 64;
/// The tint rides in the pad byte of line record 0.
const OFF_TINT: usize = OFF_LINES + LINE_REC - 1;
/// Number of placeholder ramps (`colors.PLACEHOLDER_GRADIENTS`).
pub const N_RAMPS: u8 = 14;

const _: () = assert!(OFF_ID + ID_LEN == OFF_LABEL);
const _: () = assert!(OFF_LABEL + LABEL_LEN == OFF_CAPTION);
const _: () = assert!(OFF_CAPTION + CAPTION_LEN == OFF_LINES);
const _: () = assert!(OFF_LINES + MAX_LINE_RECS * LINE_REC == SCREEN_BYTES);
const _: () = assert!(1 + LINE_LEN + 1 == LINE_REC);
const _: () = assert!(LINES_PER_PAGE * PAGES_PER_SCREEN == MAX_LINE_RECS);
const _: () = assert!(LEGACY_LINES <= MAX_LINE_RECS);
const _: () = assert!(DISPLAY_COLS <= LINE_LEN);
// The poison byte must be outside the printable-ASCII alphabet, or a valid
// record could masquerade as a poisoned one (and vice versa).
const _: () = assert!(TRANSCRIPT_POISON < 0x20 || TRANSCRIPT_POISON > 0x7E);

/// Screen kind (record byte 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The ask: disc centred, caption on the bottom band. Hub for navigation.
    Hero,
    /// A docked disc with a label and 1–3 value lines.
    Detail,
    /// Full-width value (disc parked off-panel), optional baseline label.
    Value,
    /// The auto-inserted mid-flow `Confirm?` early exit.
    Confirm,
    /// Endings and other input-dead screens.
    Status,
    /// A legacy 16×4 text page shown through the pixel engine.
    Legacy,
}

impl Kind {
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Hero => b'H',
            Self::Detail => b'D',
            Self::Value => b'V',
            Self::Confirm => b'C',
            Self::Status => b'S',
            Self::Legacy => b'L',
        }
    }

    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            b'H' => Some(Self::Hero),
            b'D' => Some(Self::Detail),
            b'V' => Some(Self::Value),
            b'C' => Some(Self::Confirm),
            b'S' => Some(Self::Status),
            b'L' => Some(Self::Legacy),
            _ => None,
        }
    }

    /// Kinds that may arm hold-right-to-sign.
    #[must_use]
    pub const fn may_commit(self) -> bool {
        matches!(self, Self::Hero | Self::Confirm)
    }

    /// Kinds that count as "details" for the `Confirm?` insertion rule.
    #[must_use]
    pub const fn is_detail_like(self) -> bool {
        matches!(self, Self::Detail | Self::Value | Self::Legacy)
    }
}

/// Disc art (record byte 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    Safe,
    Chain,
    Fingerprint,
    Wallet,
    /// The ether mark on the mono body (ETH / WETH; a tinted disc for a
    /// token without logo art).
    Eth,
    Usdc,
    Usdt,
    Dai,
    /// The blind-signing mark.
    Blind,
    /// The slot-rotation mark.
    Rotate,
    /// The CoW Swap family: the navy cow head on the `#65D9FF` brand disc.
    Cowswap,
    None,
}

impl Icon {
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Safe => b'S',
            Self::Chain => b'N',
            Self::Fingerprint => b'F',
            Self::Wallet => b'W',
            Self::Eth => b'E',
            Self::Usdc => b'U',
            Self::Usdt => b'T',
            Self::Dai => b'D',
            Self::Blind => b'B',
            Self::Rotate => b'R',
            Self::Cowswap => b'C',
            Self::None => b'-',
        }
    }

    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            b'S' => Some(Self::Safe),
            b'N' => Some(Self::Chain),
            b'F' => Some(Self::Fingerprint),
            b'W' => Some(Self::Wallet),
            b'E' => Some(Self::Eth),
            b'U' => Some(Self::Usdc),
            b'T' => Some(Self::Usdt),
            b'D' => Some(Self::Dai),
            b'B' => Some(Self::Blind),
            b'R' => Some(Self::Rotate),
            b'C' => Some(Self::Cowswap),
            b'-' => Some(Self::None),
            _ => None,
        }
    }
}

/// A family's disc: the art and, optionally, the placeholder ramp it is
/// tinted with (`None` = the icon's own look).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Look {
    pub icon: Icon,
    pub tint: Option<u8>,
}

impl Look {
    /// The Safe family's disc (untinted — its records predate the tint).
    pub const SAFE: Self = Self { icon: Icon::Safe, tint: None };
    /// The CoW Swap family's branded disc.
    pub const COWSWAP: Self = Self { icon: Icon::Cowswap, tint: None };

    #[must_use]
    pub const fn plain(icon: Icon) -> Self {
        Self { icon, tint: None }
    }
}

/// `colors.placeholder_index(key)` for a string key: CRC-32 (IEEE) of the
/// ASCII-uppercased bytes, modulo the fourteen ramps — so the same token
/// (contract address, or symbol) always wears the same ramp as on the
/// design reference.
#[must_use]
pub fn placeholder_ramp(key: &[u8]) -> u8 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in key {
        crc ^= u32::from(b.to_ascii_uppercase());
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    ((!crc) % u32::from(N_RAMPS)) as u8
}

/// Which column the disc docks on (record byte 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
    None,
}

impl Side {
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Left => b'L',
            Self::Right => b'R',
            Self::None => b'-',
        }
    }

    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            b'L' => Some(Self::Left),
            b'R' => Some(Self::Right),
            b'-' => Some(Self::None),
            _ => None,
        }
    }
}

/// Type tier of the value lines (record bytes 3..5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    T22,
    T28,
    T32,
    T36,
}

impl Tier {
    /// Pixel size.
    #[must_use]
    pub const fn px(self) -> u8 {
        match self {
            Self::T22 => 22,
            Self::T28 => 28,
            Self::T32 => 32,
            Self::T36 => 36,
        }
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; 2] {
        match self {
            Self::T22 => *b"22",
            Self::T28 => *b"28",
            Self::T32 => *b"32",
            Self::T36 => *b"36",
        }
    }

    #[must_use]
    pub const fn from_bytes(b: [u8; 2]) -> Option<Self> {
        match &b {
            b"22" => Some(Self::T22),
            b"28" => Some(Self::T28),
            b"32" => Some(Self::T32),
            b"36" => Some(Self::T36),
            _ => None,
        }
    }

    /// Line leading per DESIGN.md: the size itself at 32/36, size + 8 below.
    #[must_use]
    pub const fn line_height(self) -> u8 {
        match self {
            Self::T22 => 30,
            Self::T32 => 32,
            Self::T28 | Self::T36 => 36,
        }
    }

    /// Maximum lines a screen may stack at this tier.
    #[must_use]
    pub const fn max_lines(self) -> usize {
        match self {
            Self::T22 => 3,
            Self::T28 => 2,
            Self::T32 | Self::T36 => 1,
        }
    }
}

/// Line weight (first byte of a line record).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Weight {
    Regular,
    /// A resolved name riding `SemiBold` over its address lines.
    SemiBold,
    /// `old ▸ new` transition row (the text holds `old|new`).
    Transition,
}

impl Weight {
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Regular => b'r',
            Self::SemiBold => b's',
            Self::Transition => b't',
        }
    }

    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            b'r' => Some(Self::Regular),
            b's' => Some(Self::SemiBold),
            b't' => Some(Self::Transition),
            _ => None,
        }
    }
}

/// Status-screen state colour (record byte 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Done,
    Failed,
    Warning,
    Awaiting,
    None,
}

impl State {
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Done => b'd',
            Self::Failed => b'f',
            Self::Warning => b'w',
            Self::Awaiting => b'a',
            Self::None => b'-',
        }
    }

    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            b'd' => Some(Self::Done),
            b'f' => Some(Self::Failed),
            b'w' => Some(Self::Warning),
            b'a' => Some(Self::Awaiting),
            b'-' => Some(Self::None),
            _ => None,
        }
    }
}

/// Status-screen result mark (record byte 8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultMark {
    Check,
    Cross,
    None,
}

impl ResultMark {
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Check => b'c',
            Self::Cross => b'x',
            Self::None => b'-',
        }
    }

    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            b'c' => Some(Self::Check),
            b'x' => Some(Self::Cross),
            b'-' => Some(Self::None),
            _ => None,
        }
    }
}

/// One 256-byte transcript record. See the module docs for the layout.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Screen(pub [u8; SCREEN_BYTES]);

impl core::fmt::Debug for Screen {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Screen(")?;
        for b in &self.0[..OFF_LINES] {
            write!(f, "{}", char::from(*b))?;
        }
        write!(f, " ...)")
    }
}

impl Screen {
    /// An all-space record — every field at its "none" value except `kind`,
    /// which is `L` with zero lines so a blank is still a well-formed record.
    pub const BLANK: Self = {
        let mut b = [b' '; SCREEN_BYTES];
        b[OFF_KIND] = b'L';
        b[OFF_ICON] = b'-';
        b[OFF_SIDE] = b'-';
        b[OFF_TIER] = b'-';
        b[OFF_TIER + 1] = b'-';
        b[OFF_COMMIT] = b'N';
        b[OFF_PULSE] = b'N';
        b[OFF_STATE] = b'-';
        b[OFF_RESULT] = b'-';
        b[OFF_NPAGES] = b'1';
        b[OFF_NLINES] = b'0';
        b[OFF_NLINES + 1] = b'0';
        let mut i = 0;
        while i < MAX_LINE_RECS {
            b[OFF_LINES + i * LINE_REC] = b'r';
            i += 1;
        }
        Self(b)
    };

    /// Wrap a legacy 16×4 page as a `Legacy` screen (byte-exact, invertible
    /// through [`Screen::legacy_page`]).
    #[must_use]
    pub fn legacy(page: &Page) -> Self {
        let mut s = Self::BLANK;
        s.0[OFF_KIND] = Kind::Legacy.as_byte();
        s.0[OFF_TIER] = b'2';
        s.0[OFF_TIER + 1] = b'2';
        s.0[OFF_NLINES] = b'4';
        for (i, row) in page.iter().enumerate() {
            let o = OFF_LINES + i * LINE_REC + 1;
            s.0[o..o + DISPLAY_COLS].copy_from_slice(row);
        }
        s
    }

    /// Recover the 16×4 page a `Legacy` screen wraps; `None` for other kinds.
    #[must_use]
    pub fn legacy_page(&self) -> Option<Page> {
        if self.kind() != Some(Kind::Legacy) {
            return None;
        }
        let mut page: Page = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
        for (i, row) in page.iter_mut().enumerate() {
            let o = OFF_LINES + i * LINE_REC + 1;
            row.copy_from_slice(&self.0[o..o + DISPLAY_COLS]);
        }
        Some(page)
    }

    #[must_use]
    pub fn kind(&self) -> Option<Kind> {
        Kind::from_byte(self.0[OFF_KIND])
    }

    #[must_use]
    pub fn icon(&self) -> Option<Icon> {
        Icon::from_byte(self.0[OFF_ICON])
    }

    /// The placeholder ramp the disc is tinted with; `None` = the icon's
    /// own look (also for a malformed byte — `is_well_formed` refuses those).
    #[must_use]
    pub fn tint(&self) -> Option<u8> {
        match self.0[OFF_TINT] {
            b @ b'a'..=b'z' if b - b'a' < N_RAMPS => Some(b - b'a'),
            _ => None,
        }
    }

    /// The disc look (icon + tint).
    #[must_use]
    pub fn look(&self) -> Option<Look> {
        Some(Look { icon: self.icon()?, tint: self.tint() })
    }

    #[must_use]
    pub fn side(&self) -> Option<Side> {
        Side::from_byte(self.0[OFF_SIDE])
    }

    #[must_use]
    pub fn tier(&self) -> Option<Tier> {
        Tier::from_bytes([self.0[OFF_TIER], self.0[OFF_TIER + 1]])
    }

    /// Whether hold-right-to-sign is armed on this screen. Read twice through
    /// `black_box` so a single-fault flip on the load cannot promote it.
    #[must_use]
    pub fn commit(&self) -> bool {
        let a = core::hint::black_box(self.0[OFF_COMMIT]) == b'Y';
        let b = core::hint::black_box(self.0[OFF_COMMIT]) == b'Y';
        a && b
    }

    #[must_use]
    pub fn pulse(&self) -> bool {
        self.0[OFF_PULSE] == b'Y'
    }

    #[must_use]
    pub fn state(&self) -> Option<State> {
        State::from_byte(self.0[OFF_STATE])
    }

    #[must_use]
    pub fn result(&self) -> Option<ResultMark> {
        ResultMark::from_byte(self.0[OFF_RESULT])
    }

    /// Number of pages (1 or 2); 0 if the byte is malformed.
    #[must_use]
    pub fn npages(&self) -> u8 {
        match self.0[OFF_NPAGES] {
            b'1' => 1,
            b'2' => 2,
            _ => 0,
        }
    }

    /// Number of lines on page `p` (0..=4); 0 for an out-of-range page.
    #[must_use]
    pub fn nlines(&self, p: u8) -> u8 {
        if usize::from(p) >= PAGES_PER_SCREEN {
            return 0;
        }
        let b = self.0[OFF_NLINES + usize::from(p)];
        if (b'0'..=b'4').contains(&b) {
            b - b'0'
        } else {
            0
        }
    }

    /// Trailing-space-trimmed id.
    #[must_use]
    pub fn id(&self) -> &[u8] {
        trim_end(&self.0[OFF_ID..OFF_ID + ID_LEN])
    }

    /// Trailing-space-trimmed label.
    #[must_use]
    pub fn label(&self) -> &[u8] {
        trim_end(&self.0[OFF_LABEL..OFF_LABEL + LABEL_LEN])
    }

    /// Trailing-space-trimmed caption.
    #[must_use]
    pub fn caption(&self) -> &[u8] {
        trim_end(&self.0[OFF_CAPTION..OFF_CAPTION + CAPTION_LEN])
    }

    /// Line `i` of page `p`: weight and trailing-space-trimmed text. `None`
    /// past `nlines(p)`. Legacy screens keep their 16 columns untrimmed on
    /// the right only as far as the renderer needs (trailing spaces carry no
    /// glyphs).
    #[must_use]
    pub fn line(&self, p: u8, i: u8) -> Option<(Weight, &[u8])> {
        if i >= self.nlines(p) {
            return None;
        }
        let rec = self.line_rec_index(p, i)?;
        let o = OFF_LINES + rec * LINE_REC;
        let w = Weight::from_byte(self.0[o])?;
        Some((w, trim_end(&self.0[o + 1..o + 1 + LINE_LEN])))
    }

    fn line_rec_index(&self, p: u8, i: u8) -> Option<usize> {
        let (p, i) = (usize::from(p), usize::from(i));
        let rec = if self.kind() == Some(Kind::Legacy) {
            if p != 0 || i >= LEGACY_LINES {
                return None;
            }
            i
        } else {
            if p >= PAGES_PER_SCREEN || i >= LINES_PER_PAGE {
                return None;
            }
            p * LINES_PER_PAGE + i
        };
        Some(rec)
    }

    /// Every byte is printable ASCII (`0x20..=0x7E`).
    #[must_use]
    pub fn is_printable_ascii(&self) -> bool {
        self.0.iter().all(|b| (0x20..=0x7E).contains(b))
    }

    /// Structural well-formedness: every enum byte decodes, page/line counts
    /// are in range for the kind, and `commit` only where the kind allows it.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        let Some(kind) = self.kind() else { return false };
        if self.icon().is_none()
            || self.side().is_none()
            || self.state().is_none()
            || self.result().is_none()
        {
            return false;
        }
        let t = self.0[OFF_TINT];
        if t != b' ' && !(b'a'..b'a' + N_RAMPS).contains(&t) {
            return false;
        }
        if t != b' ' && self.kind() == Some(Kind::Legacy) {
            return false;
        }
        let tier_ok = self.tier().is_some() || &self.0[OFF_TIER..OFF_TIER + 2] == b"--";
        if !tier_ok {
            return false;
        }
        if !matches!(self.0[OFF_COMMIT], b'Y' | b'N') || !matches!(self.0[OFF_PULSE], b'Y' | b'N') {
            return false;
        }
        if self.0[OFF_COMMIT] == b'Y' && !kind.may_commit() {
            return false;
        }
        let np = self.npages();
        if np == 0 {
            return false;
        }
        for p in 0..PAGES_PER_SCREEN {
            let b = self.0[OFF_NLINES + p];
            if !(b'0'..=b'4').contains(&b) {
                return false;
            }
        }
        let max = if kind == Kind::Legacy { LEGACY_LINES } else { LINES_PER_PAGE };
        if usize::from(self.nlines(0)) > max {
            return false;
        }
        if kind == Kind::Legacy && (np != 1 || self.nlines(1) != 0) {
            return false;
        }
        if np == 1 && self.nlines(1) != 0 {
            return false;
        }
        if np == 2 && (self.nlines(1) == 0 || usize::from(self.nlines(1)) > LINES_PER_PAGE) {
            return false;
        }
        for r in 0..MAX_LINE_RECS {
            if Weight::from_byte(self.0[OFF_LINES + r * LINE_REC]).is_none() {
                return false;
            }
        }
        self.is_printable_ascii()
    }
}

fn trim_end(b: &[u8]) -> &[u8] {
    let mut n = b.len();
    while n > 0 && b[n - 1] == b' ' {
        n -= 1;
    }
    &b[..n]
}

/// Constant-shape byte-exact comparison of two records (XOR fold over all
/// 256 bytes, no early exit).
#[must_use]
#[inline(never)]
pub fn screen_exact(a: &Screen, b: &Screen) -> bool {
    let mut acc: u8 = 0;
    for i in 0..SCREEN_BYTES {
        acc |= a.0[i] ^ b.0[i];
    }
    acc == 0
}

/// `screens[i]` exists and equals `expected` byte-for-byte.
#[must_use]
pub fn screen_at_matches(screens: &Screens, i: usize, expected: &Screen) -> bool {
    screens.as_slice().get(i).is_some_and(|s| screen_exact(s, expected))
}

/// Number of visible screens byte-equal to `expected`.
#[must_use]
pub fn exact_screen_occurrences(screens: &Screens, expected: &Screen) -> usize {
    screens.as_slice().iter().filter(|s| screen_exact(s, expected)).count()
}

/// Why a builder refused to produce a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildErr {
    /// A byte outside `0x20..=0x7E`.
    NonAscii,
    /// A field longer than its slot.
    TooLong,
    /// `commit` requested on a kind that cannot arm it.
    BadCommit,
    /// More lines than the page holds.
    TooManyLines,
    /// More pages than a screen holds, or a second page with no lines.
    BadPages,
    /// A screen with no page 0 content where one is required.
    Empty,
}

/// The only writer of [`Screen`] records.
pub struct ScreenBuilder {
    s: Screen,
    kind: Kind,
    lines: [u8; PAGES_PER_SCREEN],
    page: usize,
    err: Option<BuildErr>,
}

impl ScreenBuilder {
    fn new(kind: Kind, id: &[u8]) -> Self {
        let mut b = Self {
            s: Screen::BLANK,
            kind,
            lines: [0; PAGES_PER_SCREEN],
            page: 0,
            err: None,
        };
        b.s.0[OFF_KIND] = kind.as_byte();
        b.put(OFF_ID, ID_LEN, id);
        b
    }

    /// A hero ask: disc centred, caps caption on the band, commit armed.
    #[must_use]
    pub fn hero(id: &[u8], icon: Icon, caption: &[u8]) -> Self {
        let mut b = Self::new(Kind::Hero, id);
        b.s.0[OFF_ICON] = icon.as_byte();
        b.s.0[OFF_COMMIT] = b'Y';
        b.put(OFF_CAPTION, CAPTION_LEN, caption);
        b
    }

    /// A docked detail: disc on `side`, label under it, value lines.
    #[must_use]
    pub fn detail(id: &[u8], icon: Icon, side: Side, label: &[u8]) -> Self {
        let mut b = Self::new(Kind::Detail, id);
        b.s.0[OFF_ICON] = icon.as_byte();
        b.s.0[OFF_SIDE] = side.as_byte();
        b.put(OFF_LABEL, LABEL_LEN, label);
        b
    }

    /// A full-width value screen (disc parked off-panel), baseline label.
    #[must_use]
    pub fn value(id: &[u8], icon: Icon, label: &[u8]) -> Self {
        let mut b = Self::new(Kind::Value, id);
        b.s.0[OFF_ICON] = icon.as_byte();
        b.put(OFF_LABEL, LABEL_LEN, label);
        b
    }

    /// The mid-flow `Confirm?` early exit, commit armed.
    #[must_use]
    pub fn confirm(icon: Icon) -> Self {
        let mut b = Self::new(Kind::Confirm, b"CONFIRM");
        b.s.0[OFF_ICON] = icon.as_byte();
        b.s.0[OFF_COMMIT] = b'Y';
        b.s.0[OFF_TIER] = b'3';
        b.s.0[OFF_TIER + 1] = b'6';
        b.put(OFF_CAPTION, CAPTION_LEN, b"CONFIRM?");
        b
    }

    /// An input-dead status / ending screen.
    #[must_use]
    pub fn status(id: &[u8], icon: Icon, caption: &[u8], state: State, result: ResultMark) -> Self {
        let mut b = Self::new(Kind::Status, id);
        b.s.0[OFF_ICON] = icon.as_byte();
        b.s.0[OFF_STATE] = state.as_byte();
        b.s.0[OFF_RESULT] = result.as_byte();
        b.put(OFF_CAPTION, CAPTION_LEN, caption);
        b
    }

    /// Set the value tier.
    #[must_use]
    pub fn tier(mut self, t: Tier) -> Self {
        let b = t.as_bytes();
        self.s.0[OFF_TIER] = b[0];
        self.s.0[OFF_TIER + 1] = b[1];
        self
    }

    /// Tint the disc with placeholder ramp `ramp` (`0..N_RAMPS`).
    #[must_use]
    pub fn tint(mut self, ramp: u8) -> Self {
        if ramp >= N_RAMPS {
            self.fail(BuildErr::NonAscii);
        } else {
            self.s.0[OFF_TINT] = b'a' + ramp;
        }
        self
    }

    /// Apply a [`Look`]'s tint (its icon is passed to the constructor).
    #[must_use]
    pub fn look_tint(self, look: Look) -> Self {
        match look.tint {
            Some(r) => self.tint(r),
            None => self,
        }
    }

    /// Warning rings around the disc.
    #[must_use]
    pub fn pulse(mut self) -> Self {
        self.s.0[OFF_PULSE] = b'Y';
        self
    }

    /// Append a value line to the current page.
    #[must_use]
    pub fn line(mut self, text: &[u8], w: Weight) -> Self {
        self.push_line(text, w);
        self
    }

    /// Start the second page.
    #[must_use]
    pub fn next_page(mut self) -> Self {
        if self.page + 1 >= PAGES_PER_SCREEN {
            self.fail(BuildErr::BadPages);
        } else {
            self.page += 1;
        }
        self
    }

    /// Validate and produce the record.
    pub fn finish(self) -> Result<Screen, BuildErr> {
        if let Some(e) = self.err {
            return Err(e);
        }
        let mut s = self.s;
        let np = self.page + 1;
        if np == 2 && self.lines[1] == 0 {
            return Err(BuildErr::BadPages);
        }
        if matches!(self.kind, Kind::Detail | Kind::Value) && self.lines[0] == 0 {
            return Err(BuildErr::Empty);
        }
        s.0[OFF_NPAGES] = b'0' + u8::try_from(np).unwrap_or(1);
        s.0[OFF_NLINES] = b'0' + self.lines[0];
        s.0[OFF_NLINES + 1] = b'0' + self.lines[1];
        if !s.is_well_formed() {
            // Every field was written by this builder; the only way to get
            // here is a lifecycle bug, which must surface as a refusal.
            return Err(BuildErr::NonAscii);
        }
        Ok(s)
    }

    fn push_line(&mut self, text: &[u8], w: Weight) {
        if self.lines[self.page] as usize >= LINES_PER_PAGE {
            self.fail(BuildErr::TooManyLines);
            return;
        }
        let rec = self.page * LINES_PER_PAGE + usize::from(self.lines[self.page]);
        let o = OFF_LINES + rec * LINE_REC;
        self.s.0[o] = w.as_byte();
        if self.put(o + 1, LINE_LEN, text) {
            self.lines[self.page] += 1;
        }
    }

    /// Copy `src` into the slot, space-padded; records the first error.
    fn put(&mut self, off: usize, len: usize, src: &[u8]) -> bool {
        if src.len() > len {
            self.fail(BuildErr::TooLong);
            return false;
        }
        if !src.iter().all(|b| (0x20..=0x7E).contains(b)) {
            self.fail(BuildErr::NonAscii);
            return false;
        }
        self.s.0[off..off + len].fill(b' ');
        self.s.0[off..off + src.len()].copy_from_slice(src);
        true
    }

    fn fail(&mut self, e: BuildErr) {
        if self.err.is_none() {
            self.err = Some(e);
        }
    }
}

/// A fixed-capacity transcript of up to [`MAX_SCREENS`] screens.
///
/// Same ownership rules as `Pages`: the buffer is always fully allocated,
/// only `len` changes, callers never index past `len`. Intended to live in a
/// single static in the secure world (10 KB is too large for the sign
/// handler's stack).
///
/// `#[repr(C)]` with alignment 1 (the length is a little-endian byte
/// quadruple, not a `usize`) and every bit pattern valid, so the secure world
/// can view a byte scratch region as a `Screens` without a copy — the
/// transcript overlays the unused tail of the shared sign snapshot buffer
/// instead of costing its own BSS.
#[repr(C)]
pub struct Screens {
    pub buf: [Screen; MAX_SCREENS],
    len_le: [u8; 4],
}

/// Size of a [`Screens`] in bytes (for the byte-view overlay).
pub const SCREENS_BYTES: usize = MAX_SCREENS * SCREEN_BYTES + 4;
const _: () = assert!(core::mem::size_of::<Screens>() == SCREENS_BYTES);
const _: () = assert!(core::mem::align_of::<Screens>() == 1);

impl Screens {
    /// All-blank, zero visible screens.
    #[must_use]
    pub const fn blank() -> Self {
        Self {
            buf: [Screen::BLANK; MAX_SCREENS],
            len_le: [0; 4],
        }
    }

    /// Number of visible screens (clamped to the capacity).
    #[must_use]
    pub fn len(&self) -> usize {
        (u32::from_le_bytes(self.len_le) as usize).min(MAX_SCREENS)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Set the visible length (clamped to the capacity).
    pub fn set_len(&mut self, n: usize) {
        self.len_le = (n.min(MAX_SCREENS) as u32).to_le_bytes();
    }

    /// Visible screens.
    #[must_use]
    pub fn as_slice(&self) -> &[Screen] {
        &self.buf[..self.len()]
    }

    /// Append a screen; `Err` when full (the caller refuses to sign).
    pub fn push(&mut self, s: &Screen) -> Result<usize, ()> {
        let i = self.len();
        if i >= MAX_SCREENS {
            return Err(());
        }
        self.buf[i] = *s;
        self.set_len(i + 1);
        Ok(i)
    }

    /// Append a legacy 16×4 page wrapped as a `Legacy` screen.
    pub fn push_legacy(&mut self, page: &Page) -> Result<usize, ()> {
        self.push(&Screen::legacy(page))
    }

    /// Insert the mid-flow `Confirm?` per DESIGN.md § Flow shape: when the
    /// transcript carries at least seven detail-like screens, a `Confirm`
    /// screen becomes index 5 (the sixth screen). Returns the index inserted
    /// at, `None` when the rule does not apply, `Err` when the buffer is full
    /// or a confirm screen is already present.
    pub fn insert_confirm(&mut self, icon: Icon) -> Result<Option<usize>, ()> {
        self.insert_confirm_look(Look::plain(icon))
    }

    /// [`Self::insert_confirm`] with a tinted disc.
    pub fn insert_confirm_look(&mut self, look: Look) -> Result<Option<usize>, ()> {
        const CONFIRM_INDEX: usize = 5;
        const CONFIRM_MIN_DETAILS: usize = 7;
        let icon = look.icon;
        let visible = self.as_slice();
        if visible.iter().any(|s| s.kind() == Some(Kind::Confirm)) {
            return Err(());
        }
        let details = visible
            .iter()
            .filter(|s| s.kind().is_some_and(Kind::is_detail_like))
            .count();
        if details < CONFIRM_MIN_DETAILS || visible.len() <= CONFIRM_INDEX {
            return Ok(None);
        }
        let len = self.len();
        if len >= MAX_SCREENS {
            return Err(());
        }
        let c = ScreenBuilder::confirm(icon).look_tint(look).finish().map_err(|_| ())?;
        self.buf.copy_within(CONFIRM_INDEX..len, CONFIRM_INDEX + 1);
        self.buf[CONFIRM_INDEX] = c;
        self.set_len(len + 1);
        Ok(Some(CONFIRM_INDEX))
    }

    /// Insert `s` right after the opening hero (index 1) — the batch
    /// position screen a batch member's own flow opens with. Every detail
    /// that moves down one index swaps its disc column, so the transcript
    /// keeps alternating (DESIGN.md `normalize_screens`). `Err` when there is
    /// no hero at index 0 or the buffer is full.
    pub fn insert_after_hero(&mut self, s: &Screen) -> Result<(), ()> {
        let len = self.len();
        if len == 0 || len >= MAX_SCREENS || self.buf[0].kind() != Some(Kind::Hero) {
            return Err(());
        }
        self.buf.copy_within(1..len, 2);
        self.buf[1] = *s;
        for moved in &mut self.buf[2..=len] {
            let flipped = match moved.side() {
                Some(Side::Left) => Side::Right,
                Some(Side::Right) => Side::Left,
                _ => continue,
            };
            moved.0[OFF_SIDE] = flipped.as_byte();
        }
        self.set_len(len + 1);
        Ok(())
    }

    /// Volatile-poison every byte of the fixed buffer, then reset `len`
    /// (written last, so a skipped re-emit exposes a zero count).
    #[inline(never)]
    pub fn volatile_poison_and_reset(&mut self) {
        for s in &mut self.buf {
            volatile_poison_bytes(&mut s.0);
        }
        // Length last: poison the bytes, then volatile-zero the quadruple.
        volatile_poison_bytes(&mut self.len_le);
        volatile_zero_bytes(&mut self.len_le);
    }

    /// Readback used before granting the reset CFI step.
    #[must_use]
    #[inline(never)]
    pub fn is_transcript_poisoned(&self) -> bool {
        self.len_le == [0; 4] && self.buf.iter().all(|s| s.0.iter().all(|b| *b == TRANSCRIPT_POISON))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detail(id: &[u8], n: usize) -> Screen {
        let mut b = ScreenBuilder::detail(id, Icon::Safe, Side::Left, b"LABEL").tier(Tier::T22);
        for _ in 0..n {
            b = b.line(b"0x123", Weight::Regular);
        }
        b.finish().unwrap()
    }

    #[test]
    fn blank_is_well_formed_and_ascii() {
        assert!(Screen::BLANK.is_well_formed());
        assert!(Screen::BLANK.is_printable_ascii());
        assert_eq!(Screen::BLANK.kind(), Some(Kind::Legacy));
        assert_eq!(Screen::BLANK.nlines(0), 0);
    }

    #[test]
    fn hero_round_trip() {
        let s = ScreenBuilder::hero(b"APPROVE", Icon::Safe, b"APPROVE SAFE TX?").finish().unwrap();
        assert_eq!(s.kind(), Some(Kind::Hero));
        assert!(s.commit());
        assert_eq!(s.caption(), b"APPROVE SAFE TX?");
        assert_eq!(s.id(), b"APPROVE");
        assert!(s.is_well_formed());
    }

    #[test]
    fn detail_lines_and_pages() {
        let s = ScreenBuilder::detail(b"APPDATA", Icon::Safe, Side::Right, b"APP DATA")
            .tier(Tier::T22)
            .line(b"0x0011223344556677", Weight::Regular)
            .line(b"8899aabbccddeeff", Weight::Regular)
            .next_page()
            .line(b"0011223344556677", Weight::Regular)
            .line(b"8899aabbccddeeff", Weight::Regular)
            .finish()
            .unwrap();
        assert_eq!(s.npages(), 2);
        assert_eq!(s.nlines(0), 2);
        assert_eq!(s.nlines(1), 2);
        assert_eq!(s.line(1, 0), Some((Weight::Regular, &b"0011223344556677"[..])));
        assert_eq!(s.line(1, 2), None);
        assert_eq!(s.line(0, 1), Some((Weight::Regular, &b"8899aabbccddeeff"[..])));
        assert!(!s.commit());
    }

    #[test]
    fn builder_refuses_non_ascii_overlong_and_extra_lines() {
        let e = ScreenBuilder::detail(b"X", Icon::None, Side::Left, b"L")
            .line(b"caf\xc3\xa9", Weight::Regular)
            .finish()
            .unwrap_err();
        assert_eq!(e, BuildErr::NonAscii);
        let e = ScreenBuilder::detail(b"X", Icon::None, Side::Left, b"L")
            .line(&[b'a'; LINE_LEN + 1], Weight::Regular)
            .finish()
            .unwrap_err();
        assert_eq!(e, BuildErr::TooLong);
        let e = ScreenBuilder::detail(b"X", Icon::None, Side::Left, b"L")
            .line(b"1", Weight::Regular)
            .line(b"2", Weight::Regular)
            .line(b"3", Weight::Regular)
            .line(b"4", Weight::Regular)
            .finish()
            .unwrap_err();
        assert_eq!(e, BuildErr::TooManyLines);
        let e = ScreenBuilder::detail(b"X", Icon::None, Side::Left, b"L").finish().unwrap_err();
        assert_eq!(e, BuildErr::Empty);
        let e = ScreenBuilder::detail(b"X", Icon::None, Side::Left, b"L")
            .line(b"1", Weight::Regular)
            .next_page()
            .finish()
            .unwrap_err();
        assert_eq!(e, BuildErr::BadPages);
        let e = ScreenBuilder::hero(b"TOO-LONG-ID", Icon::None, b"ASK?").finish().unwrap_err();
        assert_eq!(e, BuildErr::TooLong);
    }

    #[test]
    fn commit_only_on_hero_and_confirm() {
        let mut s = detail(b"D", 1);
        assert!(s.is_well_formed());
        s.0[OFF_COMMIT] = b'Y';
        assert!(!s.is_well_formed());
        assert!(ScreenBuilder::confirm(Icon::Safe).finish().unwrap().commit());
    }

    #[test]
    fn legacy_wrap_is_byte_exact_and_invertible() {
        let mut page: Page = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
        page[0][..5].copy_from_slice(b"Safe:");
        page[1].copy_from_slice(b"0x5aFE0000000000");
        page[3][..8].copy_from_slice(b"01  2/15");
        let s = Screen::legacy(&page);
        assert!(s.is_well_formed());
        assert_eq!(s.kind(), Some(Kind::Legacy));
        assert_eq!(s.nlines(0), 4);
        assert_eq!(s.line(0, 1), Some((Weight::Regular, &b"0x5aFE0000000000"[..])));
        assert_eq!(s.legacy_page(), Some(page));
        assert!(screen_exact(&s, &Screen::legacy(&page)));
        assert!(detail(b"D", 1).legacy_page().is_none());
    }

    #[test]
    fn exact_compare_and_occurrences() {
        let a = detail(b"A", 1);
        let mut b = a;
        assert!(screen_exact(&a, &b));
        b.0[SCREEN_BYTES - 1] = b'x';
        assert!(!screen_exact(&a, &b));
        let mut ss = Screens::blank();
        ss.push(&a).unwrap();
        ss.push(&b).unwrap();
        ss.push(&a).unwrap();
        assert_eq!(exact_screen_occurrences(&ss, &a), 2);
        assert!(screen_at_matches(&ss, 1, &b));
        assert!(!screen_at_matches(&ss, 3, &b));
    }

    #[test]
    fn push_refuses_at_capacity() {
        let mut ss = Screens::blank();
        for i in 0..MAX_SCREENS {
            assert_eq!(ss.push(&detail(b"D", 1)), Ok(i));
        }
        assert!(ss.push(&detail(b"D", 1)).is_err());
        assert_eq!(ss.as_slice().len(), MAX_SCREENS);
    }

    #[test]
    fn poison_round_trip() {
        let mut ss = Screens::blank();
        ss.push(&detail(b"D", 1)).unwrap();
        assert!(!ss.is_transcript_poisoned());
        ss.volatile_poison_and_reset();
        assert!(ss.is_transcript_poisoned());
        assert_eq!(ss.len(), 0);
        ss.push(&detail(b"D", 1)).unwrap();
        assert!(!ss.is_transcript_poisoned());
        assert!(ss.as_slice()[0].is_printable_ascii());
    }

    fn flow(details: usize) -> Screens {
        let mut ss = Screens::blank();
        ss.push(&ScreenBuilder::hero(b"ASK", Icon::Safe, b"ASK?").finish().unwrap()).unwrap();
        for _ in 0..details {
            ss.push(&detail(b"D", 1)).unwrap();
        }
        ss.push(&ScreenBuilder::hero(b"ASK", Icon::Safe, b"ASK?").finish().unwrap()).unwrap();
        ss
    }

    #[test]
    fn confirm_inserted_at_index_five_only_with_seven_details() {
        let mut six = flow(6);
        assert_eq!(six.insert_confirm(Icon::Safe), Ok(None));
        assert_eq!(six.len(), 8);

        let mut seven = flow(7);
        assert_eq!(seven.insert_confirm(Icon::Safe), Ok(Some(5)));
        assert_eq!(seven.len(), 10);
        assert_eq!(seven.as_slice()[5].kind(), Some(Kind::Confirm));
        assert!(seven.as_slice()[5].commit());
        assert_eq!(seven.as_slice()[9].kind(), Some(Kind::Hero));
        // Doubling is refused.
        assert!(seven.insert_confirm(Icon::Safe).is_err());
        // Legacy screens count as details.
        let mut legacy = Screens::blank();
        legacy.push(&ScreenBuilder::hero(b"ASK", Icon::Safe, b"ASK?").finish().unwrap()).unwrap();
        let page: Page = [[b'a'; DISPLAY_COLS]; DISPLAY_ROWS];
        for _ in 0..7 {
            legacy.push_legacy(&page).unwrap();
        }
        assert_eq!(legacy.insert_confirm(Icon::Safe), Ok(Some(5)));
    }

    #[test]
    fn insert_after_hero_keeps_the_disc_alternating() {
        let mut ss = Screens::blank();
        ss.push(&ScreenBuilder::hero(b"ASK", Icon::Eth, b"ASK?").finish().unwrap()).unwrap();
        for (i, side) in [Side::Right, Side::Left, Side::Right].into_iter().enumerate() {
            let id = [b'D', b'0' + i as u8];
            ss.push(&ScreenBuilder::detail(&id, Icon::Eth, side, b"L").line(b"x", Weight::Regular).finish().unwrap()).unwrap();
        }
        let batch = ScreenBuilder::detail(b"BATCH", Icon::Eth, Side::Right, b"BATCH").line(b"Tx 1 of 3", Weight::Regular).finish().unwrap();
        ss.insert_after_hero(&batch).unwrap();
        let sides: [Option<Side>; 5] = core::array::from_fn(|i| ss.as_slice()[i].side());
        assert_eq!(sides, [Some(Side::None), Some(Side::Right), Some(Side::Left), Some(Side::Right), Some(Side::Left)]);
        assert_eq!(ss.as_slice()[1].id(), b"BATCH");
        let mut empty = Screens::blank();
        assert!(empty.insert_after_hero(&batch).is_err());
    }

    #[test]
    fn confirm_insert_refuses_when_full() {
        let mut ss = flow(MAX_SCREENS - 2);
        assert_eq!(ss.len(), MAX_SCREENS);
        assert!(ss.insert_confirm(Icon::Safe).is_err());
    }

    #[test]
    fn placeholder_ramp_matches_the_reference_hash() {
        // `zlib.crc32(key.upper().encode()) % 14` on the design reference.
        assert_eq!(placeholder_ramp(b"0x3cA9e5F1b72D04E8a6c1D9B3f57E28a0C4d6B1e9"), 1);
        assert_eq!(placeholder_ramp(b"TOSHI"), 5);
        assert_eq!(placeholder_ramp(b"0x9E3b5c0f7A1d24e86C3F0b7d5a2E4c6F8b1D3a7c"), 6);
    }

    #[test]
    fn tint_round_trips_and_keeps_untinted_records_unchanged() {
        let plain = ScreenBuilder::hero(b"ASK", Icon::Eth, b"ASK?").finish().unwrap();
        assert_eq!(plain.tint(), None);
        let t = ScreenBuilder::hero(b"ASK", Icon::Eth, b"ASK?").tint(7).finish().unwrap();
        assert_eq!(t.tint(), Some(7));
        assert_eq!(t.look(), Some(Look { icon: Icon::Eth, tint: Some(7) }));
        assert!(t.is_well_formed());
        let mut diff = 0;
        for i in 0..SCREEN_BYTES {
            diff += usize::from(plain.0[i] != t.0[i]);
        }
        assert_eq!(diff, 1);
        assert!(ScreenBuilder::hero(b"ASK", Icon::Eth, b"ASK?").tint(N_RAMPS).finish().is_err());
        let mut bad = t;
        bad.0[OFF_TINT] = b'z';
        assert!(!bad.is_well_formed());
        for icon in [Icon::Eth, Icon::Usdc, Icon::Usdt, Icon::Dai, Icon::Blind, Icon::Rotate] {
            assert_eq!(Icon::from_byte(icon.as_byte()), Some(icon));
        }
    }
}

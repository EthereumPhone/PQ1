//! Port step 4 — the screens outside the sign dialog as pixel records.
//!
//! The firmware's status surface is ~300 `show_status(title, sub)` /
//! `show_progress(title, pct)` call sites plus a handful of dialogs of its
//! own (PIN entry, the seed wizard, the boot fingerprint). The call sites
//! keep deciding *what* is shown; this module maps each one to the design's
//! screen for it, the same "one rule" as the sign families:
//!
//! * a **verdict** where the design has one (DESIGN.md § Verdict screens):
//!   LOCKED / UNLOCKED (the padlock), WRONG PIN / PINS DIFFER (the PIN
//!   pill), WALLET WIPED (triangle + brush), TAMPER DETECTED, RNG FAILED
//!   (the die), BACKUP OK / NO MATCH (the shield), CANCELED / SIGNED (the
//!   result ring), FACTORY SIGNING (the gear);
//! * a **busy** screen (the film's caption) for work in progress;
//! * the **idle** screen (READY) at rest;
//! * everything else — every refusal and error — the detail-grid **notice**
//!   (the `sig_error` verdict: the triangle docked left, the title as its
//!   label, the reason as the detail text). Nothing a call site says is
//!   dropped: the notice carries the title and the full reason.
//!
//! Pure (no hardware): the classifier, the record builders and the caption
//! charset mapping are host-tested (`ui_px_status_map` in `main.rs`).

use pqsigner_ui_px::fit::{fit_tier, Region};
use pqsigner_ui_px::screen::{CAPTION_LEN, LABEL_LEN, LINE_LEN, MAX_ENTRY_SLOTS};
use pqsigner_ui_px::{Icon, ResultMark, Screen, ScreenBuilder, Side, State, Tier, Weight};

/// What a legacy status call becomes.
#[derive(Clone, Copy, Debug)]
pub enum Status {
    /// Present the record (a verdict, a notice, the idle screen).
    Show(Screen),
    /// Work in progress: the busy look captioned by the record.
    Busy(Screen),
    /// A prompt that only names the PIN row that follows it (the row paints
    /// at once; the prompt itself is its caption).
    PinPrompt(&'static [u8]),
}

/// The caption face (18 px) carries caps, digits and `!%&'()+,-./:?`.
fn caption_byte(b: u8) -> u8 {
    match b {
        b'a'..=b'z' => b - 32,
        b'A'..=b'Z' | b'0'..=b'9' | b' ' | b'!' | b'%' | b'&' | b'\'' | b'(' | b')' | b'+' | b',' | b'-' | b'.' | b'/'
        | b':' | b'?' => b,
        _ => b'-',
    }
}

/// `src` as caps in the caption face, at most `N` bytes (a longer title is
/// cut at a word boundary — captions are status text, never a value).
fn caps<const N: usize>(src: &[u8]) -> ([u8; N], usize) {
    let mut out = [b' '; N];
    let mut n = src.len().min(N);
    if src.len() > N {
        // Cut at the last space that fits, if any.
        if let Some(sp) = src[..N].iter().rposition(|&b| b == b' ') {
            n = sp;
        }
    }
    for (o, &b) in out.iter_mut().zip(&src[..n]) {
        *o = caption_byte(b);
    }
    // Trim the tail.
    while n > 0 && out[n - 1] == b' ' {
        n -= 1;
    }
    (out, n)
}

/// A verdict record, the caption built from `parts` joined by " - ".
fn verdict(id: &[u8], icon: Icon, state: State, result: ResultMark, parts: &[&[u8]]) -> Screen {
    let mut buf = [b' '; CAPTION_LEN];
    let mut n = 0usize;
    for (i, p) in parts.iter().filter(|p| !p.is_empty()).enumerate() {
        let sep: &[u8] = if i == 0 { b"" } else { b" - " };
        for &b in sep.iter().chain(p.iter()) {
            if n < CAPTION_LEN {
                buf[n] = b;
                n += 1;
            }
        }
    }
    let (cap, cn) = caps::<CAPTION_LEN>(&buf[..n]);
    ScreenBuilder::verdict(id, icon, &cap[..cn], state, result)
        .finish()
        .unwrap_or(Screen::BLANK)
}

/// The detail-grid notice: the triangle docked left, `title` as its label
/// (caps; a title longer than a label becomes the first line under the
/// label `ERROR`), the reason as up to three detail lines at the largest
/// tier that fits (split on spaces, never truncated — a reason that cannot
/// fit is split into as many lines as it needs, the tail kept whole).
#[must_use]
pub fn notice(title: &[u8], sub: &[u8]) -> Screen {
    let (label, ln) = caps::<LABEL_LEN>(title);
    let title_fits = title.len() <= LABEL_LEN;
    let mut lines: [[u8; LINE_LEN]; 3] = [[b' '; LINE_LEN]; 3];
    let mut lens = [0usize; 3];
    let mut nl = 0usize;
    let mut push = |text: &[u8], nl: &mut usize| {
        // Greedy word wrap at the docked 22 px budget (21 characters).
        let mut rest = text;
        while !rest.is_empty() && *nl < 3 {
            let budget = Region::Docked.chars(Tier::T22).min(LINE_LEN);
            let take = if rest.len() <= budget {
                rest.len()
            } else {
                rest[..budget].iter().rposition(|&b| b == b' ').filter(|&p| p > 0).unwrap_or(budget)
            };
            let (head, tail) = rest.split_at(take);
            let mut h = head;
            while h.last() == Some(&b' ') {
                h = &h[..h.len() - 1];
            }
            for (i, &b) in h.iter().enumerate() {
                lines[*nl][i] = if (0x20..=0x7E).contains(&b) { b } else { b'?' };
            }
            lens[*nl] = h.len();
            *nl += 1;
            rest = tail;
            while rest.first() == Some(&b' ') {
                rest = &rest[1..];
            }
        }
    };
    if !title_fits {
        push(title, &mut nl);
    }
    push(sub, &mut nl);
    let label: &[u8] = if title_fits && ln > 0 { &label[..ln] } else { b"ERROR" };
    let ins: [(&[u8], Weight); 3] = core::array::from_fn(|i| (&lines[i][..lens[i]], Weight::Regular));
    let n = nl.max(1);
    let tier = fit_tier(&ins[..n], Region::Docked).unwrap_or(Tier::T22);
    let mut b = ScreenBuilder::verdict(b"NOTICE", Icon::Alert, b"", State::Failed, ResultMark::None)
        .docked(Side::Left, label)
        .tier(tier);
    for (text, w) in &ins[..nl] {
        b = b.line(text, *w);
    }
    if nl == 0 {
        b = b.line(b"-", Weight::Regular);
    }
    b.finish().unwrap_or(Screen::BLANK)
}

/// A busy record: the film's caption is the record's caption.
#[must_use]
pub fn busy(title: &[u8]) -> Screen {
    let (cap, n) = caps::<CAPTION_LEN>(title);
    ScreenBuilder::status(b"BUSY", Icon::Eth, &cap[..n], State::Awaiting, ResultMark::None)
        .finish()
        .unwrap_or(Screen::BLANK)
}

/// The idle screen: the mono token at rest over READY.
#[must_use]
pub fn idle() -> Screen {
    ScreenBuilder::status(b"READY", Icon::Eth, b"READY", State::None, ResultMark::None)
        .finish()
        .unwrap_or(Screen::BLANK)
}

/// The boot splash: the mono token over the product's name.
#[must_use]
pub fn splash() -> Screen {
    ScreenBuilder::status(b"SPLASH", Icon::Eth, b"PQ1", State::None, ResultMark::None)
        .finish()
        .unwrap_or(Screen::BLANK)
}

fn eq(a: &str, b: &str) -> bool {
    a.trim() == b
}

/// Map a legacy `show_status(title, sub)` to its screen.
#[must_use]
pub fn classify(title: &str, sub: &str) -> Status {
    let t = title.trim();
    let s = sub.trim();
    let tb = t.as_bytes();
    let sb = s.as_bytes();
    let v = |id: &[u8], icon, state, result, parts: &[&[u8]]| Status::Show(verdict(id, icon, state, result, parts));
    match t {
        // ---- PIN ----------------------------------------------------------
        "Enter PIN" => Status::PinPrompt(b"ENTER PIN"),
        "Set new PIN" => Status::PinPrompt(b"SET NEW PIN"),
        "Confirm PIN" => Status::PinPrompt(b"CONFIRM PIN"),
        "Duress PIN" => Status::PinPrompt(b"SET DURESS PIN"),
        "Verifying..." => v(b"CHECKPIN", Icon::Pill, State::Awaiting, ResultMark::None, &[b"CHECKING PIN"]),
        "Wrong PIN" => v(b"WRONGPIN", Icon::Pill, State::Failed, ResultMark::None, &[b"WRONG PIN"]),
        "PIN mismatch" | "PINs differ" => v(b"PINDIFF", Icon::Pill, State::Failed, ResultMark::None, &[b"PINS DIFFER"]),
        "Same as main" => v(b"PINSAME", Icon::Pill, State::Failed, ResultMark::None, &[b"SAME AS MAIN PIN"]),
        "PIN locked" => v(b"PINLOCK", Icon::Lock, State::Failed, ResultMark::None, &[b"PIN LOCKED", sb]),
        "Locked" | "Idle" => v(b"LOCKED", Icon::Lock, State::Failed, ResultMark::None, &[b"LOCKED", if eq(s, "retry...") { b"" } else { sb }]),
        "Unlocked" => v(b"UNLOCKED", Icon::Unlock, State::Done, ResultMark::None, &[b"UNLOCKED"]),
        "LAST ATTEMPT" => v(b"LASTTRY", Icon::Heart, State::Failed, ResultMark::None, &[b"LAST ATTEMPT", b"WIPES ON FAIL"]),
        // ---- rest / outcomes --------------------------------------------------
        "PQSigner OS" if eq(s, "Ready") => Status::Show(idle()),
        "Cancelled" | "Declined" => v(b"CANCELED", Icon::ResultRing, State::Failed, ResultMark::Cross, &[b"CANCELED"]),
        "Signed" => v(b"SIGNED", Icon::ResultRing, State::Done, ResultMark::Check, &[b"SIGNED"]),
        // ---- wipe / tamper / RNG / factory ----------------------------------
        // Destructive work follows at once: shown at rest, never delayed by
        // an entrance.
        "WIPING" => Status::Busy(verdict(b"WIPING", Icon::Wipe, State::Warning, ResultMark::None, &[b"WIPING", b"DO NOT POWER OFF"])),
        "WALLET WIPED" | "WIPED" => v(b"WIPED", Icon::Wipe, State::Failed, ResultMark::None, &[b"WALLET WIPED"]),
        "TAMPER DETECT" => v(b"TAMPER", Icon::Alert, State::Failed, ResultMark::None, &[b"TAMPER DETECTED"]),
        "RNG failed" => v(b"RNG", Icon::Die, State::Failed, ResultMark::None, &[b"RNG FAILED"]),
        "Factory" => v(b"FACTORY", Icon::Gear, State::Awaiting, ResultMark::None, &[b"FACTORY SIGNING"]),
        // ---- the seed wizard -------------------------------------------------
        "Backup OK" => v(b"BACKUPOK", Icon::Shield, State::Done, ResultMark::Check, &[b"BACKUP OK"]),
        "Wrong word" | "Verify fail" => v(b"NOMATCH", Icon::Shield, State::Failed, ResultMark::Cross, &[b"NO MATCH"]),
        "Bad checksum" => v(b"BADSEED", Icon::ResultRing, State::Failed, ResultMark::Cross, &[b"WRONG SEED PHRASE"]),
        "No match" => v(b"NOWORD", Icon::ResultRing, State::Failed, ResultMark::Cross, &[b"NO SUCH WORD"]),
        "Words shown" => v(b"SHOWN", Icon::Shield, State::Done, ResultMark::Check, &[b"WORDS SHOWN"]),
        "Write 24 words" => v(b"WRITE24", Icon::Shield, State::Awaiting, ResultMark::None, &[b"WRITE DOWN 24 WORDS"]),
        // The intro to the words: the fingerprint mark on its white disc
        // (never the verified look — boot measures, it does not verify).
        "OS Fingerprint" => Status::Show(
            ScreenBuilder::status(b"OSFPRINT", Icon::Fingerprint, b"OS FINGERPRINT", State::None, ResultMark::None)
                .finish()
                .unwrap_or(Screen::BLANK),
        ),
        _ => {
            // Work in progress: "…", "running", "signing …", "provisioning".
            let working = s.ends_with("...")
                || s.ends_with('\u{2026}')
                || s.starts_with("running")
                || s.starts_with("signing")
                || t.ends_with("...")
                || eq(t, "Provisioning")
                || eq(s, "provisioning")
                || eq(s, "unlock")
                || eq(s, "start")
                || eq(s, "starting");
            let passed = eq(s, "PASS");
            if s.eq_ignore_ascii_case("do not power off") {
                // Irreversible work under way (first-boot lock, recovery):
                // the warning sign at rest, the work never delayed.
                Status::Busy(verdict(b"WORKING", Icon::Alert, State::Warning, ResultMark::None, &[tb, b"DO NOT POWER OFF"]))
            } else if passed {
                v(b"PASS", Icon::ResultRing, State::Done, ResultMark::Check, &[tb, b"PASS"])
            } else if working {
                let mut buf = [b' '; CAPTION_LEN];
                let mut n = 0usize;
                for &b in tb.iter().chain(b" ".iter()).chain(sb.iter()) {
                    if n < CAPTION_LEN {
                        buf[n] = b;
                        n += 1;
                    }
                }
                let text = if t.ends_with("...") || sb.is_empty() { tb } else { &buf[..n] };
                Status::Busy(busy(text))
            } else {
                Status::Show(notice(tb, sb))
            }
        }
    }
}

/// A `show_progress(title, pct)` call: the busy look captioned by the work.
#[must_use]
pub fn progress(title: &str) -> Screen {
    let cap: &[u8] = match title.trim() {
        "C10 keygen" | "Slot keygen" => b"GENERATING KEYS",
        "C10 sign" | "Slot C10 sign" | "EIP-1271 sign" => b"SIGNING",
        other => other.as_bytes(),
    };
    busy(cap)
}

/// The PIN row for the legacy entry state: positions before `pos` entered
/// (masked, `*` — the page showed `*`), `pos` active with its dialed digit
/// (the page showed it), the rest empty.
#[must_use]
pub fn pin_row(caption: &[u8], pin: &[u8], pos: usize) -> Screen {
    let n = pin.len().min(MAX_ENTRY_SLOTS);
    let mut glyphs = [b'_'; MAX_ENTRY_SLOTS];
    let mut states = [b'_'; MAX_ENTRY_SLOTS];
    for i in 0..n {
        if i < pos {
            glyphs[i] = b'*';
            states[i] = b'E';
        } else if i == pos {
            glyphs[i] = b'0' + pin[i] % 10;
            states[i] = b'A';
        }
    }
    let (cap, cn) = caps::<CAPTION_LEN>(caption);
    ScreenBuilder::entry(b"PIN", &cap[..cn], &glyphs[..n], &states[..n])
        .finish()
        .unwrap_or(Screen::BLANK)
}

/// A seed-word prefix row: `len` committed letters, the next one dialed.
#[must_use]
pub fn letter_row(title: &[u8], buf: &[u8], len: usize) -> Screen {
    let n = buf.len().min(MAX_ENTRY_SLOTS);
    let mut glyphs = [b'_'; MAX_ENTRY_SLOTS];
    let mut states = [b'_'; MAX_ENTRY_SLOTS];
    // With every slot committed the page kept dialing the last one.
    let active = len.min(n.saturating_sub(1));
    for i in 0..n {
        if i < len && i != active {
            glyphs[i] = buf[i];
            states[i] = b'E';
        } else if i == active {
            glyphs[i] = buf[i];
            states[i] = b'A';
        }
    }
    let (cap, cn) = caps::<CAPTION_LEN>(title);
    ScreenBuilder::entry(b"WORD", &cap[..cn], &glyphs[..n], &states[..n])
        .finish()
        .unwrap_or(Screen::BLANK)
}

/// A two-option chooser (the wizard's setup menu, the duress yes / no): the
/// hero asks the highlighted option; taps switch it.
#[must_use]
pub fn choice(title: &[u8], option: &[u8]) -> Screen {
    let mut buf = [b' '; CAPTION_LEN];
    let mut n = 0usize;
    for &b in title.iter().chain(b": ".iter()).chain(option.iter()).chain(b"?".iter()) {
        if n < CAPTION_LEN {
            buf[n] = b;
            n += 1;
        }
    }
    let src: &[u8] = if title.is_empty() { &buf[2..n] } else { &buf[..n] };
    let (cap, cn) = caps::<CAPTION_LEN>(src);
    // A chooser arms nothing: the wizard's own loop decides (commit off).
    ScreenBuilder::hero(b"CHOICE", Icon::Eth, &cap[..cn])
        .uncommitted()
        .finish()
        .unwrap_or(Screen::BLANK)
}

/// The boot fingerprint grid: the eight words whole, as NUL-padded cells
/// (`word_bytes_at`). BIP-39 English words are at most eight letters, so
/// nothing is cut. The FSBL's text window can only fit five-letter
/// prefixes; each prefix is the start of the word shown here, and the first
/// four letters already identify a BIP-39 word, so the two rows still
/// compare at a glance.
#[must_use]
pub fn fingerprint_grid(words: &[[u8; 8]; 8]) -> Screen {
    let mut cells: [&[u8]; 8] = [b"-"; 8];
    for (cell, w) in cells.iter_mut().zip(words) {
        let n = w.iter().position(|&b| b == 0).unwrap_or(w.len());
        if n > 0 {
            *cell = &w[..n];
        }
    }
    ScreenBuilder::words(b"FPRINT", b"", &cells).finish().unwrap_or(Screen::BLANK)
}

/// The seed-page record: `n` placeholder cells numbered from `first` — the
/// words themselves never enter the record (they are painted by the
/// constant-time run and never logged or hashed).
#[must_use]
pub fn seed_page(first: u8, n: usize) -> Screen {
    let cells: [&[u8]; 8] = [pqsigner_ui_px::rows::SECRET_PLACEHOLDER; 8];
    ScreenBuilder::words(b"SEED", b"", &cells[..n.clamp(1, 8)])
        .first_number(first)
        .finish()
        .unwrap_or(Screen::BLANK)
}

/// The candidate list (seed-word restore): three placeholder rows, the
/// middle one the cursor, `title` on the band.
#[must_use]
pub fn candidate_list(title: &[u8]) -> Screen {
    let (cap, cn) = caps::<CAPTION_LEN>(title);
    let cells: [&[u8]; 3] = [
        pqsigner_ui_px::rows::SECRET_PLACEHOLDER,
        pqsigner_ui_px::rows::SECRET_CURSOR,
        pqsigner_ui_px::rows::SECRET_PLACEHOLDER,
    ];
    ScreenBuilder::words(b"PICK", &cap[..cn], &cells)
        .first_number(0)
        .finish()
        .unwrap_or(Screen::BLANK)
}

/// `A.B.C.D` from the manifest's big-endian version bytes.
fn version_text(v: u32, out: &mut [u8; 16]) -> usize {
    let mut n = 0usize;
    for (i, b) in v.to_be_bytes().iter().enumerate() {
        if i > 0 {
            out[n] = b'.';
            n += 1;
        }
        let mut d = [0u8; 3];
        let mut k = 0usize;
        let mut x = *b;
        loop {
            d[k] = b'0' + x % 10;
            k += 1;
            x /= 10;
            if x == 0 {
                break;
            }
        }
        while k > 0 {
            k -= 1;
            out[n] = d[k];
            n += 1;
        }
    }
    n
}

fn trim_zero(w: &[u8; 8]) -> &[u8] {
    let n = w.iter().position(|&b| b == 0).unwrap_or(8);
    &w[..n]
}

/// A docked detail on the firmware family's white fingerprint disc.
fn fw_detail(id: &[u8], side: Side, label: &[u8], lines: &[&[u8]]) -> Result<Screen, ()> {
    let ins: [(&[u8], Weight); 3] = core::array::from_fn(|i| (lines.get(i).copied().unwrap_or(b""), Weight::Regular));
    let tier = fit_tier(&ins[..lines.len()], Region::Docked).ok_or(())?;
    let mut b = ScreenBuilder::detail(id, Icon::Fingerprint, side, label).tier(tier);
    for l in lines {
        b = b.line(l, Weight::Regular);
    }
    b.finish().map_err(|_| ())
}

/// The firmware-update consent (`fw_update::confirm_install`) as a pixel
/// transcript: the ask, the version and its direction (the page's facts),
/// each fingerprint announced and then shown WHOLE on the words grid (the
/// page cut every word to five letters), and the returning ask. `fw` / `key`
/// are the zero-padded BIP-39 words of the signed image hash and of the
/// vendor-key fingerprint.
pub fn firmware_update_screens(
    version: u32,
    floor: u32,
    fw: &[[u8; 8]; 8],
    key: &[[u8; 8]; 8],
    out: &mut pqsigner_ui_px::Screens,
) -> Result<(), ()> {
    out.set_len(0);
    let mut ver = [0u8; 16];
    let vn = version_text(version, &mut ver);
    let mut ask = [b' '; CAPTION_LEN];
    let mut n = 0usize;
    for &b in b"UPDATE TO V".iter().chain(&ver[..vn]).chain(b"?".iter()) {
        ask[n] = b;
        n += 1;
    }
    let hero = ScreenBuilder::hero(b"UPDATE", Icon::Fingerprint, &ask[..n]).finish().map_err(|_| ())?;
    let dir: &[u8] = if version > floor {
        b"UPGRADE"
    } else if version == floor {
        b"SAME VERSION"
    } else {
        b"DOWNGRADE!"
    };
    let mut to = [b' '; 20];
    to[..4].copy_from_slice(b"to v");
    to[4..4 + vn].copy_from_slice(&ver[..vn]);
    let fw_words: [&[u8]; 8] = core::array::from_fn(|i| trim_zero(&fw[i]));
    let key_words: [&[u8]; 8] = core::array::from_fn(|i| trim_zero(&key[i]));
    out.push(&hero)?;
    out.push(&fw_detail(b"VERSION", Side::Left, b"VERSION", &[&to[..4 + vn], dir])?)?;
    out.push(&fw_detail(b"FWPRINT", Side::Right, b"FIRMWARE", &[b"Image fingerprint", b"next: 8 words"])?)?;
    out.push(&ScreenBuilder::words(b"FWWORDS", b"", &fw_words).finish().map_err(|_| ())?)?;
    out.push(&fw_detail(b"KEYPRINT", Side::Right, b"SIGNER", &[b"Signing key", b"fingerprint", b"next: 8 words"])?)?;
    out.push(&ScreenBuilder::words(b"KEYWORDS", b"", &key_words).finish().map_err(|_| ())?)?;
    out.push(&hero)?;
    Ok(())
}

/// The consent to run the manifest verifier (`fw_update::confirm_verify_
/// request`): no manifest field is shown — the bytes are unverified.
pub fn firmware_verify_screens(out: &mut pqsigner_ui_px::Screens) -> Result<(), ()> {
    out.set_len(0);
    let hero = ScreenBuilder::hero(b"FWVERIFY", Icon::Fingerprint, b"VERIFY FIRMWARE PACKAGE?").finish().map_err(|_| ())?;
    out.push(&hero)?;
    out.push(&fw_detail(b"FWMODE", Side::Left, b"FW UPDATE", &[b"Verify the vendor-", b"signed package"])?)?;
    out.push(&hero)?;
    Ok(())
}

/// A 16×4 page row, trailing spaces trimmed.
fn row_text(r: &[u8; 16]) -> &[u8] {
    let mut n = r.len();
    while n > 0 && r[n - 1] == b' ' {
        n -= 1;
    }
    let mut a = 0;
    while a < n && r[a] == b' ' {
        a += 1;
    }
    &r[a..n]
}

/// The wallet-address consent (`CMD_GET_WALLET_ADDRESS` with show = 1) from
/// its proven page (`build_wallet_address_page`: the account label, the
/// EIP-55 address over three rows): the ask, the whole address on the
/// docked grid (the page's three rows re-joined), the returning ask.
pub fn wallet_address_screens(account_index: u32, page: &[[u8; 16]; 4], out: &mut pqsigner_ui_px::Screens) -> Result<(), ()> {
    out.set_len(0);
    let mut addr = [0u8; 42];
    let mut n = 0usize;
    for r in &page[1..4] {
        for &b in row_text(r) {
            if n >= 42 {
                return Err(());
            }
            addr[n] = b;
            n += 1;
        }
    }
    if n != 42 || &addr[..2] != b"0x" {
        return Err(());
    }
    let mut num = [0u8; 3];
    let mut k = 0usize;
    let mut v = account_index.min(999);
    loop {
        num[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    num[..k].reverse();
    let mut cap = [b' '; CAPTION_LEN];
    let mut c = 0usize;
    // The caption and label faces carry no `#`: "ACCOUNT n" names it.
    for &b in b"CONFIRM ACCOUNT ".iter().chain(&num[..k]).chain(b" ADDRESS?".iter()) {
        cap[c] = b;
        c += 1;
    }
    let mut label = [b' '; LABEL_LEN];
    let mut l = 0usize;
    for &b in b"ACCOUNT ".iter().chain(&num[..k]) {
        label[l] = b;
        l += 1;
    }
    let hero = ScreenBuilder::hero(b"WALLET", Icon::Eth, &cap[..c]).finish().map_err(|_| ())?;
    let lines = pqsigner_ui_px::fit::layout_address(&addr);
    let mut d = ScreenBuilder::detail(b"ADDRESS", Icon::Eth, Side::Left, &label[..l]).tier(Tier::T22);
    for line in lines.as_slice() {
        d = d.line(line.as_bytes(), Weight::Regular);
    }
    out.push(&hero)?;
    out.push(&d.finish().map_err(|_| ())?)?;
    out.push(&hero)?;
    Ok(())
}

/// The off-chain counter sync consent (`CMD_OFFCHAIN_SYNC`) from its proven
/// pages (`build_offchain_sync_pages`): the banner becomes the ask; every
/// fact row — the chain, the account and slot, the current and target
/// counts — becomes a docked detail line, verbatim; the page's button hints
/// (`L=Cancel` / `R=Confirm`) are the dialog's own gestures and are dropped.
pub fn offchain_sync_screens(pages: &[[[u8; 16]; 4]], out: &mut pqsigner_ui_px::Screens) -> Result<(), ()> {
    out.set_len(0);
    if pages.len() != 3 {
        return Err(());
    }
    let hero = ScreenBuilder::hero(b"SYNC", Icon::Rotate, b"SYNC OFF-CHAIN FLOOR?").finish().map_err(|_| ())?;
    out.push(&hero)?;
    let groups: [(&[u8], &[u8], usize, &[usize]); 3] = [
        (b"SYNCNET", b"NETWORK", 1, &[0, 1]),
        (b"SLOT", b"WALLET", 1, &[2, 3]),
        (b"COUNT", b"COUNTER", 2, &[0, 2]),
    ];
    for (i, (id, label, p, rows)) in groups.iter().enumerate() {
        let side = if i % 2 == 0 { Side::Left } else { Side::Right };
        let mut d = ScreenBuilder::detail(id, Icon::Rotate, side, label).tier(Tier::T22);
        let mut any = false;
        for &r in *rows {
            let t = row_text(&pages[*p][r]);
            if !t.is_empty() {
                d = d.line(t, Weight::Regular);
                any = true;
            }
        }
        if !any {
            return Err(());
        }
        out.push(&d.finish().map_err(|_| ())?)?;
    }
    out.push(&hero)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqsigner_ui_px::Kind;

    fn shown(st: Status) -> Screen {
        match st {
            Status::Show(s) | Status::Busy(s) => s,
            Status::PinPrompt(_) => panic!("prompt"),
        }
    }

    #[test]
    fn lifecycle_statuses_map_to_their_verdicts() {
        let cases: &[(&str, &str, Icon, &[u8])] = &[
            ("Locked", "", Icon::Lock, b"LOCKED"),
            ("Locked", "retry later", Icon::Lock, b"LOCKED - RETRY LATER"),
            ("PIN locked", "power cycle", Icon::Lock, b"PIN LOCKED - POWER CYCLE"),
            ("Unlocked", "", Icon::Unlock, b"UNLOCKED"),
            ("Wrong PIN", "try again", Icon::Pill, b"WRONG PIN"),
            ("Verifying...", "", Icon::Pill, b"CHECKING PIN"),
            ("WALLET WIPED", "restore from seed", Icon::Wipe, b"WALLET WIPED"),
            ("LAST ATTEMPT", "wallet wipes on fail", Icon::Heart, b"LAST ATTEMPT - WIPES ON FAIL"),
            ("TAMPER DETECT", "wiping...", Icon::Alert, b"TAMPER DETECTED"),
            ("RNG failed", "retry...", Icon::Die, b"RNG FAILED"),
            ("Cancelled", "", Icon::ResultRing, b"CANCELED"),
            ("Backup OK", "", Icon::Shield, b"BACKUP OK"),
        ];
        for &(t, s, icon, cap) in cases {
            let sc = shown(classify(t, s));
            assert_eq!(sc.kind(), Some(Kind::Verdict), "{t}");
            assert_eq!(sc.icon(), Some(icon), "{t}");
            assert_eq!(sc.caption(), cap, "{t}");
            assert!(sc.is_well_formed());
        }
        assert!(matches!(classify("Enter PIN", "to unlock"), Status::PinPrompt(c) if c == b"ENTER PIN"));
        let w = shown(classify("WIPING", "do not power off"));
        assert!(matches!(classify("WIPING", ""), Status::Busy(_)));
        assert_eq!(w.caption(), b"WIPING - DO NOT POWER OFF");
        assert_eq!(shown(classify("PQSigner OS", "Ready")).caption(), b"READY");
    }

    #[test]
    fn every_other_status_keeps_its_words() {
        // A refusal: the title is the label, the full reason the lines.
        let n = shown(classify("Sign refused", "register needs slot>=1 and a much longer tail"));
        assert_eq!(n.kind(), Some(Kind::Verdict));
        assert_eq!(n.side(), Some(Side::Left));
        assert_eq!(n.label(), b"SIGN REFUSED");
        let mut text = std::vec::Vec::new();
        for i in 0..n.nlines(0) {
            if !text.is_empty() {
                text.push(b' ');
            }
            text.extend_from_slice(n.line(0, i).unwrap().1);
        }
        assert_eq!(&text[..], b"register needs slot>=1 and a much longer tail");
        // A title longer than a label rides as the first line.
        let n = shown(classify("Duress setup failed", "power cycle to retry"));
        assert_eq!(n.label(), b"ERROR");
        assert_eq!(n.line(0, 0).unwrap().1, b"Duress setup failed");
        // Work in progress is the busy look.
        assert!(matches!(classify("Sign", "validating..."), Status::Busy(_)));
        assert!(matches!(classify("Provisioning", "..."), Status::Busy(_)));
        assert!(matches!(classify("SYNC", "running..."), Status::Busy(_)));
        let lock = shown(classify("LOCKING", "DO NOT POWER OFF"));
        assert_eq!(lock.icon(), Some(Icon::Alert));
        assert_eq!(lock.caption(), b"LOCKING - DO NOT POWER OFF");
        // Every mapped record is well formed and printable.
        for (t, s) in [("Sign", "fi tampered"), ("Batch sign", "gas unshown"), ("EIP-1271", "typed too long"), ("x", "")] {
            assert!(shown(classify(t, s)).is_well_formed(), "{t}/{s}");
        }
    }

    #[test]
    fn captions_use_only_the_caption_face() {
        let (c, n) = caps::<32>(b"Sig verify <FAIL> _x_");
        assert!(c[..n].iter().all(|&b| caption_byte(b) == b));
        assert_eq!(&c[..n], b"SIG VERIFY -FAIL- -X-");
    }

    #[test]
    fn pin_row_masks_entered_digits_like_the_page() {
        let s = pin_row(b"ENTER PIN", &[3, 1, 4, 1, 5, 9, 2, 6], 3);
        assert_eq!(s.entry_slots(), Some((&b"***1____"[..], &b"EEEA____"[..])));
        let s = letter_row(b"Word 3 of 24", b"abcd", 4);
        assert_eq!(s.entry_slots(), Some((&b"abcd"[..], &b"EEEA"[..])));
        assert_eq!(s.caption(), b"WORD 3 OF 24");
    }

    #[test]
    fn fingerprint_grid_shows_whole_words() {
        let w = |s: &[u8]| {
            let mut c = [0u8; 8];
            c[..s.len()].copy_from_slice(s);
            c
        };
        let words = [w(b"close"), w(b"agent"), w(b"own"), w(b"deputy"), w(b"grape"), w(b"though"), w(b"sail"), w(b"category")];
        let g = fingerprint_grid(&words);
        assert!(g.is_well_formed());
        assert_eq!(g.grid_word(0), Some(&b"close"[..]));
        assert_eq!(g.grid_word(2), Some(&b"own"[..]));
        assert_eq!(g.grid_word(3), Some(&b"deputy"[..]));
        // The longest BIP-39 English words (eight letters) fit whole.
        assert_eq!(g.grid_word(7), Some(&b"category"[..]));
        let longest = sphincs_tz_bip39::wordlist::WORDLIST.iter().map(|w| w.len()).max().unwrap();
        assert_eq!(longest, 8);
    }

    #[test]
    fn firmware_update_transcripts_pass_the_flow_rules() {
        let mut t = std::boxed::Box::new(pqsigner_ui_px::Screens::blank());
        let w = |s: &[u8]| {
            let mut c = [0u8; 8];
            c[..s.len()].copy_from_slice(s);
            c
        };
        let fw = [w(b"close"), w(b"agent"), w(b"own"), w(b"deputy"), w(b"grape"), w(b"though"), w(b"sail"), w(b"simple")];
        let key = [w(b"zoo"), w(b"abandon"), w(b"mountain"), w(b"withdraw"), w(b"ill"), w(b"jewel"), w(b"quality"), w(b"fix")];
        firmware_update_screens(0x0102_0304, 0x0102_0300, &fw, &key, &mut t).unwrap();
        assert_eq!(pqsigner_ui_px::check::check_flow(&t), Ok(()));
        let v = t.as_slice();
        assert_eq!(v[0].caption(), b"UPDATE TO V1.2.3.4?");
        assert_eq!(v[1].line(0, 0).unwrap().1, b"to v1.2.3.4");
        assert_eq!(v[1].line(0, 1).unwrap().1, b"UPGRADE");
        // Every word of both fingerprints, whole (the page showed five letters).
        for k in 0..8 {
            assert_eq!(v[3].grid_word(k), Some(trim_zero(&fw[k])));
            assert_eq!(v[5].grid_word(k), Some(trim_zero(&key[k])));
        }
        firmware_update_screens(5, 9, &fw, &key, &mut t).unwrap();
        assert_eq!(t.as_slice()[1].line(0, 1).unwrap().1, b"DOWNGRADE!");
        firmware_verify_screens(&mut t).unwrap();
        assert_eq!(pqsigner_ui_px::check::check_flow(&t), Ok(()));
    }

    /// The lifecycle scenarios (port step 4) as record fixtures for the frame
    /// goldens (`pqsigner-ui-px/tests/fixtures/lifecycle/`): every record is
    /// what the firmware emits for that moment. `UI_PX_EXPORT=1` rewrites the
    /// files; otherwise the committed files must match (drift is a red test).
    #[test]
    fn lifecycle_fixtures_are_current() {
        let st = |t: &str, s: &str| shown(classify(t, s));
        let w = |s: &[u8]| {
            let mut c = [0u8; 8];
            c[..s.len()].copy_from_slice(s);
            c
        };
        let fw = [w(b"close"), w(b"agent"), w(b"own"), w(b"deputy"), w(b"grape"), w(b"though"), w(b"sail"), w(b"simple")];
        let key = [w(b"zoo"), w(b"abandon"), w(b"mountain"), w(b"withdraw"), w(b"ill"), w(b"jewel"), w(b"quality"), w(b"fix")];
        let mut fwt = std::boxed::Box::new(pqsigner_ui_px::Screens::blank());
        firmware_update_screens(0x0001_0003, 0x0001_0002, &fw, &key, &mut fwt).unwrap();
        let mut fwv = std::boxed::Box::new(pqsigner_ui_px::Screens::blank());
        firmware_verify_screens(&mut fwv).unwrap();
        let prow = |t: &[u8]| {
            let mut r = [b' '; 16];
            r[..t.len()].copy_from_slice(t);
            r
        };
        let mut wal = std::boxed::Box::new(pqsigner_ui_px::Screens::blank());
        wallet_address_screens(0, &[prow(b"Wallet addr #0"), prow(b"0x1CDD2EaB611126"), prow(b"97626F7b4bB0e23D"), prow(b"a4FeBF7B7C")], &mut wal).unwrap();
        let mut sync = std::boxed::Box::new(pqsigner_ui_px::Screens::blank());
        offchain_sync_screens(
            &[
                [prow(b""), prow(b"SYNC COUNTER?"), prow(b"Off-chain floor"), prow(b"")],
                [prow(b"Chain: 8453"), prow(b"Base"), prow(b"Account: 0"), prow(b"Slot: 3")],
                [prow(b"Current: 12"), prow(b"L=Cancel"), prow(b"Target: 40"), prow(b"R=Confirm")],
            ],
            &mut sync,
        )
        .unwrap();
        let scenarios: std::vec::Vec<(&str, std::vec::Vec<Screen>)> = std::vec![
            ("boot", std::vec![splash(), st("OS Fingerprint", ""), fingerprint_grid(&fw), st("PQSigner OS", "Ready")]),
            (
                "unlock",
                std::vec![
                    pin_row(b"ENTER PIN", &[3, 1, 4, 1, 5, 9, 2, 6], 0),
                    pin_row(b"ENTER PIN", &[3, 1, 4, 1, 5, 9, 2, 6], 5),
                    st("Verifying...", ""),
                    st("Wrong PIN", "try again"),
                    st("LAST ATTEMPT", "wallet wipes on fail"),
                    st("Unlocked", ""),
                    st("Locked", ""),
                    st("PIN locked", "power cycle"),
                ],
            ),
            (
                "wizard",
                std::vec![
                    choice(b"", b"Create new wallet"),
                    choice(b"", b"Restore wallet"),
                    pin_row(b"SET NEW PIN", &[0; 8], 0),
                    st("Write 24 words", "L=cancel R=show"),
                    seed_page(9, 8),
                    letter_row(b"Check word 5", b"abaa", 2),
                    candidate_list(b"Word 3 of 24"),
                    st("Backup OK", ""),
                    st("Wrong word", "retrying..."),
                    st("Bad checksum", "retry..."),
                    st("PINs differ", "retry..."),
                ],
            ),
            (
                "outcomes",
                std::vec![
                    st("Cancelled", ""),
                    st("Signed", ""),
                    st("WIPING", "do not power off"),
                    st("WALLET WIPED", "restore from seed"),
                    st("TAMPER DETECT", "wiping..."),
                    st("RNG failed", "retry..."),
                    st("Factory", "signing slot-0"),
                    st("Sign refused", "gas unshown"),
                    st("Batch refused", "wrong EntryPoint"),
                    st("Provisioning", "..."),
                    progress("C10 keygen"),
                ],
            ),
            ("fw_update", fwt.as_slice().to_vec()),
            ("fw_verify", fwv.as_slice().to_vec()),
            ("wallet_address", wal.as_slice().to_vec()),
            ("offchain_sync", sync.as_slice().to_vec()),
        ];
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../pqsigner-ui-px/tests/fixtures/lifecycle");
        let export = std::env::var_os("UI_PX_EXPORT").is_some();
        let mut stale = std::vec::Vec::new();
        for (name, records) in scenarios {
            let mut out = std::string::String::new();
            for r in &records {
                assert!(r.is_well_formed(), "{name}: {r:?}");
                assert_eq!(pqsigner_ui_px::check::check_screens(core::slice::from_ref(r)), Ok(()), "{name}: {r:?}");
                for b in r.0 {
                    out.push_str(&std::format!("{b:02x}"));
                }
                out.push('\n');
            }
            let path = dir.join(std::format!("{name}.hex"));
            if export {
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(&path, &out).unwrap();
            } else if std::fs::read_to_string(&path).ok().as_deref() != Some(out.as_str()) {
                stale.push(name);
            }
        }
        assert!(stale.is_empty(), "lifecycle fixtures stale: {stale:?} — UI_PX_EXPORT=1 cargo test -p sphincs-tz-secure ui_px_status_map, then make ui-px-goldens-bless");
    }

    /// Pages ⊆ screens for the two lifted consents: every non-hint page row
    /// appears verbatim (the address re-joined) in the transcript.
    #[test]
    fn lifted_consents_carry_every_page_fact() {
        let row = |t: &[u8]| {
            let mut r = [b' '; 16];
            r[..t.len()].copy_from_slice(t);
            r
        };
        let page = [row(b"Wallet addr #7"), row(b"0x1CDD2EaB611126"), row(b"97626F7b4bB0e23D"), row(b"a4FeBF7B7C")];
        let mut t = std::boxed::Box::new(pqsigner_ui_px::Screens::blank());
        wallet_address_screens(7, &page, &mut t).unwrap();
        assert_eq!(pqsigner_ui_px::check::check_flow(&t), Ok(()));
        let d = &t.as_slice()[1];
        let mut joined = std::vec::Vec::new();
        for i in 0..d.nlines(0) {
            joined.extend_from_slice(d.line(0, i).unwrap().1);
        }
        assert_eq!(&joined[..], b"0x1CDD2EaB61112697626F7b4bB0e23Da4FeBF7B7C");
        assert_eq!(d.label(), b"ACCOUNT 7");
        assert_eq!(t.as_slice()[0].caption(), b"CONFIRM ACCOUNT 7 ADDRESS?");

        let pages = [
            [row(b""), row(b"SYNC COUNTER?"), row(b"Off-chain floor"), row(b"")],
            [row(b"Chain: 8453"), row(b"Base"), row(b"Account: 0"), row(b"Slot: 3")],
            [row(b"Current: 12"), row(b"L=Cancel"), row(b"Target: 40"), row(b"R=Confirm")],
        ];
        wallet_address_screens(7, &page, &mut t).unwrap();
        offchain_sync_screens(&pages, &mut t).unwrap();
        assert_eq!(pqsigner_ui_px::check::check_flow(&t), Ok(()));
        let mut lines = std::vec::Vec::new();
        for s in t.as_slice() {
            for i in 0..s.nlines(0) {
                lines.push(s.line(0, i).unwrap().1.to_vec());
            }
        }
        for want in [&b"Chain: 8453"[..], b"Base", b"Account: 0", b"Slot: 3", b"Current: 12", b"Target: 40"] {
            assert!(lines.iter().any(|l| l == want), "{}", String::from_utf8_lossy(want));
        }
    }

    #[test]
    fn secret_records_never_hold_the_words() {
        let s = seed_page(9, 8);
        for k in 0..8 {
            assert_eq!(s.grid_word(k), Some(pqsigner_ui_px::rows::SECRET_PLACEHOLDER));
        }
        assert_eq!(s.grid_first(), Some(9));
        let c = candidate_list(b"Word 3 of 24");
        assert_eq!(c.grid_word(1), Some(pqsigner_ui_px::rows::SECRET_CURSOR));
        assert_eq!(c.grid_first(), Some(0));
    }
}

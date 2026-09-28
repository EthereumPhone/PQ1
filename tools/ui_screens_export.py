#!/usr/bin/env python3
"""Export every trusted-display screen of PQSigner OS into docs/ui-screens/.

The NV3007 panel shows a 16x4 character grid (428x142 px landscape, white on
black, FONT_5X8 upscaled 3x). Every screen the secure world can show is one
such grid, so the whole UI can be exported as text + pixel-exact PNGs.

Two sources feed the catalogue and each screen is labelled with its origin:

  * captured  — frames printed by the real firmware under QEMU
                (`make e2e`, semihosting framebox), stored in
                `docs/ui-screens/_captures/e2e_frames.json`. Byte-exact,
                including the ` i/n` page indicator the confirm dialog
                overlays at draw time.
  * composed  — screens the e2e suite never reaches (boot, PIN entry, seed
                wizard, firmware update, wipe, off-chain personal-sign ...),
                built here from the firmware's literal strings and layout
                code, with representative sample values for dynamic fields.
                Each carries a `file:line` pointer to the code that draws it.

Usage:
    python3 tools/ui_screens_export.py                 # regenerate docs/ui-screens/
    python3 tools/ui_screens_export.py --e2e-log LOG   # also refresh the captures
                                                       # from a `make e2e` log

Requires Pillow (PNG output). Zero other dependencies.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    from PIL import Image, ImageDraw
except ImportError:  # pragma: no cover
    sys.exit("Pillow is required: pip install pillow")

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "ui-screens"
CAPTURES = OUT / "_captures" / "e2e_frames.json"
FONT_RAW = ROOT / "secure" / "assets" / "font_5x8.raw"

COLS, ROWS = 16, 4
PREVIEW_SCALE = 3

# ─────────────────────────────────────────────────────────────────────────────
# Panel renderer — pixel-exact port of tools/lcd_render/src/{font,lcd}.rs,
# which itself mirrors secure/src/ui/lcd.rs (verified identical output).
# ─────────────────────────────────────────────────────────────────────────────
W, H = 428, 142
SCALE, GW, GH = 3, 5, 8
COL_PITCH, ROW_PITCH, OX, OY = 26, 35, 6, 1
_RAW = FONT_RAW.read_bytes()


def _glyph_cols(ch: int) -> list[int]:
    if ch < 0x20 or ch > 0x7F:
        return [0] * 5
    idx = ch - 0x20
    gx, gy = (idx % 16) * 5, (idx // 16) * 8
    cols = []
    for c in range(5):
        b = 0
        for r in range(8):
            px, py = gx + c, gy + r
            if (_RAW[py * 10 + px // 8] >> (7 - (px % 8))) & 1:
                b |= 1 << r
        cols.append(b)
    return cols


def render_png(rows: list[str], scale: int = 1) -> Image.Image:
    im = Image.new("RGB", (W, H), (0, 0, 0))
    px = im.load()
    for r, row in enumerate(rows[:ROWS]):
        row = (row + " " * COLS)[:COLS]
        for c, ch in enumerate(row):
            b = ord(ch)
            b = b if 0x20 <= b <= 0x7E else ord("?")
            cols = _glyph_cols(b)
            x0, y0 = OX + c * COL_PITCH, OY + r * ROW_PITCH
            for gx in range(GW):
                for gy in range(GH):
                    if (cols[gx] >> gy) & 1:
                        for dx in range(SCALE):
                            for dy in range(SCALE):
                                px[x0 + gx * SCALE + dx, y0 + gy * SCALE + dy] = (255, 255, 255)
    if scale > 1:
        im = im.resize((W * scale, H * scale), Image.NEAREST)
    return im


# ─────────────────────────────────────────────────────────────────────────────
# keccak-256 (for EIP-55 checksummed sample addresses in composed screens)
# ─────────────────────────────────────────────────────────────────────────────
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]
_M = (1 << 64) - 1


def _rol(x, n):
    return ((x << n) | (x >> (64 - n))) & _M


def _keccak_f(s):
    for rc in _RC:
        c = [s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        s = [s[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(s[x + 5 * y], _ROT[x][y])
        s = [b[i] ^ ((~b[(i % 5 + 1) % 5 + 5 * (i // 5)]) & b[(i % 5 + 2) % 5 + 5 * (i // 5)]) for i in range(25)]
        s[0] ^= rc
    return s


def keccak256(data: bytes) -> bytes:
    rate = 136
    data = data + b"\x01" + b"\x00" * (rate - 1 - len(data) % rate)
    data = data[:-1] + bytes([data[-1] | 0x80])
    s = [0] * 25
    for off in range(0, len(data), rate):
        blk = data[off:off + rate]
        for i in range(rate // 8):
            s[i] ^= int.from_bytes(blk[i * 8:(i + 1) * 8], "little")
        s = _keccak_f(s)
    return b"".join(x.to_bytes(8, "little") for x in s)[:32]


assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"


def eip55(addr_hex: str) -> str:
    a = addr_hex.lower().replace("0x", "")
    h = keccak256(a.encode()).hex()
    return "".join(ch.upper() if int(h[i], 16) >= 8 else ch for i, ch in enumerate(a))


def addr_rows(addr_hex: str) -> list[str]:
    """`primitives::write_addr_full`: '0x'+14 hex / 16 hex / 10 hex."""
    a = eip55(addr_hex)
    return ["0x" + a[:14], a[14:30], a[30:40]]


# ─────────────────────────────────────────────────────────────────────────────
# Screen model
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Screen:
    family: str
    id: str
    rows: list[str]
    source: str = ""          # file:line pointers (markdown)
    when: str = ""            # when the user sees it
    origin: str = "composed"  # composed | captured
    notes: str = ""

    def norm(self) -> list[str]:
        return [(r + " " * COLS)[:COLS] for r in (self.rows + [""] * ROWS)[:ROWS]]


@dataclass
class Family:
    key: str
    title: str
    intro: str
    screens: list[Screen] = field(default_factory=list)

    def add(self, id, rows, source="", when="", origin="composed", notes=""):
        self.screens.append(Screen(self.key, id, rows, source, when, origin, notes))


FAMILIES: list[Family] = []


def family(key, title, intro) -> Family:
    f = Family(key, title, intro)
    FAMILIES.append(f)
    return f


def status(title: str, sub: str) -> list[str]:
    """`ui::show_status(title, sub)` — secure/src/ui/mod.rs: row1 title, row2 sub."""
    return ["", title, sub, ""]


def progress(title: str, pct: int) -> list[str]:
    """`ui::show_progress(title, pct)` — secure/src/ui/mod.rs: 14-cell bar on row 3."""
    filled = (min(pct, 100) * 14 + 50) // 100
    bar = "[" + "".join("#" if i < filled else "-" for i in range(14)) + "]"
    return ["", title, "", bar]


def overlay(rows: list[str], idx: int, total: int) -> list[str]:
    """`ui::confirm::overlay_page_position` (#488): right-align ` i/n` on the
    footer row of a confirm-dialog page when it fits."""
    rows = [(r + " " * COLS)[:COLS] for r in rows]
    ind = f" {idx + 1}/{total}"
    used = len(rows[3].rstrip())
    if used + len(ind) <= COLS:
        rows[3] = rows[3][: COLS - len(ind)] + ind
    return rows


def confirm_pages(pages: list[list[str]]) -> list[list[str]]:
    return [overlay(p, i, len(pages)) for i, p in enumerate(pages)]


def centered(s: str) -> str:
    """`write_centered`: (16-len)/2 leading spaces."""
    s = s[:COLS]
    return " " * ((COLS - len(s)) // 2) + s


def grep_sites(*literals: str, roots=("secure/src", "pqsigner-erc7730/src")) -> list[str]:
    """Return `file:line` hits for a set of string literals (non-test code)."""
    hits: list[str] = []
    for lit in literals:
        try:
            out = subprocess.run(
                ["grep", "-rn", "-F", "--include=*.rs", lit, *[str(ROOT / r) for r in roots]],
                capture_output=True, text=True, check=False,
            ).stdout
        except FileNotFoundError:
            out = ""
        for line in out.splitlines():
            path, ln, _ = line.split(":", 2)
            rel = os.path.relpath(path, ROOT)
            if re.search(r"(_tests?\.rs|/tests?/|pure_tests|se050_stress|prodtest)", rel):
                continue
            hits.append(f"{rel}:{ln}")
    # stable, unique
    seen, out = set(), []
    for h in hits:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def src_status(title: str, sub: str) -> str:
    """Source pointer for a `show_status(title, sub)` screen."""
    lit = f'show_status("{title}", "{sub}")'
    sites = grep_sites(lit)
    if not sites:
        sites = grep_sites(f'"{title}"')
    body = ", ".join(f"`{s}`" for s in sites[:6]) or "(dynamic call site)"
    if len(sites) > 6:
        body += f" (+{len(sites) - 6} more)"
    return f"{body} via `secure/src/ui/mod.rs` `show_status`"


# ─────────────────────────────────────────────────────────────────────────────
# Sample data (kept consistent with the e2e captures)
# ─────────────────────────────────────────────────────────────────────────────
WALLET = "bee6a6e73e418d42ef382ecf8e8025740e97c2fe"   # account-0 test wallet in e2e
FACTORY = "e8ce78cd0000000000000000000000000000cafe"  # sample factory address
FP_WORDS = ["close", "agent", "own", "deputy", "grape", "though", "sail", "simple"]


def fingerprint_lines(words=FP_WORDS) -> list[str]:
    """`sphincs_tz_bip39::firmware_fingerprint_lines`: 2 words/row, digit at
    col 0/8, word (<=6 chars) at col 2/10 — matches measured_boot.rs doc."""
    rows = []
    for r in range(4):
        row = [" "] * COLS
        row[0] = str(r + 1)
        for i, ch in enumerate(words[r][:6]):
            row[2 + i] = ch
        row[8] = str(r + 5)
        for i, ch in enumerate(words[r + 4][:6]):
            row[10 + i] = ch
        rows.append("".join(row))
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# 01 — boot
# ─────────────────────────────────────────────────────────────────────────────
def build_boot():
    f = family("01-boot", "Boot",
               "What the device shows from power-on until it is ready for a PIN. "
               "Order on a provisioned device: splash → `OS Fingerprint` title (1.5 s) → "
               "the 8 fingerprint words (4 s, any button skips) → `Enter PIN / to unlock`. "
               "On a blank device the seed wizard (family 03) runs instead of PIN entry.")
    f.add("splash", ["", "   PQ SIGNER", "", ""],
          source="`secure/src/ui/lcd.rs:207` (`Display::splash`)",
          when="Immediately at power-on, held 700 ms, then cleared.",
          notes="Static text only. The animated splash prototypes in `secure/src/ui/splash_test.rs` "
                "(`make splash-test-hw`) are bench-only and not wired into boot.")
    f.add("measured_boot_title", status("OS Fingerprint", ""),
          source="`secure/src/measured_boot.rs:215`",
          when="1.5 s after the splash, before the fingerprint words.")
    f.add("measured_boot_words", fingerprint_lines(),
          source="`secure/src/measured_boot.rs:153` (`render_all_words`) → `bip39/src/lib.rs` `firmware_fingerprint_lines`",
          when="Held 4 s (any button skips). The words are derived from the firmware hash, so they differ per build. "
               "The bench FSBL renders the same 8 words earlier in boot (`fsbl/src/`).",
          notes="Words are truncated to 6 characters; 2 words per row.")
    f.add("provisioning", status("Provisioning", "..."),
          source=src_status("Provisioning", "..."),
          when="After the seed wizard finishes, while the seed halves are written to both secure elements.")
    f.add("ready", status("PQSigner OS", "Ready"),
          source=src_status("PQSigner OS", "Ready"),
          when="Idle screen after every completed command (sign, address, init-code).")
    # first-boot self-lock (rdp2-self-lock, production-only)
    f.add("first_boot_locking", status("LOCKING", "DO NOT POWER OFF"),
          source="`secure/src/first_boot/mod.rs:199`",
          when="First field boot only (`rdp2-self-lock`, production builds): while RDP-2 is being programmed.")
    f.add("first_boot_not_locked", status("NOT LOCKED", "power to retry"),
          source="`secure/src/first_boot/mod.rs:224`",
          when="First field boot: the RDP-2 lock did not take; power-cycle re-prompts.")
    f.add("first_boot_setup", status("FIRST BOOT SETUP", "DO NOT POWER OFF"),
          source="`secure/src/first_boot/mod.rs:361`",
          when="First field boot: transport→final secure-element credential rotation in progress.")
    f.add("first_boot_recovering", status("RECOVERING", "DO NOT POWER OFF"),
          source="`secure/src/first_boot/mod.rs:359`",
          when="First field boot resumed after a power cut mid-rotation (journal replay).")


# ─────────────────────────────────────────────────────────────────────────────
# 02 — PIN / unlock
# ─────────────────────────────────────────────────────────────────────────────
def pin_screen(pin: list[int], pos: int) -> list[str]:
    """`pin_entry::render_pin_screen` (secure/src/ui/pin_entry.rs:140)."""
    r1 = [" "] * COLS
    for i, d in enumerate(pin[:8]):
        r1[i * 2] = "*" if i < pos else (str(d) if i == pos else "_")
    r2 = [" "] * COLS
    r2[pos * 2] = "^"
    return ["   Enter PIN", "".join(r1), "".join(r2), "L=- R=+ LL=back"]


def build_pin():
    f = family("02-pin-unlock", "PIN entry and unlock",
               "The 8-digit PIN dialog (`secure/src/ui/pin_entry.rs`) and every status shown around it. "
               "Buttons: L = digit down, R = digit up, long-R = next digit / confirm on the last, "
               "long-L = back one digit / cancel at digit 1. The same dialog is used to set a new PIN "
               "in the seed wizard (with the `Set new PIN` / `Confirm PIN` titles shown first).")
    f.add("enter_pin_prompt", status("Enter PIN", "to unlock"),
          source=src_status("Enter PIN", "to unlock"),
          when="Boot (provisioned device) and after every lock; shown until the companion requests unlock or the user presses a button.")
    f.add("pin_entry_digit1", pin_screen([3, 0, 0, 0, 0, 0, 0, 0], 0),
          source="`secure/src/ui/pin_entry.rs:140` (`render_pin_screen`)",
          when="PIN dialog, first digit. Entered digits become `*`, the active digit is shown in clear, remaining are `_`.")
    f.add("pin_entry_digit4", pin_screen([7, 1, 9, 5, 0, 0, 0, 0], 3),
          source="`secure/src/ui/pin_entry.rs:140`", when="PIN dialog, fourth digit.")
    f.add("pin_entry_digit8", pin_screen([7, 1, 9, 5, 2, 4, 8, 6], 7),
          source="`secure/src/ui/pin_entry.rs:140`", when="PIN dialog, last digit (long-R confirms).")
    f.add("set_new_pin", status("Set new PIN", ""), source="`secure/src/ui/pin_entry.rs:189`",
          when="Seed wizard: before the first PIN entry.")
    f.add("confirm_pin", status("Confirm PIN", ""), source="`secure/src/ui/pin_entry.rs:195`",
          when="Seed wizard: before the second (confirmation) PIN entry.")
    f.add("pins_differ", status("PINs differ", "retry..."), source=src_status("PINs differ", "retry..."),
          when="Seed wizard: the two PIN entries did not match; the dialog restarts.")
    f.add("verifying", status("Verifying...", ""), source=src_status("Verifying...", ""),
          when="After PIN confirm, while both secure elements verify the PIN.")
    f.add("unlocked", status("Unlocked", ""), source=src_status("Unlocked", ""),
          when="PIN accepted; signing window open (120 s idle timeout).")
    f.add("wrong_pin", status("Wrong PIN", ""), source=src_status("Wrong PIN", ""),
          when="PIN rejected (attempts remaining > 1).")
    f.add("last_attempt", status("LAST ATTEMPT", "wallet wipes on fail"),
          source=src_status("LAST ATTEMPT", "wallet wipes on fail"),
          when="PIN rejected and exactly one attempt remains. NOTE: the sub-line is 20 chars and is "
               "clipped to `wallet wipes on ` on the 16-column display.",
          notes="Candidate for rewording (row overflow).")
    f.add("unlock_error", status("Unlock error", "try again"), source=src_status("Unlock error", "try again"),
          when="Secure-element/transport error during unlock (not a wrong PIN).")
    f.add("pin_locked", status("PIN locked", "factory reset"), source=src_status("PIN locked", "factory reset"),
          when="Attempt counter exhausted on a secure element; device must be wiped/reset.")
    f.add("cancelled", status("Cancelled", ""), source=src_status("Cancelled", ""),
          when="User long-L cancelled a PIN entry or a confirm dialog.")
    f.add("locked", status("Locked", ""), source="`secure/src/nsc/cmd_lock.rs:13`",
          when="Companion sent CMD_LOCK, or the 120 s inactivity timer fired; secrets zeroized.")


# ─────────────────────────────────────────────────────────────────────────────
# 03 — seed wizard
# ─────────────────────────────────────────────────────────────────────────────
def menu(title: str, options: list[str], cur: int, footer="L=- R=+ LR=ok") -> list[str]:
    rows = [title]
    for i, o in enumerate(options):
        rows.append(("> " if i == cur else "  ") + o[: COLS - 2])
    while len(rows) < 3:
        rows.append("")
    rows.append(footer)
    return rows


def phrase_page(page: int, words: list[str], first: int) -> list[str]:
    """`seed_wizard::render_mnemonic_page` (secure/src/ui/seed_wizard.rs:486)."""
    rows = [f" Phrase {page}/8"]
    for i, w in enumerate(words):
        rows.append(f"{first + i:>2} {w}")
    return rows


def letter_entry(title: str, buf: str, n: int) -> list[str]:
    """`seed_wizard::render_letter_screen` (secure/src/ui/seed_wizard.rs:833)."""
    r1 = [" "] * COLS
    for i in range(4):
        r1[1 + i * 2] = buf[i] if i < n else ("a" if i == n else "_")
    r2 = [" "] * COLS
    r2[1 + min(n, 3) * 2] = "^"
    return [title, "".join(r1), "".join(r2), "L/R=ltr LR=ok"]


def candidates(title: str, cands: list[str], cur: int) -> list[str]:
    """`seed_wizard::render_candidate_screen` (secure/src/ui/seed_wizard.rs:908): rows 1-2 = cur-1, cur (with wrap)."""
    rows = [title]
    for i, w in enumerate(cands[:2]):
        rows.append(("> " if i == cur else "  ") + w)
    rows.append("L/R=scrl LR=ok")
    return rows


def build_wizard():
    f = family("03-seed-wizard", "Seed wizard (new wallet / restore)",
               "Runs on a blank device instead of PIN entry (`secure/src/ui/seed_wizard.rs`, driven from "
               "`secure/src/main.rs` `run_first_boot_wizard`). Flow: `Wallet Setup` menu → "
               "New: show 24 words (8 pages of 3) → verify 3 random words → set PIN twice → `Provisioning`. "
               "Restore: type 24 words with the 4-letter prefix picker → checksum → set PIN twice.")
    f.add("wallet_setup_new", menu("  Wallet Setup", ["New Wallet", "Restore"], 0),
          source="`secure/src/ui/seed_wizard.rs:74` (`choose_setup_mode`)",
          when="First screen of the wizard. L/R move the cursor, long-R selects, long-L cancels.")
    f.add("wallet_setup_restore", menu("  Wallet Setup", ["New Wallet", "Restore"], 1),
          source="`secure/src/ui/seed_wizard.rs:74`", when="Same menu, cursor on Restore.")
    f.add("write_24_words", status("Write 24 words", "L=cancel R=show"),
          source="`secure/src/ui/seed_wizard.rs:268` (`show_mnemonic`)",
          when="New wallet: prompt before the phrase pages.")
    f.add("phrase_page_1", phrase_page(1, ["abandon", "ability", "about"], 1),
          source="`secure/src/ui/seed_wizard.rs:486` (`render_mnemonic_page`)",
          when="New wallet: page 1 of 8. R = next page, L = previous, long-R on page 8 = done. "
               "Word rows are drawn through the constant-time secret-text path.")
    f.add("phrase_page_8", phrase_page(8, ["actual", "ad", "adapt"], 22),
          source="`secure/src/ui/seed_wizard.rs:486`", when="New wallet: last phrase page.")
    f.add("words_shown", status("Words shown", ""), source="`secure/src/ui/seed_wizard.rs:336`",
          when="After the last phrase page is acknowledged; then the 3-word verification starts.")
    f.add("check_word_letters", letter_entry(" Check word 7", "abus", 4),
          source="`secure/src/ui/seed_wizard.rs:833` (`render_letter_screen`), title from `:646` (`build_check_title`)",
          when="New-wallet verification: scroll letters with L/R, long-R accepts a letter, prefix narrows to a BIP-39 word.")
    f.add("check_word_candidates", candidates(" Check word 7", ["abuse", "abstract"], 0),
          source="`secure/src/ui/seed_wizard.rs:908` (`render_candidate_screen`)",
          when="When the typed prefix matches several words: L/R scroll the list, long-R picks, long-L goes back.")
    f.add("wrong_word", status("Wrong word", "retrying..."), source="`secure/src/ui/seed_wizard.rs:599`",
          when="Verification: the picked word does not match; the same word is asked again.")
    f.add("backup_ok", status("Backup OK", ""), source="`secure/src/ui/seed_wizard.rs:621`",
          when="All 3 verification words correct; next: `Set new PIN`.")
    f.add("restore_word_entry", letter_entry(" Word 7 of 24", "ab", 2),
          source="`secure/src/ui/seed_wizard.rs:833`, title from `:711` (`build_word_progress_title`)",
          when="Restore: same letter picker, one screen per word 1..24. Long-L at 0 letters backs up one word.")
    f.add("no_match", status("No match", "back up..."), source="`secure/src/ui/seed_wizard.rs:785`",
          when="Letter picker: the prefix matches no BIP-39 word; last letter is removed.")
    f.add("bad_checksum", status("Bad checksum", "retry..."), source="`secure/src/ui/seed_wizard.rs:704`",
          when="Restore: the 24 words fail the BIP-39 checksum; entry restarts.")
    f.add("rng_failed", status("RNG failed", "retry..."), source="`secure/src/ui/seed_wizard.rs:368`",
          when="Only with `decoy-frames`: decoy-word entropy generation failed.")
    f.add("duress_set_prompt", menu(" Set duress PIN?", ["No", "Yes"], 0),
          source="`secure/src/ui/seed_wizard.rs:180` (`collect_duress_pin` → `yes_no`)",
          when="Feature `duress-pin` only (opt-in, not in `mode-production` by default): after the main PIN is set.")
    f.add("duress_wipe_prompt", menu("Wipe on duress?", ["No", "Yes"], 0),
          source="`secure/src/ui/seed_wizard.rs:220` (`choose_duress_wipe_mode`)",
          when="Feature `duress-pin`: choose decoy wallet vs wipe when the duress PIN is entered.")
    f.add("duress_must_differ", status("Duress PIN", "must differ"), source="`secure/src/ui/seed_wizard.rs:186`",
          when="Feature `duress-pin`: intro before the duress PIN dialog.")
    f.add("duress_same_as_main", status("Same as main", "pick another"), source="`secure/src/ui/seed_wizard.rs:197`",
          when="Feature `duress-pin`: duress PIN equals the main PIN.")


# ─────────────────────────────────────────────────────────────────────────────
# 04 — firmware update
# ─────────────────────────────────────────────────────────────────────────────
def fw_version_page(new: int, floor: int) -> list[str]:
    b = new.to_bytes(4, "big")
    d = "UPGRADE" if new > floor else ("SAME VERSION" if new == floor else "DOWNGRADE!")
    return ["FW UPDATE", f"to v{b[0]}.{b[1]}.{b[2]}.{b[3]}", d, "R-tap = next"]


def fw_fingerprint_page(disc: str, words=FP_WORDS) -> list[str]:
    rows = []
    for r in range(4):
        row = [" "] * COLS
        row[0], row[1] = str(r + 1), disc
        for i, ch in enumerate(words[r][:5]):
            row[3 + i] = ch
        row[8], row[9] = str(r + 5), disc
        for i, ch in enumerate(words[r + 4][:5]):
            row[11 + i] = ch
        rows.append("".join(row))
    return rows


def build_fw():
    f = family("04-firmware-update", "Firmware update",
               "Two confirm dialogs in `secure/src/fw_update/mod.rs`, driven by CMD_FW_BEGIN "
               "(`secure/src/nsc/cmd_fw_begin.rs`). First a single-page authorisation to even run the "
               "manifest verifier, then a 4-page install dialog (short taps navigate, long-R confirms, long-L cancels). "
               "Streaming and commit show no further screens; the device resets into the new image.")
    p = confirm_pages([["FW UPDATE MODE", "Verify vendor-", "signed package?", "Hold R = enter"]])
    f.add("fw_verify_request", p[0], source="`secure/src/fw_update/mod.rs:53` (`confirm_verify_request`)",
          when="CMD_FW_BEGIN received (PIN unlock required first). Contains no manifest data on purpose.")
    pages = confirm_pages([fw_version_page(0x01020304, 0x01020303), fw_fingerprint_page("f"),
                           fw_fingerprint_page("k"), ["Confirm update?", "R-hold = YES", "L-hold = NO", "L-tap = review"]])
    f.add("fw_install_1_version", pages[0], source="`secure/src/fw_update/mod.rs:154` (`build_version_page`)",
          when="Install dialog page 1: new version + direction vs the rollback floor.")
    f.add("fw_install_2_fw_fingerprint", pages[1], source="`secure/src/fw_update/mod.rs:217` (`build_fingerprint_page`, `f`)",
          when="Page 2: 8-word fingerprint of the NEW firmware (`f` = firmware). Words truncated to 5 chars.")
    f.add("fw_install_3_key_fingerprint", pages[2], source="`secure/src/fw_update/mod.rs:217` (`build_fingerprint_page`, `k`)",
          when="Page 3: 8-word fingerprint of the vendor signing key (`k` = key).")
    f.add("fw_install_4_confirm", pages[3], source="`secure/src/fw_update/mod.rs:246` (`build_confirm_prompt_page`)",
          when="Page 4: final yes/no.")


# ─────────────────────────────────────────────────────────────────────────────
# 05 — wipe / tamper / fatal
# ─────────────────────────────────────────────────────────────────────────────
def build_wipe():
    f = family("05-wipe-tamper-fatal", "Wipe, tamper and fatal screens",
               "Terminal states. All are `show_status` layouts except the panic screen, which is drawn "
               "directly by the panic handler.")
    f.add("wiping", status("WIPING", "do not power off"), source="`secure/src/nsc/cmd_request_unlock.rs:176`",
          when="10th wrong PIN: both secure elements and MCU pages are being wiped.")
    f.add("wiping_resume", status("WIPING", "resuming from interrupt"), source="`secure/src/main.rs:1580`",
          when="Boot after a power cut during a wipe: the wipe is completed first. Sub-line is clipped to 16 cols.",
          notes="Candidate for rewording (row overflow).")
    f.add("wallet_wiped", status("WALLET WIPED", "restore from seed"),
          source="`secure/src/nsc/cmd_request_unlock.rs:192`, `secure/src/main.rs:1587`",
          when="Wipe finished. Sub-line is 17 chars and clipped to `restore from see`.",
          notes="Candidate for rewording (row overflow).")
    f.add("tamper_detect", status("TAMPER DETECT", "wiping..."), source="`secure/src/nsc/mod.rs:1407`",
          when="Confirmed TAMP intrusion (`tamp-wipe` builds): wipe starts.")
    f.add("wiped_tamper", status("WIPED", "tamper signal"), source="`secure/src/nsc/mod.rs:1415`",
          when="After a tamper-triggered wipe.")
    f.add("fatal_error", ["! FATAL ERROR", "Secrets wiped", "Power-cycle", "to retry"],
          source="`secure/src/main.rs:4187` (panic handler)",
          when="Any secure-world panic after the UI is initialised (#484). Secrets are zeroized first.")


# ─────────────────────────────────────────────────────────────────────────────
# 06 — wallet info dialogs (address, counter sync)
# ─────────────────────────────────────────────────────────────────────────────
def build_info():
    f = family("06-wallet-dialogs", "Wallet address and counter-sync dialogs",
               "Small confirm dialogs outside the sign path. The slot-rotation consent that precedes a "
               "Type-1 registration is in family 10 (captured).")
    p = confirm_pages([["Wallet addr #0"] + addr_rows(WALLET)])
    f.add("wallet_address", p[0], source="`secure/src/tx/display/wallet_address.rs:33` (`build_wallet_address_page`)",
          when="CMD_GET_WALLET_ADDRESS with the show-on-device flag: the CREATE2 address must be confirmed "
               "(long-R) before it is released to the companion. Single page, ` 1/1` overlay on the address tail.")
    pages = confirm_pages([
        ["", centered("SYNC COUNTER?"), centered("Off-chain floor"), ""],
        ["Chain: 1", "(Mainnet)", "Account: 0", "Slot: 1"],
        ["Current: 12", centered("L=Cancel"), "Target: 40", centered("R=Confirm")],
    ])
    for i, pg in enumerate(pages):
        f.add(f"offchain_sync_p{i}", pg,
              source="`secure/src/tx/display/offchain_sync.rs:43` (`build_offchain_sync_pages`)",
              when=["CMD_OFFCHAIN_SYNC page 1: intent banner.",
                    "Page 2: chain / account / slot being synced.",
                    "Page 3: the exact counter transition (current → target) to authorise."][i])
    f.add("wallet_check_progress", progress("Wallet check", 30),
          source="`secure/src/nsc/cmd_get_wallet_address.rs:94` (`progress_title`)",
          when="Bootstrap C10 keygen while deriving the wallet address (<1 s).")


# ─────────────────────────────────────────────────────────────────────────────
# 07 — off-chain EIP-1271 (composed; the EIP-712 typed variant is captured in 10)
# ─────────────────────────────────────────────────────────────────────────────
def chain_rows(chain_id: int, name: str) -> list[str]:
    return [f"Chain: {chain_id}", f"({name})"]


def fp_pages(label: str, h: bytes) -> list[list[str]]:
    hx = h.hex()
    return [["8213 Fingerprint", label, "", "> verify off-dev"],
            [hx[0:16], hx[16:32], hx[32:48], hx[48:64]]]


def context_pages(deployed: bool, acct=0, slot=1, used=1, cap=65536, gap=1) -> list[list[str]]:
    return [
        ["Offchain signer", f"Account: {acct}", f"Slot: {slot}", "> next"],
        ["Signing wallet"] + addr_rows(WALLET),
        ["DEPLOYED EIP1271" if deployed else "ERC-6492 WRAPPED", f"Use {used}/{cap}", f"Gap: {gap}", "L cancel/R sign"],
    ]


def personal_sign_pages(msg: bytes, deployed: bool, chain=(1, "Mainnet"), acct=0, slot=1, used=125, last=120, cap=65536):
    per = 3 * COLS
    n = max(1, (len(msg) + per - 1) // per)
    pages = [["EIP-1271 Sign?", "personal_sign", "Verify on dapp" if deployed else "! Undeployed sig", "> next"],
             ["Chain:"] + chain_rows(*chain) + ["> next"],
             [f"Account: {acct}", f"Slot: {slot}", "", "> next"],
             ["Signer:"] + addr_rows(WALLET)]
    for p in range(n):
        chunk = msg[p * per:(p + 1) * per].decode("ascii", "replace")
        rows = [chunk[i * COLS:(i + 1) * COLS] for i in range(3)]
        rows.append(f"Msg {p + 1}/{n}  > next")
        pages.append(rows)
    pages.append([f"{used}/{cap}", f"Gap: {used - last}", "L=Cancel", "R=Confirm"])
    return pages


def raw32_pages(h: bytes, deployed: bool, chain=(1, "Mainnet"), acct=0, slot=1, used=125, last=120, cap=65536):
    hx = h.hex()
    return [["EIP-1271 Sign?", "! BLIND RAW32", "Verify on dapp" if deployed else "! Undeployed sig", "> next"],
            ["Chain:"] + chain_rows(*chain) + ["> next"],
            [f"Account: {acct}", f"Slot: {slot}", "", "> next"],
            ["Hash 1/2:", hx[0:16], hx[16:32], "> next"],
            ["Hash 2/2:", hx[32:48], hx[48:64], "> next"],
            [f"{used}/{cap}", f"Gap: {used - last}", "L=Cancel", "R=Confirm"]]


def build_offchain():
    f = family("07-offchain-eip1271", "Off-chain signing (EIP-1271 personal_sign / raw32)",
               "CMD_SIGN_OFFCHAIN (`secure/src/nsc/cmd_sign_offchain.rs`). Page order per `cmd_sign_offchain.rs:886-1007`: "
               "renderer pages → ERC-8213 fingerprint pair → (raw32 only) ReplaySafe fingerprint pair → 3 context pages. "
               "The EIP-712 typed-data variant (ERC-7730 descriptor render) is captured live in family 10 (`Scenario 5p`). "
               "These are composed from `secure/src/tx/display/eip1271.rs` with sample values.")
    msg = b"Login to app.example.com\nNonce: 8f3a9c2e1b"
    digest = keccak256(b"\x00" * 31 + bytes([len(msg)]) + msg)
    pages = confirm_pages(personal_sign_pages(msg, True) + fp_pages("CalldataDigest", digest) + context_pages(True))
    whens = ["Banner: kind + deployed/undeployed hint.", "Chain.", "Account + slot.", "Signing wallet (EIP-712 verifyingContract).",
             "Message text, 48 chars per page (non-ASCII → `?`).", "Budget `used/cap` + unbacked gap, confirm footer.",
             "ERC-8213 fingerprint banner (`erc8213.rs:139`).", "The 32-byte digest, 8 bytes per row.",
             "Context page 1 (`eip1271.rs:240`).", "Context page 2: wallet address.", "Context page 3: deployment mode + budget; long-R signs."]
    for i, pg in enumerate(pages):
        f.add(f"personal_sign_deployed_p{i}", pg,
              source="`secure/src/tx/display/eip1271.rs:321` (`render_eip1271_personal_sign_pages`)" if i < 6 else
                     ("`secure/src/tx/display/erc8213.rs:139`" if i < 8 else "`secure/src/tx/display/eip1271.rs:240` (`build_context_pages`)"),
              when=whens[i])
    p0 = confirm_pages(personal_sign_pages(msg, False, used=1, last=0))[0]
    f.add("personal_sign_counterfactual_banner", p0, source="`secure/src/tx/display/eip1271.rs:321`",
          when="Same flow when the wallet is not deployed yet (ERC-6492 wrap): banner row 2 differs; the last context page says `ERC-6492 WRAPPED`.")
    h = bytes.fromhex("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
    rs = keccak256(b"\x19\x01" + h)  # sample stand-in for the Solady replay-safe hash
    pages = confirm_pages(raw32_pages(h, True) + fp_pages("Raw32 Hash", h) + fp_pages("ReplaySafe Hash", rs) + context_pages(True))
    whens = ["Banner: loud BLIND RAW32.", "Chain.", "Account + slot.", "Hash bytes 0..16.", "Hash bytes 16..32.", "Budget + confirm footer.",
             "ERC-8213 banner (raw hash).", "Raw hash.", "ERC-8213 banner (the nested replay-safe hash actually signed).", "Replay-safe hash.",
             "Context 1.", "Context 2.", "Context 3."]
    for i, pg in enumerate(pages):
        f.add(f"raw32_deployed_p{i}", pg,
              source="`secure/src/tx/display/eip1271.rs:431` (`render_eip1271_raw32_pages`)" if i < 6 else
                     ("`secure/src/tx/display/erc8213.rs:139`" if i < 10 else "`secure/src/tx/display/eip1271.rs:240`"),
              when=whens[i])
    f.add("eip1271_sign_progress", progress("EIP-1271 sign", 60), source="`secure/src/nsc/cmd_sign_offchain.rs:1190`",
          when="C10 signing after confirm (~1 s).")


# ─────────────────────────────────────────────────────────────────────────────
# 10 — captured sign flows
# ─────────────────────────────────────────────────────────────────────────────
# (row-0 prefix or row-1 prefix) → (page kind, source)
PAGE_KINDS: list[tuple[str, str, str]] = [
    ("Sign refused", "refusal status", "`secure/src/nsc/cmd_sign_userop.rs` (grep the text)"),
    ("Send ETH?", "tx header (intent + chain)", "`secure/src/tx/display/value_transfer.rs:29` (`render_pages`)"),
    ("Contract call?", "tx header (intent + chain)", "`secure/src/tx/display/value_transfer.rs:29`"),
    ("Value:", "value", "`secure/src/tx/display/value_transfer.rs` + `pqsigner-erc7730/src/display/primitives.rs`"),
    ("Fees: max / tip", "legacy fee page", "`secure/src/tx/display/value_page.rs:408` (`build_legacy_fee_pages`) → `pqsigner-erc7730/src/display/primitives.rs`"),
    ("Worst-case:", "worst-case fee page", "`secure/src/tx/display/value_page.rs:408` → `pqsigner-erc7730/src/display/primitives.rs`"),
    ("Nonce:", "nonce + data + confirm footer", "`secure/src/tx/display/value_transfer.rs` / the flow's renderer"),
    ("! NATIVE ", "loud native-value page (value != 0)", "`secure/src/tx/display/value_page.rs:278` (`build_native_value_page`)"),
    ("Signer acct #", "mandatory signer identity page", "`secure/src/tx/display/value_page.rs:134` (`build_signer_identity_page`)"),
    ("Target contract:", "mandatory target page", "`secure/src/tx/display/value_page.rs:203` (`build_target_identity_page`)"),
    ("Call:", "ERC-4337 gas lane", "`secure/src/tx/display/userop_gas_lane.rs:259` (`build_gas_lane_page`)"),
    ("8213 Fingerprint", "ERC-8213 fingerprint banner (next page = hash)", "`secure/src/tx/display/erc8213.rs:139` (`build_fingerprint_pair`)"),
    ("! PAYMASTER SET", "paymaster warning", "`secure/src/tx/display/value_page.rs:539`"),
    ("Nonce lane key:", "non-zero EntryPoint nonce lane", "`secure/src/tx/display/nonce_lane.rs:117`"),
    ("DEPLOY FACTORY:", "deployment consent", "`secure/src/tx/display/deployment.rs:243`"),
    ("! BLIND SIGN", "blind-sign banner", "`secure/src/tx/display/blind_sign.rs:32` (`render_blind_sign_pages`) / `typed_call/mod.rs` for `selector(args)` banners"),
    ("FUNCTION:", "blind-sign known function name", "`secure/src/tx/display/blind_sign.rs`"),
    ("Value: 0 ETH", "blind-sign value", "`secure/src/tx/display/blind_sign.rs`"),
    ("Sel: 0x", "blind-sign selector + length", "`secure/src/tx/display/blind_sign.rs`"),
    ("Data hash:", "blind-sign calldata hash", "`secure/src/tx/display/blind_sign.rs`"),
    ("! UNVERIFIED", "self-attested typed call banner", "`secure/src/tx/display/typed_call/mod.rs`"),
    ("arg ", "typed-call argument", "`secure/src/tx/display/typed_call/mod.rs` + `pqsigner-erc7730/src/render/resolve.rs`"),
    ("To:", "recipient / target", "the flow's renderer (`value_transfer.rs`, `blind_sign.rs`, `typed_call/mod.rs`)"),
    ("Chain:", "chain page", "`pqsigner-erc7730/src/display/primitives.rs` (`write_chain`)"),
    ("Approve Safe TX", "Safe approveHash banner", "`secure/src/tx/display/safe_display.rs:510` (`render_safe_v1_pages`)"),
    ("Execute Safe TX", "Safe execTransaction banner", "`secure/src/tx/display/safe_display.rs:569` (`render_safe_exec_pages`)"),
    ("Send ", "known ERC-20 header", "`secure/src/tx/display/erc20_known.rs:29`"),
    ("Approve ", "known ERC-20 approve header", "`secure/src/tx/display/erc20_known.rs:29`"),
    ("Recipient:", "ERC-20 recipient", "`secure/src/tx/display/erc20_known.rs` / `erc20_unknown.rs` / `safe_display.rs`"),
    ("Amount:", "ERC-20 amount", "`secure/src/tx/display/erc20_known.rs`"),
    ("Amount (raw):", "unknown-token raw amount", "`secure/src/tx/display/erc20_unknown.rs:15`"),
    ("! Unknown token", "unknown ERC-20 banner", "`secure/src/tx/display/erc20_unknown.rs:15`"),
    ("Contract:", "token contract", "`secure/src/tx/display/erc20_known.rs` / `erc20_unknown.rs` / `safe_display.rs`"),
    ("Safe:", "Safe address", "`secure/src/tx/display/safe_display.rs:607`"),
    ("SafeTx #", "Safe nonce / op / inner kind", "`secure/src/tx/display/safe_display.rs:607` + `:1254` (`write_inner_kind_hint`)"),
    ("(execute now)", "Safe exec op + inner", "`secure/src/tx/display/safe_display.rs`"),
    ("Empty call to:", "Safe empty inner call", "`secure/src/tx/display/safe_display.rs:1642`"),
    ("ERC-20 call", "Safe inner ERC-20 (unverified)", "`secure/src/tx/display/safe_display.rs:1642` (`append_inner_kind_pages`)"),
    ("Raw amount:", "Safe inner ERC-20 raw amount", "`secure/src/tx/display/safe_display.rs:1835`"),
    ("Long-press to", "Safe confirm footer", "`secure/src/tx/display/safe_display.rs`"),
    ("MSend rec", "multiSend record divider", "`secure/src/tx/display/safe_display.rs:2027` (`write_msend_divider_page`)"),
    ("CoW VaultRelayer", "named spender (CoW)", "`secure/src/tx/display/safe_display.rs` + `secure/src/names/`"),
    ("CowSwap order", "CoW order banner", "`secure/src/tx/eip712/cowswap_display.rs` (`append_order_body_pages`)"),
    ("Sell addr;amtHex", "CoW sell leg (next page = amount hex)", "`secure/src/tx/eip712/cowswap_display.rs`"),
    ("Buy addr;amtHex", "CoW buy leg (next page = amount hex)", "`secure/src/tx/eip712/cowswap_display.rs`"),
    ("Receiver:", "CoW receiver", "`secure/src/tx/eip712/cowswap_display.rs`"),
    ("Expires:", "CoW validity", "`secure/src/tx/eip712/cowswap_display.rs`"),
    ("Fee (sell tok):", "CoW fee + balance sources", "`secure/src/tx/eip712/cowswap_display.rs`"),
    ("appData:", "CoW appData", "`secure/src/tx/eip712/cowswap_display.rs`"),
    ("** DEV BUILD **", "ERC-7730 unattested-descriptor warning (dev builds only)", "`pqsigner-erc7730/src/display/render/intent.rs:52`"),
    ("Network:", "ERC-7730 chain page", "`pqsigner-erc7730/src/display/render/mod.rs`"),
    ("Max fee/", "ERC-7730 fee page", "`pqsigner-erc7730/src/display/render/mod.rs`"),
    ("Max total/", "ERC-7730 worst-case page", "`pqsigner-erc7730/src/display/render/mod.rs`"),
    ("Gas:", "ERC-7730 worst-case page", "`pqsigner-erc7730/src/display/render/mod.rs`"),
    ("Nonce (hex):", "ERC-7730 nonce (2 pages)", "`pqsigner-erc7730/src/display/render/mod.rs`"),
    ("Offchain signer", "off-chain context page 1", "`secure/src/tx/display/eip1271.rs:240`"),
    ("Signing wallet", "off-chain context page 2", "`secure/src/tx/display/eip1271.rs:240`"),
    ("DEPLOYED EIP1271", "off-chain context page 3", "`secure/src/tx/display/eip1271.rs:240`"),
    ("ERC-6492 WRAPPED", "off-chain context page 3", "`secure/src/tx/display/eip1271.rs:240`"),
]
ROW1_KINDS = [
    ("ROTATE SLOT?", "slot-rotation consent (Type-1)", "`secure/src/tx/display/slot_rotation.rs:36` (`build_slot_rotation_pages`)"),
    ("BATCH SIGN", "batch banner", "`secure/src/tx/display/batch.rs:154` (`build_batch_banner_page`)"),
    ("Sign ", "batch final summary", "`secure/src/tx/display/batch.rs:220` (`build_final_summary_pages`)"),
]
HEXROW = re.compile(r"^[0-9a-f]{16}$")


def classify(rows: list[str], prev_kind: str | None) -> tuple[str, str]:
    r0, r1 = rows[0], rows[1]
    if r0.strip() == "" and r1.strip() and rows[3].startswith("["):
        return ("progress bar", "`secure/src/ui/mod.rs` `show_progress` (call sites in `secure/src/nsc/cmd_sign_userop*.rs`)")
    if r0.strip() == "" and rows[3].strip() == "" and r1.strip():
        for pre, kind, src in ROW1_KINDS:
            if r1.strip().startswith(pre):
                return (kind, src)
        return ("status message", "`secure/src/ui/mod.rs` `show_status` — see 90-status-messages.md")
    if r0.strip() == "" and r1.strip() == "" and rows[2].startswith("L=Cancel"):
        return ("ERC-7730 confirm footer page", "`pqsigner-erc7730/src/display/render/mod.rs`")
    for pre, kind, src in ROW1_KINDS:
        if r1.strip().startswith(pre):
            return (kind, src)
    if HEXROW.match(r0.strip()) or (r0.strip() and re.fullmatch(r"[0-9a-f ]+", r0.strip()) and r0.strip() == r0.rstrip() and len(r0.strip()) == 16):
        return (f"continuation of previous page ({prev_kind})", "same renderer as the previous page")
    for pre, kind, src in PAGE_KINDS:
        if r0.startswith(pre):
            return (kind, src)
    # ERC-7730 intent / field pages: title on row 0, value rows, "> next" or "N bytes"
    return ("ERC-7730 descriptor page (intent / field)", "`pqsigner-erc7730/src/display/render/{intent,formatters,mod}.rs` — text comes from the descriptor")


SCENARIOS = [
    # (scenario key, family key, screen base id, title, description)
    ("Scenario 2", "10-sign-eth", "eth_transfer",
     "ETH transfer, normal Type-2 sign",
     "The common case: `CMD_SIGN_USEROP` with a plain value transfer on an already-registered slot."),
    ("Scenario 1", "10-sign-eth", "eth_transfer_with_slot_registration",
     "ETH transfer that also registers a new slot (Type-1 + Type-2)",
     "A 3-page slot-rotation consent (bootstrap key use) is confirmed first, then the normal transfer dialog."),
    ("Scenario 5w", "10-sign-eth", "eth_transfer_named_recipient",
     "ETH transfer to a known named address",
     "When the recipient is in the verified address-name DB the `To:` page shows the name plus a shortened address."),
    ("Scenario 5g", "10-sign-eth", "batch_contract_call_zero_value",
     "Zero-value contract call inside a 4-tx batch",
     "Shows the `Contract call?` header variant and the batch banner; only the first tx is kept here (see family 15 for full batches)."),
    ("Scenario 5v", "11-sign-erc20", "erc20_transfer_known_token",
     "ERC-20 transfer of a token in the trusted DB (TEL on Base)",
     "Token name/symbol/decimals come from the firmware-pinned ERC-20 Merkle root; a slot registration precedes it in this capture."),
    ("Scenario 5c", "12-sign-blind-typed", "blind_sign_unknown_call",
     "Blind sign, unknown selector",
     "Calldata that decodes to nothing known: loud banner, selector, length and hash."),
    ("Scenario 5d", "12-sign-blind-typed", "blind_sign_known_function_name",
     "Blind sign with a verified function name",
     "A selector bundle proved the human-readable signature, but the args are not clear-signed."),
    ("Scenario 5b", "12-sign-blind-typed", "typed_call_curated",
     "Typed-call render from the curated selector DB",
     "`balanceOf(address)` decoded on-device: banner shows the signature, then one page per argument."),
    ("Scenario 5j", "12-sign-blind-typed", "typed_call_self_attested",
     "Typed-call render from a self-attested (unverified) ABI",
     "Same layout with the `! UNVERIFIED` banner because the ABI text was companion-supplied."),
    ("Scenario 5", "13-sign-safe-cow", "safe_approvehash_erc20",
     "Safe approveHash with an inner ERC-20 transfer",
     "SafeTx typed-data verified in S-world; the inner call is decoded and rendered per record."),
    ("Scenario 0h", "13-sign-safe-cow", "safe_exec_empty_call",
     "Safe execTransaction, empty inner call",
     "The `Execute Safe TX` banner variant."),
    ("Scenario 5q", "13-sign-safe-cow", "safe_cow_presign",
     "Safe-wrapped CoW Swap order (setPreSignature)",
     "The CoW order bound to the presign calldata is decoded on-device and rendered inside the Safe context."),
    ("Scenario 5s", "13-sign-safe-cow", "safe_multisend_approve_presign",
     "Safe multiSend: approve(vault relayer) + setPreSignature",
     "The Safe web-UI shape: two records with divider pages, each routed through the same inner ladder."),
    ("Scenario 5m", "14-sign-erc7730", "erc7730_wrap_weth",
     "ERC-7730 clear-sign (WETH wrap)",
     "Descriptor-driven intent + fields, then the ERC-7730 fee/nonce pages and the mandatory trailer pages. "
     "`** DEV BUILD **` appears only on dev builds with unattested descriptors."),
    ("Scenario 5m-nested", "14-sign-erc7730", "erc7730_nested_forwarder",
     "ERC-7730 nested calldata (forwarder → token transfer)",
     "Two descriptor blocks rendered in sequence; 256-bit amounts split over 2 pages when not exactly renderable."),
    ("Scenario 5m-multi-tail", "14-sign-erc7730", "erc7730_string_fields",
     "ERC-7730 with string fields",
     "Short string fields render inline with a byte count in the footer."),
    ("Scenario 5e", "15-sign-batch", "batch_eth_unknown_token_blind",
     "Atomic batch of 3 (ETH + unknown token + blind)",
     "Each member gets a `BATCH SIGN Tx i of N` banner and its own full dialog; a final summary confirms the whole batch."),
    ("Scenario 5f", "15-sign-batch", "batch_single_1wei",
     "Degenerate 1-tx batch (1 wei)",
     "Shows the base-unit (`wei`) value rendering."),
    ("Scenario 5e-rt-erc20", "15-sign-batch", "batch_erc7730_token_amounts",
     "Batch of 2 ERC-7730 renders with token amounts",
     "Token metadata comes from the ERC-20 DB, never from the descriptor."),
    ("Scenario 5p", "16-offchain-eip712", "eip712_typed_erc7730",
     "Off-chain EIP-712 typed-data sign via ERC-7730 descriptor",
     "`CMD_SIGN_OFFCHAIN` kind EIP712_TYPED: descriptor pages → ERC-8213 `EIP-712 Final` fingerprint → 3 context pages. "
     "The capture ends with a second, refused request (one-bit domain mismatch)."),
]

FLOW_FAMILY_INTROS = {
    "10-sign-eth": ("Sign flows: ETH transfers", "Captured live from the firmware (`make e2e`). Every page is exactly what the panel shows, including the ` i/n` page counter the confirm dialog overlays. Short R/L taps page forward/back; long-R on the last page confirms; long-L cancels."),
    "11-sign-erc20": ("Sign flows: ERC-20", "Captured live. Known tokens render name/symbol/decimals; unknown tokens render the raw amount (see the batch capture in family 15 for the unknown-token variant)."),
    "12-sign-blind-typed": ("Sign flows: blind sign and typed calls", "Captured live. The blind path is the loud fallback for calldata nothing else could decode."),
    "13-sign-safe-cow": ("Sign flows: Safe and CoW Swap", "Captured live. Safe typed-data is verified in the secure world and the inner call is clear-signed per record."),
    "14-sign-erc7730": ("Sign flows: ERC-7730 clear-signing", "Captured live. The descriptor text (intent, field labels) is data from the ERC-7730 bundle; the fee/nonce/network pages are rendered by `pqsigner-erc7730/src/display/render/`."),
    "15-sign-batch": ("Sign flows: batch", "Captured live. `CMD_SIGN_USEROP_BATCH`: per-tx banner + dialog, then one final summary confirm."),
    "16-offchain-eip712": ("Off-chain EIP-712 typed data (captured)", "Captured live. Complements the composed personal_sign / raw32 flows in family 07."),
}


def build_flows(captures: dict):
    fams: dict[str, Family] = {}
    for key, (title, intro) in FLOW_FAMILY_INTROS.items():
        fams[key] = family(key, title, intro)
    for scen, fam_key, base, title, desc in SCENARIOS:
        frames = captures.get(scen)
        if not frames:
            continue
        fam = fams[fam_key]
        if base == "batch_contract_call_zero_value":
            # keep only up to the first member's fingerprint hash page
            cut = 0
            for i, fr in enumerate(frames):
                if fr[1].strip().startswith("BATCH SIGN") and i > 1:
                    cut = i
                    break
            frames = frames[:cut] if cut else frames
        prev_kind = None
        fam.screens.append(Screen(fam_key, f"{base}__title", [], notes=f"## {title}\n\n{desc}\n\nSource capture: `{scen}` in `_captures/e2e_frames.json`.", origin="captured"))
        for i, fr in enumerate(frames):
            kind, src = classify(fr, prev_kind)
            prev_kind = kind
            fam.add(f"{base}_p{i:02d}", fr, source=src, when=kind, origin="captured")


# ─────────────────────────────────────────────────────────────────────────────
# 90 — every status message (production paths)
# ─────────────────────────────────────────────────────────────────────────────
DEV_GATE = re.compile(r"e2e|test|bench|probe|stress|diag|golden|pulse|splash-test|duress-ui|factory-provisioning|prodtest|self-test|rollback|debug-log|admin-wipe|multi-unlock|rotate-scp03|factory-reset|wipe-for|crash|extract|mock-se|lcd-test|button-test", re.I)


# Files whose #[cfg] gate sits on the `mod` declaration (secure/src/nsc/mod.rs)
# rather than inside the file.
FILE_GATES = {
    "secure/src/nsc/cmd_test_pin_lockout.rs": 'feature = "e2e-test"',
    "secure/src/nsc/cmd_sign_userop_forced.rs": 'feature = "erc7730-forced-blind"',
    "secure/src/tx/display/forced_blind.rs": 'feature = "erc7730-forced-blind"',
}


def scan_status_sites() -> list[tuple[str, str, str, str]]:
    """Every literal show_status / show_progress call in secure/src with its
    enclosing #[cfg] gates. Returns (title, sub, file:line, gates)."""
    out = []
    for path in sorted((ROOT / "secure" / "src").rglob("*.rs")):
        rel = os.path.relpath(path, ROOT)
        if re.search(r"(_tests?\.rs|/tests?/|pure_tests|se050_stress|prodtest|ui_under_test)", rel):
            continue
        file_gate = FILE_GATES.get(rel, "")
        L = path.read_text(errors="replace").split("\n")
        for i, l in enumerate(L):
            m = re.search(r'show_(status|progress)\(\s*"([^"]*)"\s*,\s*("([^"]*)"|[^)]*)\)', l)
            if not m or l.strip().startswith("//"):
                continue
            kind, title = m.group(1), m.group(2)
            sub = m.group(4) if m.group(4) is not None else ("<progress>" if kind == "progress" else "<dynamic>")
            # gate scan: attributes directly above each enclosing block
            ind = len(l) - len(l.lstrip())
            gates, cur, collecting = [], ind, False
            for j in range(i - 1, -1, -1):
                s = L[j]
                if not s.strip():
                    continue
                si, st = len(s) - len(s.lstrip()), s.strip()
                if st.startswith("#[") and collecting and si == cur:
                    if st.startswith("#[cfg("):
                        gates.append(st[6:-1])
                    continue
                if st.startswith("//"):
                    continue
                if si < cur:
                    cur, collecting = si, True
                    if si == 0 and (st.startswith("fn ") or st.startswith("pub")):
                        for k in range(j - 1, -1, -1):
                            t = L[k].strip()
                            if t.startswith("#[cfg("):
                                gates.append(t[6:-1])
                            elif t.startswith("#[") or t.startswith("//") or not t:
                                continue
                            else:
                                break
                        break
                else:
                    collecting = False
            if file_gate:
                gates.append(file_gate)
            out.append((title, sub, f"{rel}:{i + 1}", " & ".join(gates)))
    return out


def build_status_family(sites):
    f = family("90-status-messages", "All status messages (production paths)",
               "Every `show_status(title, sub)` / `show_progress(title, …)` call reachable in a shipping "
               "build, deduplicated by text. Same layout for all: title on row 2, sub on row 3 "
               "(`secure/src/ui/mod.rs`). Most are error/refusal texts shown for a moment before the "
               "device returns to `PQSigner OS / Ready`. Sub-lines longer than 16 characters are clipped on the panel.")
    seen: dict[tuple[str, str], list[str]] = {}
    feat: dict[tuple[str, str], set[str]] = {}
    for title, sub, loc, gates in sites:
        if DEV_GATE.search(gates):
            continue
        seen.setdefault((title, sub), []).append(loc)
        for g in re.findall(r'feature = "([^"]+)"', gates):
            feat.setdefault((title, sub), set()).add(g)
    for (title, sub), locs in sorted(seen.items()):
        gate_note = ""
        if feat.get((title, sub)):
            gate_note = "only with feature(s): " + ", ".join(sorted(feat[(title, sub)]))
        sid = re.sub(r"[^a-z0-9]+", "_", f"{title}_{sub}".lower()).strip("_")[:60]
        if sub == "<progress>":
            rows = progress(title, 50)
        elif sub == "<dynamic>":
            rows = status(title, "<dynamic text>")
        else:
            rows = status(title, sub)
        f.add(sid, rows, source=", ".join(f"`{l}`" for l in locs[:8]) + (f" (+{len(locs) - 8})" if len(locs) > 8 else ""),
              when=gate_note, notes=("clipped: sub-line > 16 chars" if len(sub) > COLS else ""))
    f.add("sign_v3_len_cap_debug", ["Sign v3 len>cap", "d=0000", "e=0000 r=0000", "v3=1234"],
          source="`secure/src/nsc/cmd_sign_userop.rs:488`",
          when="Refusal with a 4-line diagnostic (declared trailer lengths in hex) when a v3 sign payload exceeds the cap.")
    return f


# ─────────────────────────────────────────────────────────────────────────────
# Output
# ─────────────────────────────────────────────────────────────────────────────
def box(rows: list[str]) -> str:
    inner = [f"|{r}|" for r in rows]
    return "\n".join(["+" + "-" * COLS + "+", *inner, "+" + "-" * COLS + "+"])


def write_family(fam: Family):
    md = [f"# {fam.title}", "", fam.intro, "",
          f"Contact sheet: [`sheets/{fam.key}.png`](sheets/{fam.key}.png)", ""]
    real = [s for s in fam.screens if s.rows]
    for s in fam.screens:
        if not s.rows:
            md.append(s.notes)
            md.append("")
            continue
        rows = s.norm()
        md.append(f"### `{fam.key}/{s.id}`")
        md.append("")
        md.append("```text")
        md.append(box(rows))
        md.append("```")
        md.append("")
        md.append(f"![{s.id}](preview/{fam.key}/{s.id}.png)")
        md.append("")
        if s.when:
            md.append(f"- **What/when:** {s.when}")
        if s.source:
            md.append(f"- **Source:** {s.source}")
        md.append(f"- **Origin:** {'captured from the running firmware (QEMU e2e)' if s.origin == 'captured' else 'composed from the firmware source; sample values for dynamic fields'}")
        if s.notes:
            md.append(f"- **Note:** {s.notes}")
        md.append("")
    (OUT / f"{fam.key}.md").write_text("\n".join(md))
    # PNGs
    (OUT / "png" / fam.key).mkdir(parents=True, exist_ok=True)
    (OUT / "preview" / fam.key).mkdir(parents=True, exist_ok=True)
    for s in real:
        rows = s.norm()
        render_png(rows).save(OUT / "png" / fam.key / f"{s.id}.png")
        render_png(rows, PREVIEW_SCALE).save(OUT / "preview" / fam.key / f"{s.id}.png")
    # contact sheet
    write_sheet(fam, real)


def write_sheet(fam: Family, screens: list[Screen]):
    (OUT / "sheets").mkdir(parents=True, exist_ok=True)
    if not screens:
        return
    sc = 2
    cw, ch = W * sc, H * sc
    pad, cap = 16, 22
    cols = 3
    n = len(screens)
    rws = (n + cols - 1) // cols
    sheet = Image.new("RGB", (cols * (cw + pad) + pad, rws * (ch + cap + pad) + pad), (40, 40, 40))
    d = ImageDraw.Draw(sheet)
    for i, s in enumerate(screens):
        x = pad + (i % cols) * (cw + pad)
        y = pad + (i // cols) * (ch + cap + pad)
        d.text((x, y + 4), f"{s.id}", fill=(230, 230, 230))
        sheet.paste(render_png(s.norm(), sc), (x, y + cap))
    sheet.save(OUT / "sheets" / f"{fam.key}.png")


def write_screens_txt():
    lines = ["# Every screen, one block each: `@@ family/id` then the 4 rows between | bars.",
             "# Edit the rows in place (16 columns max) and hand the file back to request changes.", ""]
    for fam in FAMILIES:
        for s in fam.screens:
            if not s.rows:
                continue
            lines.append(f"@@ {fam.key}/{s.id}")
            lines.extend(f"|{r}|" for r in s.norm())
            lines.append("")
    (OUT / "screens.txt").write_text("\n".join(lines))


def write_readme(n_screens: int, n_status: int):
    fam_lines = []
    for fam in FAMILIES:
        n = sum(1 for s in fam.screens if s.rows)
        fam_lines.append(f"| [{fam.key}]({fam.key}.md) | {fam.title} | {n} |")
    md = f"""# PQSigner OS — trusted-display screen catalogue

Every screen the device can show, exported for UI work. Regenerate with
`python3 tools/ui_screens_export.py` (see the bottom of this file).

## The display in one paragraph

The NV3007 panel is used as a **16 column × 4 row character grid** (428 × 142 px landscape,
white on black, 5×8 font scaled 3×). There are no icons, no colours, no proportional text:
a screen *is* four 16-character lines. Input is **two buttons**, Left and Right, each with a
short tap and a long press (≈500 ms). Every dialog uses the same grammar:

| Gesture | Menus / PIN / word picker | Confirm dialogs (sign, address, fw-update) |
|---|---|---|
| R tap | next option / digit up / next letter | next page |
| L tap | previous option / digit down | previous page |
| R long | select / confirm | **confirm** (only allowed once the last page has been seen) |
| L long | back / cancel | cancel |

Confirm dialogs are pre-rendered as a list of pages; the dialog code
(`secure/src/ui/confirm.rs`) draws them and overlays a right-aligned ` i/n` page counter on the
footer row whenever it fits. Status messages (`show_status`) put the title on row 2 and a
sub-line on row 3; progress bars (`show_progress`) use row 4.

## How to ask for a change

Every screen has an id `family/screen_id` and a source pointer. Either:

1. Edit the rows in [`screens.txt`](screens.txt) (keep 16 columns) and send the file back, or
2. Say e.g. *"`02-pin-unlock/wrong_pin`: row 2 → `PIN incorrect`, row 3 → `3 tries left`"*.

Anything that changes a **sign-flow page** (families 10–16) also changes the FI page-proof
expectations and the WYSIWYS tests, so those edits are heavier than status/menu text.
Texts marked *clipped* in the notes currently overflow the 16 columns and are worth fixing first.

## Families

| File | Family | Screens |
|---|---|---|
{chr(10).join(fam_lines)}

Total: {n_screens} screens ({n_status} of them status messages).
Per family you get the markdown (ASCII box + preview image + source + when), the pixel-exact PNGs in
`png/<family>/`, {PREVIEW_SCALE}× previews in `preview/<family>/` and a contact sheet in `sheets/<family>.png`.

## Two kinds of screens

* **captured** — printed by the real firmware running under QEMU (`make e2e`), stored in
  `_captures/e2e_frames.json`. Byte-exact for the sample inputs of that scenario.
* **composed** — built by the exporter from the firmware's string literals and layout code for
  screens the e2e suite never reaches (boot, PIN, seed wizard, firmware update, wipe, off-chain
  personal_sign). Layout is exact; dynamic values (addresses, words, numbers) are samples.

Not exported: bench/test-only screens compiled behind dev feature flags (se050-stress,
crash-safety, PIN-gate harness, LCD orientation test, prodtest patterns, factory provisioning
operator screens). The FSBL's own fingerprint screen renders the same 8 words as
`01-boot/measured_boot_words`.

## The recurring trailer of every on-chain sign dialog

After the per-transaction pages, `pick_sign_pages` (`secure/src/tx/display/dispatch.rs`) always
appends, in this order: the loud `! NATIVE ETH` value page (if value ≠ 0) · `Signer acct #N` +
wallet address · `Target contract:` · the ERC-4337 gas lane (`Call/Verify/PreVer/Total`) ·
the two ERC-8213 fingerprint pages · optionally `! PAYMASTER SET`, `Nonce lane key:` and
`DEPLOY FACTORY:` pages. These are mandatory WYSIWYS pages; see the source pointers in the flow files.

## Regenerating

```bash
python3 tools/ui_screens_export.py                       # from the stored captures
make e2e > /tmp/e2e.log 2>&1 && \\
python3 tools/ui_screens_export.py --e2e-log /tmp/e2e.log   # refresh captures first
```

The exporter's panel renderer is a Python port of `tools/lcd_render` (verified pixel-identical);
`tools/lcd_render` still exists for single-screen renders and the CH347 panel-push bridge.
"""
    (OUT / "README.md").write_text(md)


def parse_e2e_log(path: Path) -> dict:
    L = path.read_text(errors="replace").split("\n")
    scen, frames, order, i = None, {}, [], 0
    while i < len(L):
        l = L[i]
        m = re.match(r"\[NS\]\[e2e\] (Scenario [^:]+):", l)
        if m:
            scen = m.group(1)
            order.append(scen)
            frames[scen] = []
            i += 1
            continue
        if l.strip() == "+----------------+" and i + 5 < len(L) and L[i + 5].strip() == "+----------------+":
            rows = [L[i + 1 + k].strip()[1:-1] for k in range(4)]
            if scen is not None:
                frames[scen].append(rows)
            i += 6
            continue
        i += 1

    def collapse(fr):
        out = []
        for f in fr:
            if out and out[-1] == f:
                continue
            if out and f[1] == out[-1][1] and f[3].startswith("[") and out[-1][3].startswith("["):
                out[-1] = f
                continue
            out.append(f)
        return out

    return {s: collapse(frames[s]) for s in order}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--e2e-log", help="refresh _captures/e2e_frames.json from a `make e2e` log")
    ap.add_argument("--px", metavar="LOG", help="pixel-UI catalogue (docs/ui-screens/px/) from a `make e2e-px` log's [UI-PXR] records, rendered by the real engine")
    args = ap.parse_args()
    if args.px:
        import ui_px_screens  # sibling module

        ui_px_screens.export(Path(args.px))
        return
    OUT.mkdir(parents=True, exist_ok=True)
    if args.e2e_log:
        caps = parse_e2e_log(Path(args.e2e_log))
        CAPTURES.parent.mkdir(parents=True, exist_ok=True)
        CAPTURES.write_text(json.dumps(caps, indent=0))
    captures = json.loads(CAPTURES.read_text()) if CAPTURES.exists() else {}

    build_boot()
    build_pin()
    build_wizard()
    build_fw()
    build_wipe()
    build_info()
    build_offchain()
    build_flows(captures)
    sites = scan_status_sites()
    build_status_family(sites)

    for fam in FAMILIES:
        write_family(fam)
    write_screens_txt()
    n = sum(1 for f in FAMILIES for s in f.screens if s.rows)
    n_status = sum(1 for s in FAMILIES[-1].screens if s.rows)
    write_readme(n, n_status)
    print(f"wrote {n} screens across {len(FAMILIES)} families → {OUT}")


if __name__ == "__main__":
    main()

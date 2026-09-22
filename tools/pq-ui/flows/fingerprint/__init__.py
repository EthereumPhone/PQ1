"""FINGERPRINT flow family — the device showing a cryptographic digest for
the user to match against an independent source (ERC-8213: Wallet
Signature and Calldata Digest Display — the short, reproducible
fingerprint of what is about to be signed), on the PQ1 grid.

Shared identity for every fingerprint flow: the digest is the DEVICE's
own reading of the bytes — a firmware action, not a token — so the
token wears the fingerprint mark (pq1/assets/fingerprint.svg traced as
procedural art, pq1/procedural/fingerprint.py, components.GLYPHS
["fingerprint"]) BLACK on a WHITE disc under a BLACK edge stroke (the
explicit ring, flush at the disc edge over the mark — the SAFE token's
stroke idiom — so the white body stands off the grey followers): the
mono look inverted, over the default grey trail
(colors.FINGERPRINT_GRADIENT — the MONO ramp pinned under its own name
with a WHITE fill, never hashed). The family has no brand, so the
endings keep the unbranded resting look — black disc, the state colour
on the ring stroke and the glyph — and ends(subject) captions them
"<SUBJECT> CONFIRMED" / "<SUBJECT> DECLINED".

The digest is ONE value read in full, on a VALUE screen (layout:
"value") — the hash alone, full width, centred on the panel, no token
on it: the circle slides off the left edge and back. digest(value)
turns a 0x hex string into that screen's value field at the 22 tier
(DESIGN.md § Typography: hashes are Default-tier content), the bytes
balanced over the fewest lines of BYTES_PER_LINE or fewer (the "0x"
riding on the first) — a 32-byte digest is three lines, 11 / 11 / 10
bytes, plain `lines`, no pager; a digest that overflows the three lines
turns PAGES (DESIGN.md § Text rules, Pages) and the pager "n/m" comes
with them. A new fingerprint flow is one module in this package:
DEFAULTS, ENDS = ends(<subject>), then its screens; render with
`python -m flows fingerprint/<name> --end all`
-> renders/flows/fingerprint/<name>/{success,cancel}/<name>_full_<end>.gif.
"""
import copy
import math

from pq1 import colors

ICON = "fingerprint"      # the traced fingerprint mark
PALETTE = "FINGERPRINT"   # the white disc over the mono trail (colors)
SIZE = 22                 # the Default tier: multi-line hashes
BYTES_PER_LINE = 13       # 26 hex characters — 28 with the "0x" — inside the
                          # full-width 22 budget (30) with room for the widest glyphs
LINES_PER_PAGE = 3        # the 22 tier's three lines (DESIGN.md § Typography)

DEFAULTS = dict(icon=ICON, icon_color=list(colors.BLACK),   # black mark …
                token=dict(palette=PALETTE,                 # … on the white disc …
                           ring=list(colors.BLACK)))        # … under a black edge stroke


def digest(value):
    """the digest's value field for a value screen — `lines` when it fits
    one screen (no pager), `pages` when it overflows the three lines (the
    pager "n/m" shows): the bytes balanced over the fewest lines of
    BYTES_PER_LINE or fewer, the "0x" riding on the first, LINES_PER_PAGE
    per page, one size for the screen"""
    prefix, hexs = ("0x", value[2:]) if value[:2].lower() == "0x" else ("", value)
    n_bytes = len(hexs) // 2
    n_lines = max(1, math.ceil(n_bytes / BYTES_PER_LINE))
    base, extra = divmod(n_bytes, n_lines)        # the first `extra` lines carry one more byte
    lines, at = [], 0
    for i in range(n_lines):
        take = 2 * (base + (1 if i < extra else 0))
        lines.append(hexs[at:at + take])
        at += take
    lines[0] = prefix + lines[0]
    pages = [lines[i:i + LINES_PER_PAGE] for i in range(0, len(lines), LINES_PER_PAGE)]
    if len(pages) == 1:
        return dict(lines=lines, size=SIZE)
    return dict(pages=pages, size=SIZE)


def ends(subject="DIGEST"):
    """fresh copies of the shared endings, captioned on the subject
    ("DIGEST CONFIRMED" / "DIGEST DECLINED"): CONFIRMED plays the qubit
    film resolving to the green check; DECLINED plays NO film — the cancel
    resolve (status.default_anim): the token resolves in place, red ring
    stroke and red X on the unfilled black disc"""
    return copy.deepcopy({
        "confirmed": dict(id="CONFIRMED", kind="status",
                          bottom=f"{subject} CONFIRMED", chev=None),
        "declined": dict(id="DECLINED", kind="status", result="x", state="failed",
                         bottom=f"{subject} DECLINED", chev=None),
    })

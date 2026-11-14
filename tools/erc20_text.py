"""
erc20_text.py — the ONE sanitizer for ERC-20 `name` / `symbol` strings that
enter `secure/data/erc20.json` (and `erc20-e2e.json`).

Every DB row is a Merkle leaf the device verifies with
`tx/src/erc20/bundle.rs::metadata_shape_is_device_verifiable`: name and symbol
must each be 1..=64 bytes of printable ASCII (0x20..=0x7e). A row that fails
that rule is committed to the root but can never render, and dbgen now refuses
to build such a DB. Both writers of the DB use this module:

  * tools/build_erc20_db.py        (upstream token lists -> DB)
  * tools/verify_erc20_decimals.py (on-chain name()/symbol() -> DB fixes)

Policy (2026-11-14):

  1. Strip control characters (Unicode category Cc); collapse whitespace; trim.
  2. Explicit, unambiguous folds: Tugrik sign `₮` -> `T` (Tether's own
     "USD₮" spelling), `€` -> `EUR`, `£` -> `GBP`, curly quotes -> ASCII
     quotes, en/em dash -> `-`, `Ø`/`ø` -> `O`/`o`, `ß` -> `ss`,
     `™` -> `(TM)`, `®` -> `(R)`.
  3. Unicode NFKD, then drop combining marks (é -> e, ñ -> n, ö -> o, ş -> s).
  4. If ANY non-ASCII character remains, the field is rejected (None) and the
     caller drops the whole row: the device then shows the raw amount and the
     token address as UNVERIFIED. Cyrillic / Greek / Armenian / other-script
     look-alikes are NEVER folded to Latin — a token named `ՍSDT` (Armenian
     U+054D) must not become a verified `USDT`. Ambiguous symbols (`¥`, which
     is both JPY and CNY) are likewise not guessed.
  5. Empty after cleaning -> None.
  6. Length (bytes; ASCII so bytes == chars):
       * name > 64: a trailing " (Ondo Tokenized)" becomes " (Ondo)"; if still
         > 64, cut at the last word boundary <= 61 bytes and append "...".
       * symbol > 64: rejected (a symbol is an identity; never truncate it).

The functions are idempotent: clean(clean(x)) == clean(x).

Stdlib only.
"""

from __future__ import annotations

import unicodedata

# tx/src/erc20/bundle.rs MAX_DISPLAY_FIELD
FIELD_MAX_BYTES = 64

# Name truncation: keep at most this many bytes before the ellipsis so the
# result is <= FIELD_MAX_BYTES.
ELLIPSIS = "..."
NAME_CUT_BYTES = FIELD_MAX_BYTES - len(ELLIPSIS)  # 61

ONDO_LONG_SUFFIX = " (Ondo Tokenized)"
ONDO_SHORT_SUFFIX = " (Ondo)"

# Explicit folds applied BEFORE NFKD. Each maps one code point to ASCII and is
# unambiguous (a currency sign with one ISO code, typographic punctuation, or
# a Latin letter whose ASCII base is not in doubt). Deliberately absent:
#   * any Cyrillic/Greek/Armenian/... letter (impersonation risk);
#   * `¥` (JPY or CNY), `ℏ`, `₸`, emoji, CJK.
SAFE_FOLDS: dict[str, str] = {
    "₮": "T",      # ₮ TUGRIK SIGN — Tether writes "USD₮"
    "€": "EUR",    # € EURO SIGN
    "£": "GBP",    # £ POUND SIGN
    "‘": "'",      # ‘ LEFT SINGLE QUOTATION MARK
    "’": "'",      # ’ RIGHT SINGLE QUOTATION MARK
    "“": '"',      # “ LEFT DOUBLE QUOTATION MARK
    "”": '"',      # ” RIGHT DOUBLE QUOTATION MARK
    "–": "-",      # – EN DASH
    "—": "-",      # — EM DASH
    "Ø": "O",      # Ø LATIN CAPITAL LETTER O WITH STROKE
    "ø": "o",      # ø LATIN SMALL LETTER O WITH STROKE
    "ß": "ss",     # ß LATIN SMALL LETTER SHARP S
    "™": "(TM)",   # ™ TRADE MARK SIGN (NFKD would glue "TM" to the word)
    "®": "(R)",    # ® REGISTERED SIGN
}


def is_device_text(s: str) -> bool:
    """True iff `s` is 1..=64 bytes of printable ASCII (the device rule)."""
    if not isinstance(s, str):
        return False
    b = s.encode("utf-8")
    return 1 <= len(b) <= FIELD_MAX_BYTES and all(0x20 <= c <= 0x7E for c in b)


def basic_clean(s) -> str | None:
    """Strip control characters, collapse whitespace, trim. Keeps any other
    Unicode intact (used for REPORTING on-chain values). '' -> None."""
    if not isinstance(s, str):
        return None
    s = "".join(" " if unicodedata.category(c) == "Cc" else c for c in s)
    s = " ".join(s.split())
    return s or None


def fold_ascii(s) -> str | None:
    """Steps 1-5 of the policy: the ASCII form of `s`, or None if `s` holds a
    character that has no safe ASCII fold (the row must then be dropped).
    No length policy is applied here."""
    s = basic_clean(s)
    if s is None:
        return None
    s = "".join(SAFE_FOLDS.get(c, c) for c in s)
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    # NFKD can introduce new whitespace (e.g. NBSP -> space); re-collapse.
    s = " ".join(s.split())
    if not s:
        return None
    if any(not (0x20 <= ord(c) <= 0x7E) for c in s):
        return None
    return s


def shorten_name(s: str) -> str:
    """Apply the name length policy to an already-ASCII string."""
    if len(s) <= FIELD_MAX_BYTES:
        return s
    if s.endswith(ONDO_LONG_SUFFIX):
        s = s[: -len(ONDO_LONG_SUFFIX)] + ONDO_SHORT_SUFFIX
        if len(s) <= FIELD_MAX_BYTES:
            return s
    head = s[: NAME_CUT_BYTES + 1]
    # Last word boundary at or before NAME_CUT_BYTES: a space whose prefix
    # fits. If there is none, hard-cut.
    cut = head.rfind(" ")
    head = s[:cut] if 0 < cut <= NAME_CUT_BYTES else s[:NAME_CUT_BYTES]
    head = head.rstrip()
    return head + ELLIPSIS


def clean_name(s) -> str | None:
    """Device-verifiable token name, or None (drop the row)."""
    s = fold_ascii(s)
    if s is None:
        return None
    s = shorten_name(s)
    return s if is_device_text(s) else None


def clean_symbol(s) -> str | None:
    """Device-verifiable token symbol, or None (drop the row). Never
    truncates."""
    s = fold_ascii(s)
    if s is None or not is_device_text(s):
        return None
    return s

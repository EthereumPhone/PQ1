#!/usr/bin/env python3
"""Curate a top-N function-selector → text-signature dataset for the wallet.

Source: a clone of `ethereum-lists/4bytes` (defaults to ~/Documents/4bytes-db).
Output: `secure/data/selectors.json`, consumed by `cargo run -p dbgen`.

Curation rules (in order):

  1. Take selectors ranked by usage frequency (the upstream
     `signatures_sorted_counted.lst.gz`). Default cutoff is N=2000;
     tunable via `--top-n`.

  2. For each selector, look up `signatures/<hex>` in the corpus. The
     upstream repo curates each file to a single canonical text
     signature (no semicolons in the wild as of 2024-12-21); we still
     defensively split on `;` and pick the first entry.

  3. Drop any text signature that:
       - is empty
       - exceeds SELECTOR_TEXT_SIG_MAX_LEN (63 bytes)
       - contains a non-printable-ASCII byte (0x20..=0x7e is the gate)
       - matches any line in the upstream `ignored.lst` collision deny-list

  4. Drop selectors whose corresponding `signatures/<hex>` file does
     not exist (a sorted-list rank with no resolved signature).

  5. Sanity-check the surviving text signature parses as `name(typelist)`:
       - has exactly one '(' and ends in ')'
       - the first character of `name` is [A-Za-z_]
       - the typelist body splits on commas into tokens that match a
         simple whitelist (uint*, int*, address, bool, bytes*, string,
         and arbitrarily-nested arrays/tuples). Anything outside the
         whitelist is dropped from this top-N pass; they can be
         re-included once the firmware-side type parser supports them.

The result is a JSON array of `{"selector": "0x...", "text_sig": "..."}`
objects — exactly what `dbgen::SelectorsRecord` expects.
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import sys
from pathlib import Path

SELECTOR_TEXT_SIG_MAX_LEN = 63

# Whitelist primitives. Arrays / nested tuples are supported by the
# recursive type validator below.
PRIMITIVE_RE = re.compile(
    r"^("
    # uintN / intN — N must be a multiple of 8 in 8..=256, or bare uint/int
    r"u?int(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?"
    r"|address"
    r"|bool"
    # bytes / bytesN where N in 1..=32, or unsized "bytes"
    r"|bytes(?:[1-9]|[12][0-9]|3[0-2])?"
    r"|string"
    r")$"
)


def is_primitive(t: str) -> bool:
    return bool(PRIMITIVE_RE.match(t))


def split_type_list(body: str) -> list[str]:
    """Split a top-level comma-separated type list, respecting nested
    parentheses (tuples) and brackets (arrays).
    """
    out: list[str] = []
    depth = 0
    cur = ""
    for ch in body:
        if ch == "(" or ch == "[":
            depth += 1
            cur += ch
        elif ch == ")" or ch == "]":
            depth -= 1
            cur += ch
        elif ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def is_valid_type(t: str) -> bool:
    """Recursive type validator. Accepts:
       - any primitive (PRIMITIVE_RE)
       - <type>[<digits-or-empty>]  → fixed or dynamic array
       - (<type>,<type>,...)        → tuple
    """
    if not t:
        return False
    # Strip trailing array suffixes one at a time.
    while True:
        m = re.match(r"^(.+?)(\[\d*\])$", t)
        if not m:
            break
        t = m.group(1)
    if t.startswith("(") and t.endswith(")"):
        inner = t[1:-1]
        if not inner:
            # Empty tuple is not allowed — Solidity never emits it.
            return False
        return all(is_valid_type(x) for x in split_type_list(inner))
    return is_primitive(t)


NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def is_valid_text_sig(text: str) -> bool:
    if not text or len(text) > SELECTOR_TEXT_SIG_MAX_LEN:
        return False
    # Printable ASCII only.
    for b in text.encode("utf-8", errors="replace"):
        if not (0x20 <= b < 0x7F):
            return False
    # Shape: name(typelist).
    open_paren = text.find("(")
    if open_paren < 1 or not text.endswith(")"):
        return False
    name = text[:open_paren]
    if not NAME_RE.match(name):
        return False
    body = text[open_paren + 1:-1]
    if not body:
        # Zero-arg call is fine.
        return True
    return all(is_valid_type(t) for t in split_type_list(body))


def parse_sorted_counted_line(line: str) -> tuple[str, int] | None:
    """Each line looks like:
        '1177023 0xa9059cbb-64'
    Returns (selector_hex_lower, count) or None if malformed.
    """
    line = line.strip()
    if not line:
        return None
    parts = line.split(None, 1)
    if len(parts) != 2:
        return None
    try:
        count = int(parts[0])
    except ValueError:
        return None
    sel_part = parts[1].split("-", 1)[0]
    if sel_part.startswith("0x") or sel_part.startswith("0X"):
        sel_part = sel_part[2:]
    sel_part = sel_part.lower()
    if len(sel_part) != 8 or any(c not in "0123456789abcdef" for c in sel_part):
        return None
    return (sel_part, count)


def load_ignored(corpus: Path) -> set[str]:
    f = corpus / "ignored.lst"
    if not f.exists():
        return set()
    return {ln.strip() for ln in f.read_text().splitlines() if ln.strip()}


def main() -> int:
    here = Path(__file__).resolve().parent
    repo_root = here.parent
    default_corpus = Path(os.path.expanduser("~/Documents/4bytes-db"))
    default_out = repo_root / "secure" / "data" / "selectors.json"

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--corpus",
        type=Path,
        default=default_corpus,
        help=f"Path to the cloned ethereum-lists/4bytes corpus "
             f"(default: {default_corpus})",
    )
    ap.add_argument("--top-n", type=int, default=2000, help="Top-N selectors by usage")
    ap.add_argument(
        "--out",
        type=Path,
        default=default_out,
        help=f"Output JSON path (default: {default_out})",
    )
    args = ap.parse_args()

    corpus = args.corpus
    if not (corpus / "signatures").is_dir():
        print(f"error: {corpus}/signatures/ not found", file=sys.stderr)
        return 1
    sorted_gz = corpus / "signatures_sorted_counted.lst.gz"
    if not sorted_gz.exists():
        print(f"error: {sorted_gz} not found", file=sys.stderr)
        return 1

    ignored = load_ignored(corpus)

    seen: set[str] = set()
    kept: list[dict[str, str]] = []
    dropped_no_file = 0
    dropped_invalid = 0
    dropped_ignored = 0
    dropped_dup = 0
    scanned = 0

    with gzip.open(sorted_gz, "rt", encoding="utf-8") as f:
        for line in f:
            scanned += 1
            parsed = parse_sorted_counted_line(line)
            if parsed is None:
                continue
            sel_hex, _count = parsed
            if sel_hex in seen:
                dropped_dup += 1
                continue
            seen.add(sel_hex)

            sig_path = corpus / "signatures" / sel_hex
            if not sig_path.exists():
                dropped_no_file += 1
                continue
            try:
                raw = sig_path.read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                dropped_no_file += 1
                continue

            # Defensive: split on ';' and take the first entry. The
            # upstream corpus is one-line-per-file in current shape
            # but the README documents semicolon multiplexing so we
            # honour that.
            text = raw.split(";", 1)[0].strip()
            if not text or text in ignored:
                dropped_ignored += 1
                continue
            if not is_valid_text_sig(text):
                dropped_invalid += 1
                continue

            kept.append({"selector": "0x" + sel_hex, "text_sig": text})
            if len(kept) >= args.top_n:
                break

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(kept, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )

    print(
        f"build_selectors_json: kept {len(kept)} entries to {args.out}\n"
        f"  scanned: {scanned} ranked rows\n"
        f"  dropped_no_file: {dropped_no_file}\n"
        f"  dropped_invalid_shape: {dropped_invalid}\n"
        f"  dropped_ignored: {dropped_ignored}\n"
        f"  dropped_duplicate_selector: {dropped_dup}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

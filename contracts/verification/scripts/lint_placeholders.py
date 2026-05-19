#!/usr/bin/env python3
"""
Source-level scanner for `True := trivial`-style placeholder theorems
under `contracts/verification/lean/SphincsCVerify/`.

Tracks `namespace`/`end` blocks so each theorem name is reported with
its full path. Supports multi-line theorem declarations where the
`: True := trivial` body is wrapped across lines.

Strategy:
  1. Walk lines; track the current namespace stack.
  2. When a `theorem <name>` line is found, slurp lines until the next
     top-level declaration keyword or `end`/`namespace`.
  3. In that slurped block, search for the type-and-proof pattern
     `: True := (trivial | by trivial)` (possibly across lines).
  4. Emit qualified names.

Output: one line per offending theorem, fully qualified:
    PLACEHOLDER <full.qualified.name>

Exit code is always 0; the surrounding shell script does the
allowlist diff and decides whether to fail.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


THEOREM_START_RE = re.compile(r"^[ \t]*theorem\s+([A-Za-z0-9_']+)")
AXIOM_START_RE = re.compile(r"^[ \t]*axiom\s+([A-Za-z0-9_']+)")
TOP_LEVEL_KEYWORDS = (
    "theorem", "def", "axiom", "namespace", "end", "section",
    "class", "structure", "instance", "abbrev", "opaque",
    "lemma", "example", "inductive", "variable", "open",
)
TOP_LEVEL_KW_RE = re.compile(
    r"^[ \t]*(?:" + "|".join(TOP_LEVEL_KEYWORDS) + r")\b"
)
BODY_PATTERN_RE = re.compile(
    r":\s*True\s*:=\s*(?:trivial|by\s+trivial|by\s*\n\s*trivial)"
)
# An axiom's "True" conclusion appears as the last token before EOF or a
# top-level next declaration. We look for `, True` or `: True` at end of
# the (collapsed) block — `re.search` with the block joined by spaces.
AXIOM_TRUE_RE = re.compile(r"[:,]\s+True(?:\s|\Z)")
NAMESPACE_RE = re.compile(r"^\s*namespace\s+([A-Za-z0-9_.]+)")
END_RE = re.compile(r"^\s*end\s+([A-Za-z0-9_.]+)")


def strip_comments(lines: list[str]) -> list[str]:
    """Return the lines with `--` line-comments removed (but preserve
    line count + leading whitespace so offset reasoning still works)."""
    out: list[str] = []
    in_block = 0  # depth of `/- ... -/` blocks
    for line in lines:
        i = 0
        buf = []
        while i < len(line):
            if in_block > 0:
                # Look for `-/`
                close_at = line.find("-/", i)
                if close_at == -1:
                    i = len(line)
                else:
                    in_block -= 1
                    i = close_at + 2
            else:
                open_at = line.find("/-", i)
                cmt_at = line.find("--", i)
                # pick whichever is earliest
                if open_at == -1 and cmt_at == -1:
                    buf.append(line[i:])
                    i = len(line)
                elif cmt_at != -1 and (open_at == -1 or cmt_at < open_at):
                    buf.append(line[i:cmt_at])
                    i = len(line)  # rest of line is a comment
                else:
                    buf.append(line[i:open_at])
                    in_block += 1
                    i = open_at + 2
        out.append("".join(buf))
    return out


def find_placeholders_in_file(file_text: str) -> tuple[list[str], list[str]]:
    """Return (theorem_placeholders, axiom_placeholders) found in file_text.

    Theorem placeholders: declarations matching `theorem <name> ... : True := trivial`.
    Axiom placeholders:   declarations matching `axiom <name> ... : ..., True` (or `: True`).
    """
    raw_lines = file_text.splitlines(keepends=False)
    clean_lines = strip_comments(raw_lines)
    ns_stack: list[str] = []
    theorem_placeholders: list[str] = []
    axiom_placeholders: list[str] = []

    i = 0
    n = len(clean_lines)
    while i < n:
        line = clean_lines[i]

        m_ns = NAMESPACE_RE.match(line)
        m_end = END_RE.match(line)
        if m_ns:
            ns_stack.append(m_ns.group(1))
            i += 1
            continue
        if m_end:
            if ns_stack and m_end.group(1) == ns_stack[-1]:
                ns_stack.pop()
            i += 1
            continue

        m_thm = THEOREM_START_RE.match(line)
        m_ax = AXIOM_START_RE.match(line)

        if not m_thm and not m_ax:
            i += 1
            continue

        is_theorem = m_thm is not None
        name = (m_thm or m_ax).group(1)
        # Slurp following lines until the next top-level declaration.
        body_lines = [line]
        j = i + 1
        while j < n:
            next_line = clean_lines[j]
            if TOP_LEVEL_KW_RE.match(next_line):
                break
            body_lines.append(next_line)
            j += 1

        body = "\n".join(body_lines)
        qualified = ".".join(ns_stack + [name]) if ns_stack else name

        if is_theorem:
            if BODY_PATTERN_RE.search(body):
                theorem_placeholders.append(qualified)
        else:
            # Axiom — check if the type's conclusion is `True`.
            # Collapse whitespace for the type-suffix check.
            # The body for an axiom is `axiom <name> [args] : <type>` with
            # no `:= ...`. After collapsing whitespace, the type's
            # conclusion appears at end of block.
            collapsed = re.sub(r"\s+", " ", body).rstrip()
            # Drop trailing `)` or stray punctuation introduced by
            # trailing comment removal.
            if AXIOM_TRUE_RE.search(collapsed + " "):
                axiom_placeholders.append(qualified)

        i = j

    return theorem_placeholders, axiom_placeholders


def main() -> int:
    repo_root = Path(__file__).resolve().parents[3]
    target = repo_root / "contracts" / "verification" / "lean" / "SphincsCVerify"
    if not target.exists():
        print(f"ERROR: {target} not found", file=sys.stderr)
        return 1
    theorems: list[str] = []
    axioms: list[str] = []
    for lean_file in sorted(target.rglob("*.lean")):
        try:
            text = lean_file.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"ERROR: cannot read {lean_file}: {exc}", file=sys.stderr)
            continue
        t, a = find_placeholders_in_file(text)
        theorems.extend(t)
        axioms.extend(a)
    theorems.sort()
    axioms.sort()
    for q in theorems:
        print(f"PLACEHOLDER {q}")
    for q in axioms:
        print(f"BAD_AXIOM {q}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

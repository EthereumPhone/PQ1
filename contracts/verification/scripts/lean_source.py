"""Conservative raw-source mention census, intentionally independent of parsing.

Lean's extensible tokens can contain apparent comment/literal delimiters. Never
strip comments or guess word boundaries: either could erase real declarations.
A mention in prose or a string counts too. Whole-module axiom pins bind all
matching source; Verity applies its unchanged per-file budget without comment
allowances. The Lean build and elaborated inventory remain mandatory checks.
"""
import re


def keyword_count(source: str, words: str) -> int:
    """Count every raw substring match, using linear fixed-pattern scans."""
    return sum(1 for _ in re.finditer(words, source))

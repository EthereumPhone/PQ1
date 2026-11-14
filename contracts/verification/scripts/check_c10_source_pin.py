#!/usr/bin/env python3
"""
check_c10_source_pin.py — byte-pin for the A3.1 in-kernel parse theorem's SOURCE.

The Lean module `lean/SphincsCVerify/Interpreter/C10Source.lean` embeds the
deployed verifier's assembly interior — EXACTLY lines 37-230 of
`contracts/smart-wallet/test/ref/RefSPHINCsC10Asm.sol` (the frozen copy of the deployed
reference; `src/` now holds the optimized v1) — as a raw string
literal `c10Source`. The kernel theorem `parse_c10 : parseYul c10Source = some
c10ProgramFull` (Interpreter/C10Parse.lean, local `make verify-parse-transcription`)
binds that LITERAL to the AST; THIS script binds the literal to the FILE:

    bytes(r#"..."# literal in C10Source.lean)  ==  sed -n '37,230p' SPHINCsC10Asm.sol

byte-for-byte. Together the two checks pin `SPHINCsC10Asm.sol` source text ↔
`c10ProgramFull` with the only trusted parser being the Lean-kernel-checked one.
This script is pure Python so it runs in the `a31-transcription.yml` CI job
(via `make verify-transcription`); the Lake proof itself stays local.

FAILS SAFE on a `.sol` re-layout: the line-range anchors (L36 must open the
`assembly {` block, L231 must close it) are asserted, so a shifted file fails
here rather than silently pinning the wrong bytes. After a LEGITIMATE `.sol`
change, regenerate the embedded literal with `--write` (then re-run the Lake
proof — the kernel theorem must be re-checked against the new bytes, and the
transcription `c10Program` + `c10ProgramFull` updated if the Yul changed).

Exit 0 = literal == file bytes; non-zero = drift (or a broken anchor).
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
VERIF = HERE.parent
SOL = VERIF.parent / "smart-wallet" / "test" / "ref" / "RefSPHINCsC10Asm.sol"
LEAN = VERIF / "lean" / "SphincsCVerify" / "Interpreter" / "C10Source.lean"

# 1-indexed inclusive line range of the assembly-block INTERIOR (not the
# `assembly {` / `}` wrapper lines). Anchored below; re-sync on re-layout.
FIRST_LINE = 37
LAST_LINE = 230

OPEN_MARK = 'def c10Source : String := r#"'
CLOSE_MARK = '"#'


def sol_interior() -> str:
    lines = SOL.read_text().splitlines(keepends=True)
    # Anchors: fail safe if the file was re-laid-out.
    if not lines[FIRST_LINE - 2].rstrip().endswith("assembly {"):
        sys.exit(
            f"FATAL: {SOL.name} L{FIRST_LINE - 1} no longer opens the assembly block "
            f"(got {lines[FIRST_LINE - 2]!r}); re-sync FIRST_LINE/LAST_LINE."
        )
    if lines[LAST_LINE].strip() != "}":
        sys.exit(
            f"FATAL: {SOL.name} L{LAST_LINE + 1} no longer closes the assembly block "
            f"(got {lines[LAST_LINE]!r}); re-sync FIRST_LINE/LAST_LINE."
        )
    interior = "".join(lines[FIRST_LINE - 1 : LAST_LINE])
    # Raw-string-literal safety: the embedding uses r#"..."#.
    if CLOSE_MARK in interior:
        sys.exit('FATAL: assembly interior contains `"#` — the r#"..."# embedding breaks.')
    if not interior.isascii():
        sys.exit("FATAL: assembly interior is not pure ASCII (Char.toNat = byte no longer holds).")
    return interior


def lean_literal(text: str) -> str:
    start = text.find(OPEN_MARK)
    if start < 0:
        sys.exit(f"FATAL: {LEAN.name}: `{OPEN_MARK}` marker not found.")
    start += len(OPEN_MARK)
    end = text.find(CLOSE_MARK, start)
    if end < 0:
        sys.exit(f"FATAL: {LEAN.name}: unterminated r#-string (no `\"#`).")
    return text[start:end]


def main() -> int:
    write = "--write" in sys.argv[1:]
    interior = sol_interior()
    text = LEAN.read_text()

    if write:
        start = text.find(OPEN_MARK)
        if start < 0:
            sys.exit(f"FATAL: {LEAN.name}: `{OPEN_MARK}` marker not found.")
        start += len(OPEN_MARK)
        end = text.find(CLOSE_MARK, start)
        LEAN.write_text(text[:start] + interior + text[end:])
        print(f"WROTE: embedded {len(interior)} bytes ({SOL.name} L{FIRST_LINE}-{LAST_LINE}) into {LEAN.name}")
        print("       now re-run `make verify-parse-transcription` (the kernel theorem must re-check).")
        return 0

    embedded = lean_literal(text)
    print("=== A3.1 c10Source literal <-> SPHINCsC10Asm.sol byte-pin ===")
    print(f"    {SOL.name} L{FIRST_LINE}-{LAST_LINE}: {len(interior)} bytes")
    print(f"    {LEAN.name} r#-literal      : {len(embedded)} bytes")
    if embedded == interior:
        print("    PASS — the embedded `c10Source` literal is BYTE-IDENTICAL to the .sol")
        print("           assembly interior. With the kernel theorem `parse_c10` (local")
        print("           `make verify-parse-transcription`), the source text is bound to")
        print("           `c10ProgramFull` with the parser as the only reviewed TCB element.")
        return 0
    # First divergent byte, for the diagnostic.
    idx = next(
        (i for i, (a, b) in enumerate(zip(embedded, interior)) if a != b),
        min(len(embedded), len(interior)),
    )
    line = interior[:idx].count("\n") + FIRST_LINE
    print(f"    FAIL — first divergence at byte {idx} (~{SOL.name} L{line}).", file=sys.stderr)
    print(f"           literal : {embedded[idx:idx+60]!r}", file=sys.stderr)
    print(f"           .sol    : {interior[idx:idx+60]!r}", file=sys.stderr)
    print("    The embedded c10Source drifted from the .sol. If the .sol change is", file=sys.stderr)
    print("    legitimate, regenerate with `--write` and re-run the Lake proof;", file=sys.stderr)
    print("    otherwise revert the drift.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

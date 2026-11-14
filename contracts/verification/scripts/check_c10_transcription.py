#!/usr/bin/env python3
"""
check_c10_transcription.py — positional transcription-fidelity lint for A3.1.

Cross-checks the hand transcription `c10Program`
(lean/SphincsCVerify/Interpreter/C10Program.lean) against the deployed verifier
SOURCE (smart-wallet/test/ref/RefSPHINCsC10Asm.sol, the frozen copy of the deployed
reference; `src/` now holds the optimized v1) — the single residual the
Lean kernel proof `execC10Asm_eq` CANNOT see (it relates c10Program <-> spec,
never c10Program <-> .sol). This converts the one-time human diff (see
docs/findings/A3_1_ADVERSARIAL_REVIEW_2026-06-18.md) into a re-runnable CI regression gate.

FOUR checks:
  (A) POSITIONAL constant cross-check — using c10Program's `-- L<n>` anchors, every
      numeric constant used in each c10Program fragment must appear in the .sol
      lines that fragment claims to transcribe. Catches a constant placed in the
      WRONG fragment (a cross-fragment swap) or a mistyped constant — localized.
  (B) GLOBAL constant-set equality — every numeric constant in the .sol verify()
      Yul appears somewhere in c10Program and vice versa (modulo the documented
      error-string revert elision). Catches a dropped/added statement's constant.
  (C) STATEMENT-KIND HISTOGRAM — flat per-kind counts (letv/setv/mstore/sha256/
      ifnz/forRange/block/revert/ret) match. Catches a dropped/added statement
      even when its constants are common.
  (D) N-MASK GATE VARIABLES — the two security-critical input gates (Audit I-2) must
      check (pkSeed, pkRoot) in order, internally consistent, matching the .sol. A
      var-swap leaving a key UNGATED changes no constant/kind (so A/B/C miss it) and
      the all-N-masked corpus can't fire the gate — a dedicated check is required.
      (Adversarial-finder RANK-1, 2026-06-18; the full `lake build` also catches this
      via c10Program_decompose's `rfl`, but the lint is the CI-enforced gate.)

HONEST SCOPE: a regression gate + positional cross-check, NOT a proof. An
intra-fragment swap of two constants that are BOTH present in the same .sol
line-range is not caught here — that remains covered by the 396-vector
`verify-interp` corpus (any behaviour-changing swap fails it) and `execC10Asm_eq`.
Residual unchanged: interpreter==EVM, A1/A4/A5.

KNOWN COVERAGE LIMITS / PARSER ASSUMPTIONS (none active on the current tree; an
adversarial pass confirmed no false-PASS hole — the global check is exact, the
positional is a ⊆-per-fragment check, the histogram is exact):
  * Behaviour-CHANGING but constant-set- AND statement-kind-preserving edits inside
    ONE fragment (a same-kind statement reorder, a `var "X"`->`var "Y"` swap with no
    constant change, or a non-commutative operand-order swap using only already-present
    constants) PASS checks (A)-(C) by design — they are caught by the `verify-interp`
    corpus, not here. (A behaviour-PRESERVING edit is not a real divergence at all.)
    EXCEPTION: the one such class that is ALSO corpus-blind — a var-swap on the N-mask
    input gates (corpus keys are all N-masked, so the gate never fires) — is closed by
    check (D). General var-swaps elsewhere remain corpus-/build-caught.
  * Positional localization is only as tight as the anchors: a broad anchor (e.g. the
    hypertree `-- L149-226`) lets a constant misplaced WITHIN that wide range still pass.
  * Assumes `c10Program` is a single INLINED `List Stmt` literal. If it is ever
    refactored to reference named fragment defs (hmsgFragment, …), extend the parser to
    follow them, or the constants in those fragments would go unseen.
  * The four mask names {NMASK,ALLFF,CHAINBASE_MASK,TREEADRS_MASK} are hard-coded; a
    5th mask or a rename needs a regex update (a missing mask def fails LOUD via
    sys.exit, not silently). A standalone Yul `{`-block must be on its own line.

Exit 0 = consistent; non-zero = drift (re-check the transcription).
"""

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
VERIF = HERE.parent
SOL = VERIF.parent / "smart-wallet" / "test" / "ref" / "RefSPHINCsC10Asm.sol"
LEAN = VERIF / "lean" / "SphincsCVerify" / "Interpreter" / "C10Program.lean"

# Lines of the .sol error-string revert body (4 mstores + the revert with its
# 0x00/0x64 length args), explicitly ELIDED in c10Program (documented at
# C10Program.lean header note "Error-string mstores before a revert are elided").
# Excluded from the CONSTANT checks. The L48 `revert(...)` still maps to a
# c10Program `.revert`, so it IS counted in the statement histogram (see below).
CONST_EXCLUDE_SOL_LINES = {44, 45, 46, 47, 48}
# For the histogram, only the 4 error MSTOREs are elided; the L48 revert is kept.
HIST_EXCLUDE_SOL_LINES = {44, 45, 46, 47}

# The assembly block of verify() (inclusive line range in the .sol).
SOL_ASM_FIRST, SOL_ASM_LAST = 37, 230

HEX_RE = re.compile(r"0x[0-9a-fA-F]+")
DEC_RE = re.compile(r"(?<![0-9a-fA-Fx_])\d+\b")
STRIP_LINE_COMMENT = re.compile(r"//.*$")

# Check (D) — the security-critical N-mask input GATES (Audit I-2). A var-swap that
# makes a gate check the WRONG key (e.g. both gates on pkRoot, leaving pkSeed ungated)
# changes NO constant and NO statement kind, so checks (A)/(B)/(C) and the 396-vector
# corpus (whose keys are all N-masked) all miss it; only the full `lake build` catches
# it (c10Program_decompose's `rfl` pins the gate vars). This dedicated check closes that
# gap in the CI-enforced lint. (Adversarial-finder RANK-1, 2026-06-18.)
LEAN_GATE_RE = re.compile(r'eEq \(eAnd \(var "(\w+)"\) \(var "N_MASK"\)\) \(var "(\w+)"\)')
SOL_GATE_RE = re.compile(r"eq\(and\((\w+),\s*N_MASK\),\s*(\w+)\)")
EXPECTED_GATE_KEYS = ["pkSeed", "pkRoot"]  # order matters: .sol L58 then L62


def strip_comment(line: str) -> str:
    return STRIP_LINE_COMMENT.sub("", line)


def consts_in_text(text: str) -> set[int]:
    """All numeric literal VALUES in a chunk of (comment-stripped) source."""
    vals: set[int] = set()
    for m in HEX_RE.findall(text):
        vals.add(int(m, 16))
    # Remove hex spans before scanning decimals so 0x600 doesn't also yield 600.
    text_no_hex = HEX_RE.sub(" ", text)
    for m in DEC_RE.findall(text_no_hex):
        vals.add(int(m))
    return vals


# --------------------------------------------------------------------------- #
# .sol parsing
# --------------------------------------------------------------------------- #
def load_sol():
    lines = SOL.read_text().splitlines()
    # 1-indexed access.
    return {i + 1: l for i, l in enumerate(lines)}


def sol_consts_for_lines(sol_lines, line_nums) -> set[int]:
    vals: set[int] = set()
    for ln in line_nums:
        if ln in CONST_EXCLUDE_SOL_LINES:
            continue
        src = sol_lines.get(ln)
        if src is None:
            continue
        vals |= consts_in_text(strip_comment(src))
    return vals


def sol_global_consts(sol_lines) -> set[int]:
    return sol_consts_for_lines(sol_lines, range(SOL_ASM_FIRST, SOL_ASM_LAST + 1))


def return_vars(sol_lines) -> set[str]:
    """Yul `returns (T name, ...)` pre-declares `name` in the function signature
    (OUTSIDE the assembly block). The first assembly `name :=` is therefore a
    Yul *reassignment*, but c10Program — which has no return-variable notion —
    transcribes it as a `.letv` declaration. So a reassignment to a return var is
    counted as `letv` in the .sol histogram (a benign representation difference,
    like the error-string elision). For SPHINCsC10Asm.verify this is just `valid`."""
    out: set[str] = set()
    for src in sol_lines.values():
        m = re.search(r"\breturns\s*\(([^)]*)\)", src)
        if m:
            for part in m.group(1).split(","):
                toks = part.split()
                if toks:
                    out.add(toks[-1])
    return out


def sol_statement_histogram(sol_lines) -> dict[str, int]:
    h = {k: 0 for k in
         ("letv", "setv", "mstore", "sha256", "ifnz", "forRange", "block", "revert", "ret")}
    rets = return_vars(sol_lines)
    for ln in range(SOL_ASM_FIRST, SOL_ASM_LAST + 1):
        if ln in HIST_EXCLUDE_SOL_LINES:
            continue
        s = strip_comment(sol_lines.get(ln, "")).strip()
        if not s:
            continue
        if re.match(r"^let\s+\w+\s*:=", s):
            h["letv"] += 1
        else:
            m = re.match(r"^(\w+)\s*:=", s)        # reassignment (no `let`)
            if m:
                # A reassignment to a signature-declared return var is the var's
                # in-assembly initialization → mirrors c10Program's `.letv`.
                h["letv" if m.group(1) in rets else "setv"] += 1
        # statement-bearing tokens (a line may carry one)
        h["mstore"] += len(re.findall(r"\bmstore\(", s))
        h["sha256"] += len(re.findall(r"\bstaticcall\(", s))
        if re.match(r"^if\b", s):
            h["ifnz"] += 1
        if re.match(r"^for\b", s):
            h["forRange"] += 1
        h["revert"] += len(re.findall(r"\brevert\(", s))
        h["ret"] += len(re.findall(r"\breturn\(", s))
        # a standalone `{` opening a Yul scope-block (the last FORS tree): a line
        # that is exactly `{` (not `for {`/`if ... {`, handled above).
        if s == "{":
            h["block"] += 1
    return h


# --------------------------------------------------------------------------- #
# c10Program (Lean) parsing
# --------------------------------------------------------------------------- #
MASK_DEF_RE = re.compile(r"private def (NMASK|ALLFF|CHAINBASE_MASK|TREEADRS_MASK)\s*:\s*Nat\s*:=\s*(0x[0-9a-fA-F]+)")
ANCHOR_RE = re.compile(r"--\s*L([\d,\-]+)")
LIT_NUM_RE = re.compile(r"\blit\s+(0x[0-9a-fA-F]+|\d+)")
LIT_MASK_RE = re.compile(r"\blit\s+(NMASK|ALLFF|CHAINBASE_MASK|TREEADRS_MASK)\b")
MASK_TOKEN_RE = re.compile(r"\b(NMASK|ALLFF|CHAINBASE_MASK|TREEADRS_MASK)\b")


def parse_anchor_lines(token: str) -> set[int]:
    """`37,41` -> {37,41}; `43-49` -> {43..49}; `81` -> {81}."""
    out: set[int] = set()
    for part in token.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            out |= set(range(int(a), int(b) + 1))
        elif part:
            out.add(int(part))
    return out


def load_lean():
    text = LEAN.read_text()
    masks = {name: int(val, 16) for name, val in MASK_DEF_RE.findall(text)}
    for req in ("NMASK", "ALLFF", "CHAINBASE_MASK", "TREEADRS_MASK"):
        if req not in masks:
            sys.exit(f"FATAL: mask def {req} not found in {LEAN.name}")
    return text.splitlines(), masks


def lean_const(token: str, masks: dict) -> int:
    if token in masks:
        return masks[token]
    return int(token, 16) if token.startswith("0x") else int(token)


def parse_c10program(lean_lines, masks):
    """Return (buckets, global_consts, histogram).

    buckets: list of (anchor_lineset, anchor_label, set_of_const_values) — one per
    `-- L<n>` anchor inside the `def c10Program` body.
    """
    # Find the c10Program body span.
    start = next((i for i, l in enumerate(lean_lines) if l.startswith("def c10Program")), None)
    if start is None:
        sys.exit("FATAL: `def c10Program` not found")
    # Body ends at the next top-level `def `/`theorem `/`/-!` after start.
    end = len(lean_lines)
    for i in range(start + 1, len(lean_lines)):
        if re.match(r"^(def |theorem |/-!|end )", lean_lines[i]):
            end = i
            break
    body = lean_lines[start:end]

    buckets = []
    cur_lines, cur_label, cur_consts = None, None, set()
    g_consts: set[int] = set()
    hist = {k: 0 for k in
            ("letv", "setv", "mstore", "sha256", "ifnz", "forRange", "block", "revert", "ret")}

    def flush():
        if cur_lines is not None:
            buckets.append((cur_lines, cur_label, set(cur_consts)))

    for raw in body:
        anchor = ANCHOR_RE.search(raw)
        if anchor:
            flush()
            cur_lines = parse_anchor_lines(anchor.group(1))
            cur_label = "L" + anchor.group(1)
            cur_consts = set()
            # An anchor line carries only a comment — no code constants/kinds.
            continue
        # constants on this code line
        line_consts: set[int] = set()
        for tok in LIT_NUM_RE.findall(raw):
            line_consts.add(lean_const(tok, masks))
        for name in LIT_MASK_RE.findall(raw):
            line_consts.add(masks[name])
        # statement kinds
        hist["letv"] += len(re.findall(r"\.letv\b", raw))
        hist["setv"] += len(re.findall(r"\.setv\b", raw))
        hist["mstore"] += len(re.findall(r"\.mstore\b", raw))
        hist["sha256"] += len(re.findall(r"\.sha256\b", raw))
        hist["ifnz"] += len(re.findall(r"\.ifnz\b", raw))
        hist["forRange"] += len(re.findall(r"\.forRange\b", raw))
        hist["block"] += len(re.findall(r"\.block\b", raw))
        hist["revert"] += len(re.findall(r"\.revert\b", raw))
        hist["ret"] += len(re.findall(r"\.ret\b", raw))

        g_consts |= line_consts
        if cur_consts is not None:
            cur_consts |= line_consts
    flush()
    return buckets, g_consts, hist


def gate_keys_sol(sol_lines):
    """Ordered (lhs, rhs) var pairs of each `eq(and(X, N_MASK), Y)` gate in verify()."""
    out = []
    for ln in range(SOL_ASM_FIRST, SOL_ASM_LAST + 1):
        for a, b in SOL_GATE_RE.findall(strip_comment(sol_lines.get(ln, ""))):
            out.append((a, b))
    return out


def gate_keys_lean(lean_text):
    """Ordered (lhs, rhs) var pairs of each c10Program N-mask-shape `.ifnz` guard."""
    return LEAN_GATE_RE.findall(lean_text)


def hx(v: int) -> str:
    return hex(v) if v >= 16 else str(v)


def fmt_set(s) -> str:
    return "{" + ", ".join(hx(v) for v in sorted(s)) + "}"


def main() -> int:
    if not SOL.exists():
        sys.exit(f"FATAL: {SOL} not found")
    if not LEAN.exists():
        sys.exit(f"FATAL: {LEAN} not found")
    sol_lines = load_sol()
    lean_lines, masks = load_lean()
    buckets, lean_global, lean_hist = parse_c10program(lean_lines, masks)
    sol_global = sol_global_consts(sol_lines)
    sol_hist = sol_statement_histogram(sol_lines)

    failures = 0
    print("=== A3.1 c10Program <-> SPHINCsC10Asm.sol transcription lint ===")
    print(f"masks: NMASK={hx(masks['NMASK'])[:10]}… ALLFF=2^256-1? "
          f"{masks['ALLFF'] == 2**256 - 1}  CHAINBASE/TREEADRS resolved")
    print(f"anchors parsed: {len(buckets)}")
    print()

    # (A) Positional cross-check.
    print("(A) POSITIONAL constant cross-check (each c10Program fragment's consts ⊆ its .sol lines)")
    posfail = 0
    for line_set, label, consts in buckets:
        sol_here = sol_consts_for_lines(sol_lines, line_set)
        missing = consts - sol_here
        if missing:
            posfail += 1
            print(f"    FAIL  {label}: c10Program uses {fmt_set(missing)} "
                  f"NOT present in .sol lines {sorted(line_set)}")
            print(f"          (.sol{sorted(line_set)} consts = {fmt_set(sol_here)})")
    if posfail == 0:
        print(f"    PASS — all {len(buckets)} fragments' constants are justified by their anchored .sol lines")
    failures += posfail
    print()

    # (B) Global set equality.
    print("(B) GLOBAL constant-set equality (.sol verify() Yul  <->  c10Program)")
    only_sol = sol_global - lean_global
    only_lean = lean_global - sol_global
    if only_sol:
        print(f"    FAIL — in .sol but NOT in c10Program: {fmt_set(only_sol)} (dropped statement / constant?)")
    if only_lean:
        print(f"    FAIL — in c10Program but NOT in .sol: {fmt_set(only_lean)} (hallucinated / wrong constant?)")
    if not only_sol and not only_lean:
        print(f"    PASS — {len(sol_global)} distinct constants match exactly (error-string revert elided)")
    failures += (1 if only_sol else 0) + (1 if only_lean else 0)
    print()

    # (C) Statement-kind histogram.
    print("(C) STATEMENT-KIND HISTOGRAM (flat per-kind counts match)")
    histfail = 0
    for k in ("letv", "setv", "mstore", "sha256", "ifnz", "forRange", "block", "revert", "ret"):
        s, l = sol_hist[k], lean_hist[k]
        flag = "" if s == l else "   <-- MISMATCH"
        if s != l:
            histfail += 1
        print(f"    {k:9s} .sol={s:<3d} c10Program={l:<3d}{flag}")
    if histfail == 0:
        print("    PASS — every statement kind has equal count (no dropped/added statement)")
    failures += histfail
    print()

    # (D) Security-critical N-mask gate variables — pins which key each gate checks.
    print("(D) N-MASK GATE VARIABLES (each input gate checks the RIGHT key, in order — Audit I-2)")
    sol_gates = gate_keys_sol(sol_lines)
    lean_gates = gate_keys_lean("\n".join(lean_lines))
    dfail = 0
    for side, gates in (("c10Program", lean_gates), (".sol", sol_gates)):
        for a, b in gates:
            if a != b:  # eq(and(X,N_MASK), Y) MUST have X == Y (the compared value is the gated one)
                print(f"    FAIL — {side} N-mask gate is `and({a}, N_MASK) == {b}` (mismatched var: {a}≠{b})")
                dfail += 1
    lean_keys = [a for a, _ in lean_gates]
    sol_keys = [a for a, _ in sol_gates]
    if lean_keys != sol_keys:
        print(f"    FAIL — gate-key ORDER differs: c10Program={lean_keys} vs .sol={sol_keys}")
        dfail += 1
    if lean_keys != EXPECTED_GATE_KEYS:
        print(f"    FAIL — c10Program gates are {lean_keys}, expected {EXPECTED_GATE_KEYS} "
              f"(a swap that leaves a key UNGATED — corpus/global/histogram all miss this)")
        dfail += 1
    if dfail == 0:
        print(f"    PASS — both N-mask gates check {EXPECTED_GATE_KEYS} in order, internally consistent")
    failures += dfail
    print()

    if failures:
        print(f"RESULT: FAIL — {failures} transcription drift(s). The c10Program hand transcription")
        print("        diverged from SPHINCsC10Asm.sol. Re-check; if intended, update both + the anchors.")
        return 1
    print("RESULT: PASS — c10Program is constant-faithful and statement-complete vs SPHINCsC10Asm.sol")
    print("        (regression gate + positional cross-check; NOT a proof — intra-fragment structural")
    print("        fidelity remains covered by verify-interp's 396-vector corpus + execC10Asm_eq).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

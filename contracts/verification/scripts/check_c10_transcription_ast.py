#!/usr/bin/env python3
"""
check_c10_transcription_ast.py — STRUCTURAL transcription-fidelity check for A3.1.

The companion `check_c10_transcription.py` is a STATISTICAL lint: it cross-checks
constant SETS, statement-kind HISTOGRAMS, and the N-mask gate variables between the
deployed verifier source `SPHINCsC10Asm.sol` and its Lean transcription `c10Program`.
That lint documents its own hole (see its "KNOWN COVERAGE LIMITS"): a behaviour-
changing edit INSIDE one fragment that preserves the constant-set AND the kind-
histogram — a same-kind statement REORDER, a non-gate `var "X" -> var "Y"` swap, or a
non-commutative operand-order swap (`eSub a b -> eSub b a`) using only already-present
constants — PASSES the statistical lint. It was previously caught only by the 396-vector
`verify-interp` corpus + the kernel `execC10Asm_eq`, never by a source-level gate.

THIS script closes exactly that hole. It PARSES both sides into a common AST and asserts
STRUCTURAL TREE EQUALITY:

  * a recursive-descent parser over the `SPHINCsC10Asm.sol` `assembly { ... }` block
    (the codehash-pinned deployed verifier SOURCE), and
  * a parser over the committed `C10Program.lean` `def c10Program` LITERAL (the exact
    artifact the kernel proof `execC10Asm_eq` consumes — parsed in place, not a copy),

both targeting the `Interpreter.Yul` AST vocabulary, then `assert yul_ast == lean_ast`.
A structural REORDER / var-swap / operand-swap now flips the tree and FAILS here.

WHAT THIS MOVES (honest scope). It upgrades the *source <-> AST* transcription leg of
the A3.1 residual R1 from STATISTICAL to STRUCTURAL: the human-review surface shrinks
from "eyeball the whole 200-line transcription" to "review this small, general parser +
the TWO enumerable normalization rules below." It does NOT close R1: the solc
*source -> deployed bytecode* leg is untouched (that needs verified compilation), and
the parser + its two normalization rules are now themselves the trusted base. It is a
regression gate + a structural cross-check, still not a machine-checked proof of
`bytecode = c10Program` (a Lean `parseYul = c10Program` by `decide` would be that; it
is the multi-week item, out of scope here). See docs/A3_1_CLOSURE_PATH.md §8.

TWO — and only two — benign normalization rules (both already honoured by the
statistical lint, kept byte-identical here so the two checkers agree on "elided"):
  (N1) ERROR-STRING mstore elision. The 4 `mstore`s that build the "Invalid sig length"
       revert string (`.sol` lines 44-47) have no Bool-verdict meaning and are elided in
       `c10Program`; we drop `mstore`s on exactly those lines (the same set as the
       statistical lint's HIST_EXCLUDE_SOL_LINES). The L48 `revert` is KEPT (-> .revert).
  (N2) RETURN-VAR init. Yul `returns (bool valid)` pre-declares `valid`, so `valid := E`
       is a Yul reassignment; `c10Program` — having no return-var notion — models the
       FIRST such assignment as a `.letv` declaration. We map the first assignment to a
       signature return var to `letv`, later ones to `setv`.
If a THIRD divergence ever surfaces, it is NOT to be silenced with a new rule — it is a
candidate real transcription bug the statistical lint missed. Investigate it.

Exit 0 = the two ASTs are structurally identical (modulo N1/N2); non-zero = a structural
drift (re-check the transcription) or a parser assertion (an unexpected Yul shape).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
VERIF = HERE.parent
# the frozen copy of the deployed reference (src/ now holds the optimized v1)
SOL = VERIF.parent / "smart-wallet" / "test" / "ref" / "RefSPHINCsC10Asm.sol"
LEAN = VERIF / "lean" / "SphincsCVerify" / "Interpreter" / "C10Program.lean"

# (N1) error-string mstores elided (same set as check_c10_transcription.py's
# HIST_EXCLUDE_SOL_LINES — the 4 mstores; the L48 revert is kept as .revert).
# Keyed on ABSOLUTE .sol line numbers. FAILS SAFE on a line-shift: if the .sol ever
# moves these lines, the wrong mstores elide → a structural MISMATCH (FAIL), never a
# false PASS. Re-sync this set (and the statistical lint's) when the .sol is re-laid-out.
ELIDE_MSTORE_SOL_LINES = {44, 45, 46, 47}

# Yul builtin name -> AST BinOp tag (the interpreter's `BinOp`).
YUL_BINOP = {
    "add": "add", "sub": "sub", "mul": "mul",
    "and": "band", "or": "bor", "xor": "bxor",
    "shl": "shl", "shr": "shr", "eq": "eq", "lt": "lt",
}

# Lean C10Program helper def -> AST BinOp tag (from C10Program.lean L48-57).
LEAN_BINOP = {
    "eAdd": "add", "eSub": "sub", "eMul": "mul",
    "eAnd": "band", "eOr": "bor", "eXor": "bxor",
    "eShl": "shl", "eShr": "shr", "eEq": "eq", "eLt": "lt",
}


class ParseError(Exception):
    pass


# =========================================================================== #
# Shared tokenizer (works for both Yul and the Lean literal — same lexical
# atoms: idents, numbers, strings, and single-char punctuation).
# =========================================================================== #
# Order matters: multi-char / dotted idents before single chars. `sig.offset`
# and `.letv` both contain dots, so an ident may start with `.` or contain one.
_TOKEN_RE = re.compile(r"""
      (?P<ws>\s+)
    | (?P<str>"[^"]*")
    | (?P<hex>0x[0-9a-fA-F]+)
    | (?P<dec>\d+)
    | (?P<ident>\.?[A-Za-z_][A-Za-z0-9_.]*)
    | (?P<punc>[()\[\],{}]|:=)
""", re.VERBOSE)


def tokenize(src: str, track_lines: bool) -> list:
    """Return [(kind, text, line)]. `line` is the 1-indexed source line of the
    token's first char when track_lines, else 0. Comments already stripped."""
    toks = []
    line = 1
    i = 0
    n = len(src)
    while i < n:
        m = _TOKEN_RE.match(src, i)
        if not m:
            raise ParseError(f"lex error at offset {i}: {src[i:i+40]!r}")
        kind = m.lastgroup
        text = m.group()
        if kind == "ws":
            line += text.count("\n")
            i = m.end()
            continue
        toks.append((kind, text, line if track_lines else 0))
        line += text.count("\n")
        i = m.end()
    return toks


class Cursor:
    def __init__(self, toks):
        self.toks = toks
        self.i = 0

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else ("eof", "", 0)

    def next(self):
        t = self.peek()
        self.i += 1
        return t

    def expect_punc(self, p):
        k, t, ln = self.next()
        if not (k == "punc" and t == p):
            raise ParseError(f"expected {p!r}, got {t!r} (line {ln})")

    def at_punc(self, p):
        k, t, _ = self.peek()
        return k == "punc" and t == p


# =========================================================================== #
# Yul (.sol) parser  ->  AST
# =========================================================================== #
def strip_sol_comments(text: str) -> str:
    # line comments only (no /* */ in this file's assembly block)
    return re.sub(r"//.*", "", text)


def sol_return_vars(full_src: str) -> set[str]:
    out: set[str] = set()
    for m in re.finditer(r"\breturns\s*\(([^)]*)\)", full_src):
        for part in m.group(1).split(","):
            toks = part.split()
            if toks:
                out.add(toks[-1])
    return out


class YulParser:
    def __init__(self, toks, return_vars):
        self.c = Cursor(toks)
        self.return_vars = return_vars
        self.assigned_returns: set[str] = set()

    # ---- expressions ----
    def expr(self):
        k, t, ln = self.c.next()
        if k == "hex":
            return ("lit", int(t, 16))
        if k == "dec":
            return ("lit", int(t))
        if k == "str":
            # Only reachable inside an error-string mstore (`.sol` L47), which is
            # elided by (N1). Represent as an opaque atom; it never reaches the diff.
            return ("str", t[1:-1])
        if k == "ident":
            if t == "sig.offset":
                return ("sigOffset",)
            if t == "sig.length":
                return ("sigLength",)
            # function-call form?  ident '(' args ')'
            if self.c.at_punc("("):
                return self.call_expr(t, ln)
            return ("var", t)
        raise ParseError(f"unexpected token {t!r} in expr (line {ln})")

    def call_args(self):
        self.c.expect_punc("(")
        args = []
        if self.c.at_punc(")"):
            self.c.expect_punc(")")
            return args
        while True:
            args.append(self.expr())
            if self.c.at_punc(","):
                self.c.expect_punc(",")
                continue
            break
        self.c.expect_punc(")")
        return args

    def call_expr(self, name, ln):
        args = self.call_args()
        if name == "gas":
            # nullary; only appears as staticcall's gas() arg (asserted-shape, unused)
            if args:
                raise ParseError(f"gas() takes no args (line {ln})")
            return ("gas",)
        if name in YUL_BINOP:
            if len(args) != 2:
                raise ParseError(f"{name} expects 2 args, got {len(args)} (line {ln})")
            return ("bin", YUL_BINOP[name], args[0], args[1])
        if name == "iszero":
            if len(args) != 1:
                raise ParseError(f"iszero expects 1 arg (line {ln})")
            return ("iszero", args[0])
        if name == "mload":
            if len(args) != 1:
                raise ParseError(f"mload expects 1 arg (line {ln})")
            return ("mload", args[0])
        if name == "calldataload":
            if len(args) != 1:
                raise ParseError(f"calldataload expects 1 arg (line {ln})")
            return ("calldataload", args[0])
        raise ParseError(f"unsupported Yul builtin {name!r} in expr (line {ln})")

    # ---- statements ----
    def stmt_list_until(self, closer):
        """Parse statements until (and consuming) the `closer` punctuation."""
        stmts = []
        while True:
            k, t, ln = self.c.peek()
            if k == "punc" and t == closer:
                self.c.next()
                return stmts
            if k == "eof":
                raise ParseError(f"unexpected EOF before {closer!r}")
            s = self.stmt()
            if s is not None:
                stmts.append(s)

    def brace_body(self):
        self.c.expect_punc("{")
        return self.stmt_list_until("}")

    def stmt(self):
        k, t, ln = self.c.peek()
        if k == "punc" and t == "{":
            # standalone scope block
            return ("block", self.brace_body())
        if k != "ident":
            raise ParseError(f"unexpected token {t!r} at statement (line {ln})")

        if t == "let":
            self.c.next()
            _, name, ln2 = self.c.next()
            self.c.expect_punc(":=")
            e = self.expr()
            return ("letv", name, e)

        if t == "if":
            self.c.next()
            cond = self.expr()
            body = self.brace_body()
            return ("ifnz", cond, body)

        if t == "for":
            self.c.next()
            return self.for_stmt(ln)

        if t == "pop":
            self.c.next()
            return self.pop_staticcall(ln)

        if t == "mstore":
            self.c.next()
            args = self.call_args()
            if len(args) != 2:
                raise ParseError(f"mstore expects 2 args (line {ln})")
            if ln in ELIDE_MSTORE_SOL_LINES:  # (N1)
                return None
            return ("mstore", args[0], args[1])

        if t == "revert":
            self.c.next()
            self.call_args()  # args dropped (halt-revert -> Bool false)
            return ("revert",)

        if t == "return":
            self.c.next()
            args = self.call_args()
            if len(args) != 2:
                raise ParseError(f"return expects 2 args (line {ln})")
            # .sol always returns a 32-byte word; c10Program's .ret drops the len.
            if args[1] != ("lit", 0x20):
                raise ParseError(f"return length != 0x20 (line {ln}): {args[1]}")
            return ("ret", args[0])

        # bare `X := E` reassignment
        name = t
        self.c.next()
        if not self.c.at_punc(":="):
            raise ParseError(f"unexpected ident {name!r} at statement (line {ln})")
        self.c.expect_punc(":=")
        e = self.expr()
        if name in self.return_vars and name not in self.assigned_returns:  # (N2)
            self.assigned_returns.add(name)
            return ("letv", name, e)
        return ("setv", name, e)

    def for_stmt(self, ln):
        # for { let V := 0 } lt(V, COUNT) { V := add(V, 1) } { BODY }
        init = self.brace_body()
        if len(init) != 1 or init[0][0] != "letv" or init[0][2] != ("lit", 0):
            raise ParseError(f"for-init not `let V := 0` (line {ln}): {init}")
        loopvar = init[0][1]
        cond = self.expr()
        if not (cond[0] == "bin" and cond[1] == "lt" and cond[2] == ("var", loopvar)):
            raise ParseError(f"for-cond not `lt({loopvar}, COUNT)` (line {ln}): {cond}")
        count = cond[3]
        post = self.brace_body()
        exp_post = ("setv", loopvar, ("bin", "add", ("var", loopvar), ("lit", 1)))
        if len(post) != 1 or post[0] != exp_post:
            raise ParseError(f"for-post not `{loopvar} := add({loopvar},1)` (line {ln}): {post}")
        body = self.brace_body()
        return ("forRange", loopvar, count, body)

    def pop_staticcall(self, ln):
        # pop( staticcall(gas(), 0x02, inOff, inLen, outOff, 32) )
        self.c.expect_punc("(")
        _, name, ln2 = self.c.next()
        if name != "staticcall":
            raise ParseError(f"pop() wraps {name!r}, expected staticcall (line {ln})")
        args = self.call_args()
        if len(args) != 6:
            raise ParseError(f"staticcall expects 6 args, got {len(args)} (line {ln})")
        # ASSERT the fixed precompile shape (advisor #3): 0x02 target + 32 out-len.
        if args[1] != ("lit", 0x02):
            raise ParseError(f"staticcall target != 0x02 (line {ln}): {args[1]}")
        if args[5] != ("lit", 32):
            raise ParseError(f"staticcall out-len != 32 (line {ln}): {args[5]}")
        self.c.expect_punc(")")  # close pop(
        inOff, inLen, outOff = args[2], args[3], args[4]
        return ("sha256", inOff, inLen, outOff)


# Parse against the FULL file (block masked to blanks) so token line numbers stay
# ABSOLUTE — the (N1) error-string elision keys on absolute `.sol` line numbers.
def parse_yul_abs() -> list:
    full = SOL.read_text()
    m = re.search(r"\bassembly\b\s*\{", full)
    open_idx = full.index("{", m.start())
    # matching close
    depth = 0
    close_idx = None
    for j in range(open_idx, len(full)):
        if full[j] == "{":
            depth += 1
        elif full[j] == "}":
            depth -= 1
            if depth == 0:
                close_idx = j
                break
    # Blank out everything outside the block (keep newlines for line counting).
    def blank_keep_nl(s):
        return "".join(ch if ch == "\n" else " " for ch in s)
    masked = (blank_keep_nl(full[:open_idx + 1])
              + strip_sol_comments(full[open_idx + 1:close_idx])
              + blank_keep_nl(full[close_idx:]))
    toks = tokenize(masked, track_lines=True)
    p = YulParser(toks, sol_return_vars(full))
    return p.stmt_list_until_eof()


def _stmt_list_until_eof(self):
    stmts = []
    while True:
        k, t, ln = self.c.peek()
        if k == "eof":
            return stmts
        s = self.stmt()
        if s is not None:
            stmts.append(s)


YulParser.stmt_list_until_eof = _stmt_list_until_eof


# =========================================================================== #
# Lean c10Program literal  ->  AST
# =========================================================================== #
def load_lean_masks(text: str) -> dict:
    masks = {}
    for m in re.finditer(r"private def (NMASK|ALLFF|CHAINBASE_MASK|TREEADRS_MASK)\s*:\s*Nat\s*:=\s*(0x[0-9a-fA-F]+)", text):
        masks[m.group(1)] = int(m.group(2), 16)
    for req in ("NMASK", "ALLFF", "CHAINBASE_MASK", "TREEADRS_MASK"):
        if req not in masks:
            raise ParseError(f"mask def {req} not found in C10Program.lean")
    return masks


def strip_lean_comments(text: str) -> str:
    # `-- ...` line comments (the `-- L<n>` anchors + section notes)
    return re.sub(r"--.*", "", text)


def extract_c10program_body(text: str) -> str:
    """The `def c10Program : List Stmt := [ ... ]` bracket body."""
    m = re.search(r"def c10Program\b[^\[]*", text)
    if not m:
        raise ParseError("`def c10Program` not found")
    start = text.index("[", m.end() - 1) if "[" in text[m.start():m.end()] else text.index("[", m.end())
    depth = 0
    for j in range(start, len(text)):
        if text[j] == "[":
            depth += 1
        elif text[j] == "]":
            depth -= 1
            if depth == 0:
                return text[start:j + 1]
    raise ParseError("unbalanced [] in c10Program body")


class LeanParser:
    """Recursive-descent over the c10Program literal. Expr helpers are the
    private defs in C10Program.lean (lit/var/cl/ml/isz/eAdd../eShl..); mask names
    resolve to their numeric def value ONLY as `lit MASK` args (bare `var "N_MASK"`
    stays a variable — matching the Yul let-var)."""

    def __init__(self, toks, masks):
        self.c = Cursor(toks)
        self.masks = masks

    # ---- expressions ----
    # An expr is either an atom (`.sigOffset`, `.sigLength`) or `head arg...`,
    # optionally wrapped in parens. Application is by juxtaposition.
    def expr(self):
        if self.c.at_punc("("):
            self.c.expect_punc("(")
            e = self.expr()
            self.c.expect_punc(")")
            return e
        k, t, ln = self.c.next()
        if k != "ident":
            raise ParseError(f"expected expr head, got {t!r} (line {ln})")
        if t == ".sigOffset":
            return ("sigOffset",)
        if t == ".sigLength":
            return ("sigLength",)
        if t == "lit":
            return ("lit", self.lit_arg())
        if t == "var":
            return ("var", self.string_arg())
        if t == "cl":
            return ("calldataload", self.arg())
        if t == "ml":
            return ("mload", self.arg())
        if t == "isz":
            return ("iszero", self.arg())
        if t in LEAN_BINOP:
            a = self.arg()
            b = self.arg()
            return ("bin", LEAN_BINOP[t], a, b)
        raise ParseError(f"unknown expr head {t!r} (line {ln})")

    def arg(self):
        """A single argument expression: an atom, or a parenthesized expr."""
        if self.c.at_punc("("):
            return self.expr()
        k, t, ln = self.c.peek()
        if k == "ident" and t in (".sigOffset", ".sigLength"):
            self.c.next()
            return ("sigOffset",) if t == ".sigOffset" else ("sigLength",)
        # bare atom head with no parens must still be a nullary/known head; but in
        # c10Program every non-atom arg is parenthesized, so a bare ident here is
        # only `lit`/`var` used WITHOUT parens? No — always wrapped. Guard:
        raise ParseError(f"expected parenthesized arg or atom, got {t!r} (line {ln})")

    def lit_arg(self):
        k, t, ln = self.c.next()
        if k == "hex":
            return int(t, 16)
        if k == "dec":
            return int(t)
        if k == "ident" and t in self.masks:
            return self.masks[t]
        raise ParseError(f"bad lit arg {t!r} (line {ln})")

    def string_arg(self):
        k, t, ln = self.c.next()
        if k != "str":
            raise ParseError(f"expected string arg, got {t!r} (line {ln})")
        return t[1:-1]

    # ---- statements ----
    def stmt_list(self):
        """`[ stmt , stmt , ... ]` (possibly empty)."""
        self.c.expect_punc("[")
        stmts = []
        if self.c.at_punc("]"):
            self.c.expect_punc("]")
            return stmts
        while True:
            stmts.append(self.stmt())
            if self.c.at_punc(","):
                self.c.expect_punc(",")
                continue
            break
        self.c.expect_punc("]")
        return stmts

    def stmt(self):
        k, t, ln = self.c.next()
        if k != "ident":
            raise ParseError(f"expected .stmt head, got {t!r} (line {ln})")
        if t == ".letv":
            return ("letv", self.string_arg(), self.arg())
        if t == ".setv":
            return ("setv", self.string_arg(), self.arg())
        if t == ".mstore":
            return ("mstore", self.arg(), self.arg())
        if t == ".sha256":
            return ("sha256", self.arg(), self.arg(), self.arg())
        if t == ".ifnz":
            cond = self.arg()
            body = self.stmt_list()
            return ("ifnz", cond, body)
        if t == ".forRange":
            name = self.string_arg()
            count = self.arg()
            body = self.stmt_list()
            return ("forRange", name, count, body)
        if t == ".block":
            return ("block", self.stmt_list())
        if t == ".revert":
            return ("revert",)
        if t == ".ret":
            return ("ret", self.arg())
        raise ParseError(f"unknown .stmt head {t!r} (line {ln})")


def parse_lean() -> list:
    text = LEAN.read_text()
    masks = load_lean_masks(text)
    body = strip_lean_comments(extract_c10program_body(text))
    toks = tokenize(body, track_lines=False)
    p = LeanParser(toks, masks)
    stmts = p.stmt_list()
    k, t, _ = p.c.peek()
    if k != "eof":
        raise ParseError(f"trailing tokens after c10Program body: {t!r}")
    return stmts


# =========================================================================== #
# Structural comparison + first-divergence diagnostics
# =========================================================================== #
def find_divergence(a, b, path="root"):
    """Return (path, a_sub, b_sub) of the first structural difference, or None."""
    if isinstance(a, tuple) and isinstance(b, tuple):
        if a and b and isinstance(a[0], str) and isinstance(b[0], str) and a[0] != b[0]:
            return (path, a, b)
        if len(a) != len(b):
            return (path, a, b)
        for idx, (x, y) in enumerate(zip(a, b)):
            d = find_divergence(x, y, f"{path}.{a[0] if a and isinstance(a[0], str) else idx}[{idx}]")
            if d:
                return d
        return None
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return (path, f"<list len {len(a)}>", f"<list len {len(b)}>")
        for idx, (x, y) in enumerate(zip(a, b)):
            d = find_divergence(x, y, f"{path}[{idx}]")
            if d:
                return d
        return None
    if a != b:
        return (path, a, b)
    return None


def count_nodes(x):
    if isinstance(x, tuple):
        return 1 + sum(count_nodes(e) for e in x[1:])
    if isinstance(x, list):
        return sum(count_nodes(e) for e in x)
    return 0


def main() -> int:
    if not SOL.exists():
        sys.exit(f"FATAL: {SOL} not found")
    if not LEAN.exists():
        sys.exit(f"FATAL: {LEAN} not found")
    print("=== A3.1 c10Program <-> SPHINCsC10Asm.sol STRUCTURAL transcription check ===")
    try:
        yul = parse_yul_abs()
        lean = parse_lean()
    except ParseError as e:
        print(f"    PARSE ERROR: {e}", file=sys.stderr)
        print("    (an unexpected Yul/Lean shape — a parser assumption broke; investigate)")
        return 2

    print(f"    parsed .sol assembly  : {len(yul):3d} top-level stmts, {count_nodes(('_',*yul))} AST nodes")
    print(f"    parsed c10Program     : {len(lean):3d} top-level stmts, {count_nodes(('_',*lean))} AST nodes")

    # The verdict rests on trusted Python structural `==` (tuples/lists compare
    # recursively, element by element). `find_divergence` below is used ONLY to
    # LOCALIZE the diagnostic — a bug in that hand-written walker therefore cannot
    # produce a false PASS (the `==` is the load-bearing equality).
    if yul == lean:
        print("    PASS — the two ASTs are STRUCTURALLY IDENTICAL (modulo N1 error-string")
        print("           elision + N2 return-var init). A statement reorder / var-swap /")
        print("           operand-order swap inside any fragment would flip the tree and fail here.")
        print("    Scope: upgrades the source<->AST leg from statistical to structural; does")
        print("           NOT close R1 (solc source->bytecode untouched; parser+N1/N2 are TCB).")
        return 0

    div = find_divergence(yul, lean)
    if div is None:  # `==` said differ but the walker couldn't localize — still a FAIL.
        print("    FAIL — ASTs are unequal (Python `==`) but the diagnostic walker could not"
              " localize the point; inspect manually.", file=sys.stderr)
        return 1
    path, a, b = div
    print(f"    FAIL — structural divergence at {path}", file=sys.stderr)
    print(f"           .sol AST      : {a}", file=sys.stderr)
    print(f"           c10Program AST: {b}", file=sys.stderr)
    print("    The c10Program transcription diverged STRUCTURALLY from SPHINCsC10Asm.sol.", file=sys.stderr)
    print("    Re-check; if intended, update both. (If this is a benign 3rd representation", file=sys.stderr)
    print("    difference, do NOT add a normalization rule reflexively — confirm it changes", file=sys.stderr)
    print("    no behaviour first; a real drift must fail.)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

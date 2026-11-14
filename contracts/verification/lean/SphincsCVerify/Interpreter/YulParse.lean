/-
SphincsCVerify.Interpreter.YulParse — an in-kernel parser for the Yul subset
the deployed `SPHINCsC10Asm.sol` verifier uses, targeting the EXISTING
`Interpreter.Yul` AST (`Expr` / `Stmt`).

This is the A3.1 **R1a** upgrade (see `docs/A3_1_CLOSURE_PATH.md` §8): the
source↔AST transcription-fidelity leg moves from a trusted host-side Python
structural checker (`scripts/check_c10_transcription_ast.py`) into a
Lean-kernel-checked theorem

    `parse_c10 : parseYul c10Source = some c10ProgramFull`   (Interpreter/C10Parse.lean)

so the reviewed TCB element becomes THIS parser (a total, computable,
fuel-based function) instead of the Python script + its runtime. The Python
checker stays as the CI mirror (CI has no Lean toolchain).

## Mapping rules (the Python checker `check_c10_transcription_ast.py` mirrors the pre-extension rules only)

  * `pop(staticcall(gas(), 0x02, inOff, inLen, outOff, 32))` → `.sha256 inOff inLen outOff`
    — FAILS (`none`) unless the target is the literal `0x02` and the out-len the
    literal `32` (asserted at token level: the pinned source has literals there), or, the
    batch-6 extension, the literal `16` (→ `.sha256h`, the first 16 digest bytes).
  * `return(off, 0x20)` → `.ret off` — FAILS if the length expr ≠ `.lit 0x20`.
  * `revert(a, b)` → `.revert` (both argument exprs parsed, then dropped —
    a halt-revert's arguments cannot affect the Bool verdict).
  * canonical `for { let v := 0 } lt(v, COUNT) { v := add(v, 1) } { BODY }`
    → `.forRange v COUNT BODY` — FAILS on ANY non-canonical shape (init not
    `let v := 0`, cond not `lt(v, …)`, post not `v := add(v, 1)`). Batch-6 extension: an
    init `let v := E` with a NON-literal `E`, a literal count `< 2^256` and a body that does
    not assign `v` → `.forFrom v E COUNT BODY`; a literal init other than `0` still FAILS.
  * Batch-6 extension: `byte(i, x)` → `.bin .byte`; `mstore8(a, b)` → `.mstore8`;
    `calldatacopy(a, b, c)` → `.calldatacopy` (the two statement forms only when the name is
    followed by `(`, so an assignment to a variable of that name parses as before).
  * `if COND { BODY }` → `.ifnz COND BODY`; standalone `{ … }` → `.block`;
    `let x := E` → `.letv x E`; `x := E` → `.setv x E` (NO return-var
    normalization — the faithful parse of `valid := …` is `.setv`).
  * `sig.offset` / `sig.length` atoms; Yul builtin args map 1:1 onto `.bin`
    (the AST already uses Yul's `shl`/`shr` operand order).
  * A string literal (only `"Invalid sig length"` in the pinned source)
    tokenizes to its LEFT-ALIGNED 32-byte EVM word value (Yul `mstore(p, "…")`
    semantics: string bytes at the high end, zero-padded low).

## Kernel-reduction discipline (the 2026-07-04 timing spike's measured rules)

  * Input enters as ONE `String.toList`; everything after is `List Char` /
    `List Tok`.
  * ALL recursion is fuel-based and STRUCTURAL (equation-compiler
    `| 0 => … | n+1 => step …`) — never `termination_by` / well-founded
    (`WellFounded.fix` does not kernel-reduce; a `rfl` proof would hang).
  * The tokenizer dispatches on `c.toNat` + `Nat` comparisons and uses the
    tail-recursive accumulator form + `List.reverse` (lowers stack depth).
  * One generous fuel literal (`parseFuel = 16384`) — lazy, costs nothing.
  * Proofs downstream use `rfl` (NOT `decide`; note `deriving DecidableEq`
    FAILS on `Stmt` in this toolchain due to the nested `List Stmt`).
  * Checking a `parseYul` call over the full 9,256-char source needs
    `--tstack=32768` (wired via the lakefile's `moreLeanArgs`); the `#guard`
    smoke tests below are all tstack-safe small fragments.

Mathlib-free (Lean core only); no `sorry`/`admit`/`axiom`/`native_decide`;
everything is a total computable `def` (no `partial`).
-/

import SphincsCVerify.Interpreter.Yul

namespace SphincsCVerify.Interpreter.YulParse

/-! ## Tokens -/

/-- Tokens of the Yul subset. String literals are folded to their left-aligned
    32-byte EVM word value at lex time, so a `num` token covers them too. -/
inductive Tok
  | ident (s : String)
  | num (n : Nat)
  | lparen | rparen | lbrace | rbrace | comma | assign
deriving Repr, DecidableEq

/-! ## Character classes (Nat codepoint comparisons — ASCII source) -/

/-- Whitespace: space, `\n`, `\r`, `\t`. -/
def isWs (n : Nat) : Bool := n = 32 || n = 10 || n = 13 || n = 9

/-- ASCII digit. -/
def isDigit (n : Nat) : Bool := 48 ≤ n && n ≤ 57

/-- Identifier head: letter or `_`. -/
def isIdentStart (n : Nat) : Bool :=
  (65 ≤ n && n ≤ 90) || (97 ≤ n && n ≤ 122) || n = 95

/-- Identifier continuation: head chars, digits, or `.` (Yul's `sig.offset` /
    `sig.length` are single dotted identifiers). -/
def isIdentChar (n : Nat) : Bool := isIdentStart n || isDigit n || n = 46

/-- Hex digit value (`0-9a-fA-F`), or `none`. -/
def hexVal (n : Nat) : Option Nat :=
  if 48 ≤ n && n ≤ 57 then some (n - 48)
  else if 97 ≤ n && n ≤ 102 then some (n - 87)
  else if 65 ≤ n && n ≤ 70 then some (n - 55)
  else none

/-! ## Sub-lexers (structural recursion on the char list; tail-recursive) -/

/-- Drop the remainder of a `//` line comment (through the newline). -/
def dropLine : List Char → List Char
  | [] => []
  | c :: rest => if c.toNat = 10 then rest else dropLine rest

/-- Accumulate identifier chars; returns `(ident chars, rest)`. -/
def lexIdent : List Char → List Char → (List Char × List Char)
  | acc, [] => (acc.reverse, [])
  | acc, c :: rest =>
      if isIdentChar c.toNat then lexIdent (c :: acc) rest
      else (acc.reverse, c :: rest)

/-- Accumulate a decimal number onto `v`; returns `(value, rest)`. -/
def lexDec : Nat → List Char → (Nat × List Char)
  | v, [] => (v, [])
  | v, c :: rest =>
      if isDigit c.toNat then lexDec (v * 10 + (c.toNat - 48)) rest
      else (v, c :: rest)

/-- Accumulate a hex number onto `v`; returns `(value, rest)`. -/
def lexHex : Nat → List Char → (Nat × List Char)
  | v, [] => (v, [])
  | v, c :: rest =>
      match hexVal c.toNat with
      | some d => lexHex (v * 16 + d) rest
      | none => (v, c :: rest)

/-- Scan a string-literal body up to the closing `"`; `none` on EOF
    (unterminated). No escape processing — the Yul subset has none. -/
def lexStr : List Char → List Char → Option (List Char × List Char)
  | _, [] => none
  | acc, c :: rest =>
      if c.toNat = 34 then some (acc.reverse, rest) else lexStr (c :: acc) rest

/-- Left-aligned 32-byte EVM word value of a short string literal (Yul
    `mstore(p, "…")` semantics): bytes at the high end, zero-padded low.
    `none` past 32 bytes (Yul itself rejects those). ASCII assumed
    (`c.toNat` = the byte). -/
def strWord (cs : List Char) : Option Nat :=
  if cs.length ≤ 32 then
    some ((cs.foldl (fun a c => a * 256 + c.toNat) 0) <<< (8 * (32 - cs.length)))
  else none

/-! ## Tokenizer -/

/-- Fuel-based tokenizer (tail-recursive accumulator, reversed at the end).
    Fails (`none`) on: fuel exhaustion, an unknown character, `/` not opening
    a `//` comment, a lone `:` (must be `:=`), an unterminated or >32-byte
    string literal, or a `0x` prefix with no hex digit. -/
def tokenize : Nat → List Char → List Tok → Option (List Tok)
  | 0, _, _ => none
  | fuel+1, cs, acc =>
    match cs with
    | [] => some acc.reverse
    | c :: rest =>
      let n := c.toNat
      if isWs n then tokenize fuel rest acc
      else if n = 47 then      -- '/' must open a `//` line comment
        match rest with
        | c2 :: rest2 =>
            if c2.toNat = 47 then tokenize fuel (dropLine rest2) acc else none
        | [] => none
      else if n = 40 then tokenize fuel rest (.lparen :: acc)
      else if n = 41 then tokenize fuel rest (.rparen :: acc)
      else if n = 123 then tokenize fuel rest (.lbrace :: acc)
      else if n = 125 then tokenize fuel rest (.rbrace :: acc)
      else if n = 44 then tokenize fuel rest (.comma :: acc)
      else if n = 58 then      -- ':' must be ':='
        match rest with
        | c2 :: rest2 =>
            if c2.toNat = 61 then tokenize fuel rest2 (.assign :: acc) else none
        | [] => none
      else if n = 34 then      -- '"' string literal → left-aligned word value
        match lexStr [] rest with
        | some (body, rest2) =>
            match strWord body with
            | some w => tokenize fuel rest2 (.num w :: acc)
            | none => none
        | none => none
      else if isDigit n then
        if n = 48 then          -- leading '0': `0x…` hex or plain decimal
          match rest with
          | c2 :: rest2 =>
              if c2.toNat = 120 then      -- 'x'
                match rest2 with
                | c3 :: _ =>
                    match hexVal c3.toNat with
                    | some _ =>
                        let (v, rest3) := lexHex 0 rest2
                        tokenize fuel rest3 (.num v :: acc)
                    | none => none        -- `0x` with no hex digit
                | [] => none
              else
                let (v, rest') := lexDec 0 rest
                tokenize fuel rest' (.num v :: acc)
          | [] => some (Tok.num 0 :: acc).reverse
        else
          let (v, rest') := lexDec (n - 48) rest
          tokenize fuel rest' (.num v :: acc)
      else if isIdentStart n then
        let (csI, rest') := lexIdent [c] rest
        tokenize fuel rest' (.ident (String.mk csI) :: acc)
      else none

/-! ## Token expecters (tiny total matchers; no `DecidableEq` needed) -/

def expLParen : List Tok → Option (List Tok)
  | .lparen :: r => some r | _ => none
def expRParen : List Tok → Option (List Tok)
  | .rparen :: r => some r | _ => none
def expLBrace : List Tok → Option (List Tok)
  | .lbrace :: r => some r | _ => none
def expRBrace : List Tok → Option (List Tok)
  | .rbrace :: r => some r | _ => none
def expComma : List Tok → Option (List Tok)
  | .comma :: r => some r | _ => none
def expAssign : List Tok → Option (List Tok)
  | .assign :: r => some r | _ => none
/-- Expect exactly the numeric literal `k` (the `0x02`-target / `32`-out-len /
    for-loop `0` and `1` pins). -/
def expNum (k : Nat) : List Tok → Option (List Tok)
  | .num n :: r => if n = k then some r else none
  | _ => none
/-- Whether the next token is `(` (batch-6 extension: the new statement forms `mstore8(…)` /
    `calldatacopy(…)` are taken only then, so `mstore8 := e` still parses as the assignment it
    was before the extension). -/
def nextIsLParen : List Tok → Bool
  | .lparen :: _ => true
  | _ => false
/-- Expect exactly the identifier `s` (`staticcall` / `gas` / `lt` / `add`). -/
def expIdent (s : String) : List Tok → Option (List Tok)
  | .ident t :: r => if t == s then some r else none
  | _ => none

/-! ## Expression parser -/

/-- Yul builtin name → `BinOp` (arg order maps 1:1 — the AST already uses
    Yul's `shl`/`shr` operand order, see `Interpreter.Yul.eval`). -/
def binOpOf (s : String) : Option BinOp :=
  if s == "add" then some .add
  else if s == "sub" then some .sub
  else if s == "mul" then some .mul
  else if s == "and" then some .band
  else if s == "or" then some .bor
  else if s == "xor" then some .bxor
  else if s == "shl" then some .shl
  else if s == "shr" then some .shr
  else if s == "eq" then some .eq
  else if s == "lt" then some .lt
  else if s == "byte" then some .byte      -- batch-6 extension
  else none

/-- Fuel-based expression parser. `fuel` bounds nesting depth. An identifier
    followed by `(` must be a known builtin (`gas()` is NOT one here — it is
    consumed token-level inside the `pop(staticcall(…))` statement shape, so a
    stray `gas()` in expression position fails the parse). -/
def parseExpr : Nat → List Tok → Option (Expr × List Tok)
  | 0, _ => none
  | fuel+1, toks =>
    match toks with
    | .num n :: rest => some (.lit n, rest)
    | .ident s :: .lparen :: rest =>
        if s == "iszero" then do
          let (a, r1) ← parseExpr fuel rest
          let r2 ← expRParen r1
          pure (.iszero a, r2)
        else if s == "mload" then do
          let (a, r1) ← parseExpr fuel rest
          let r2 ← expRParen r1
          pure (.mload a, r2)
        else if s == "calldataload" then do
          let (a, r1) ← parseExpr fuel rest
          let r2 ← expRParen r1
          pure (.calldataload a, r2)
        else
          match binOpOf s with
          | some op => do
              let (a, r1) ← parseExpr fuel rest
              let r2 ← expComma r1
              let (b, r3) ← parseExpr fuel r2
              let r4 ← expRParen r3
              pure (.bin op a b, r4)
          | none => none
    | .ident s :: rest =>
        if s == "sig.offset" then some (.sigOffset, rest)
        else if s == "sig.length" then some (.sigLength, rest)
        else some (.var s, rest)
    | _ => none

/-! ## Loop-variable assignment check (batch-6 extension)

`.forFrom` fixes its iteration count at entry; that is faithful to Yul's re-evaluated
`lt(v, count)` only if the body never assigns `v` (and the count is a literal, checked at the
parse site). `assignsIn fuel v body` is that check. -/

/-- Fuel-based (structural on the fuel, so it kernel-reduces inside `rfl` parse proofs; the
    nested `Stmt`/`List Stmt` recursion would be well-founded-compiled). Out of fuel answers
    `true`, i.e. the parse is REJECTED. -/
def assignsIn : Nat → String → List Stmt → Bool
  | 0, _, _ => true
  | _ + 1, _, [] => false
  | f + 1, v, s :: rest =>
      (match s with
       | .letv x _ => x == v
       | .setv x _ => x == v
       | .ifnz _ body => assignsIn f v body
       | .forRange u _ body => u == v || assignsIn f v body
       | .block body => assignsIn f v body
       | .forFrom u _ _ body => u == v || assignsIn f v body
       | _ => false)
      || assignsIn f v rest

/-! ## Statement parser -/

/-- Fuel-based statement-list parser. Parses statements up to (WITHOUT
    consuming) a closing `}` or EOF; callers of nested bodies consume the
    brace. Every statement branch validates its full canonical shape and
    returns `none` on any deviation (see the module header's mapping rules). -/
def parseStmtList : Nat → List Tok → Option (List Stmt × List Tok)
  | 0, _ => none
  | fuel+1, toks =>
    match toks with
    | [] => some ([], [])
    | .rbrace :: _ => some ([], toks)
    | .lbrace :: rest => do           -- standalone `{ … }` scope
        let (body, r1) ← parseStmtList fuel rest
        let r2 ← expRBrace r1
        let (stmts, r3) ← parseStmtList fuel r2
        pure (.block body :: stmts, r3)
    | .ident s :: rest =>
        if s == "let" then             -- `let x := E`
          match rest with
          | .ident x :: r1 => do
              let r2 ← expAssign r1
              let (e, r3) ← parseExpr fuel r2
              let (stmts, r4) ← parseStmtList fuel r3
              pure (.letv x e :: stmts, r4)
          | _ => none
        else if s == "if" then do      -- `if COND { BODY }`
          let (c, r1) ← parseExpr fuel rest
          let r2 ← expLBrace r1
          let (body, r3) ← parseStmtList fuel r2
          let r4 ← expRBrace r3
          let (stmts, r5) ← parseStmtList fuel r4
          pure (.ifnz c body :: stmts, r5)
        else if s == "for" then do
          -- canonical `for { let v := 0 } lt(v, COUNT) { v := add(v, 1) } { BODY }`
          let r1 ← expLBrace rest
          let r2 ← expIdent "let" r1
          -- batch-6 extension: the init expression is parsed; a literal 0 gives the canonical
          -- `.forRange` exactly as before, any other literal is still rejected, and a computed
          -- start with a LITERAL count gives `.forFrom`
          match r2 with
          | .ident v :: r3 => do
              let r4 ← expAssign r3
              let (start, r5) ← parseExpr fuel r4
              let r6 ← expRBrace r5
              let r7 ← expIdent "lt" r6
              let r8 ← expLParen r7
              let r9 ← expIdent v r8
              let r10 ← expComma r9
              let (count, r11) ← parseExpr fuel r10
              let r12 ← expRParen r11
              let r13 ← expLBrace r12
              let r14 ← expIdent v r13
              let r15 ← expAssign r14
              let r16 ← expIdent "add" r15
              let r17 ← expLParen r16
              let r18 ← expIdent v r17
              let r19 ← expComma r18
              let r20 ← expNum 1 r19
              let r21 ← expRParen r20
              let r22 ← expRBrace r21
              let r23 ← expLBrace r22
              let (body, r24) ← parseStmtList fuel r23
              let r25 ← expRBrace r24
              let (stmts, r26) ← parseStmtList fuel r25
              match start, count with
              | .lit 0, _ => pure (.forRange v count body :: stmts, r26)
              | .lit _, _ => none
              | _, .lit k =>
                  -- the count is a literal WORD (Yul rejects larger literals) and the body must
                  -- not assign the loop variable
                  if k < W && !assignsIn fuel v body then pure (.forFrom v start (.lit k) body :: stmts, r26)
                  else none
              | _, _ => none
          | _ => none
        else if s == "pop" then do
          -- `pop(staticcall(gas(), 0x02, inOff, inLen, outOff, 32))` → `.sha256`
          let r1 ← expLParen rest
          let r2 ← expIdent "staticcall" r1
          let r3 ← expLParen r2
          let r4 ← expIdent "gas" r3
          let r5 ← expLParen r4
          let r6 ← expRParen r5
          let r7 ← expComma r6
          let r8 ← expNum 2 r7           -- target MUST be the literal 0x02
          let r9 ← expComma r8
          let (inOff, r10) ← parseExpr fuel r9
          let r11 ← expComma r10
          let (inLen, r12) ← parseExpr fuel r11
          let r13 ← expComma r12
          let (outOff, r14) ← parseExpr fuel r13
          let r15 ← expComma r14
          -- out-len MUST be the literal 32 (`.sha256`) or, batch-6 extension, 16 (`.sha256h`)
          match r15 with
          | .num 32 :: r16 => do
              let r17 ← expRParen r16        -- close staticcall(
              let r18 ← expRParen r17        -- close pop(
              let (stmts, r19) ← parseStmtList fuel r18
              pure (.sha256 inOff inLen outOff :: stmts, r19)
          | .num 16 :: r16 => do
              let r17 ← expRParen r16
              let r18 ← expRParen r17
              let (stmts, r19) ← parseStmtList fuel r18
              pure (.sha256h inOff inLen outOff :: stmts, r19)
          | _ => none
        else if s == "mstore" then do    -- `mstore(a, b)`
          let r1 ← expLParen rest
          let (a, r2) ← parseExpr fuel r1
          let r3 ← expComma r2
          let (b, r4) ← parseExpr fuel r3
          let r5 ← expRParen r4
          let (stmts, r6) ← parseStmtList fuel r5
          pure (.mstore a b :: stmts, r6)
        else if s == "mstore8" && nextIsLParen rest then do   -- batch-6 extension: `mstore8(a, b)`
          let r1 ← expLParen rest
          let (a, r2) ← parseExpr fuel r1
          let r3 ← expComma r2
          let (b, r4) ← parseExpr fuel r3
          let r5 ← expRParen r4
          let (stmts, r6) ← parseStmtList fuel r5
          pure (.mstore8 a b :: stmts, r6)
        else if s == "calldatacopy" && nextIsLParen rest then do  -- batch-6: `calldatacopy(a, b, c)`
          let r1 ← expLParen rest
          let (a, r2) ← parseExpr fuel r1
          let r3 ← expComma r2
          let (b, r4) ← parseExpr fuel r3
          let r5 ← expComma r4
          let (c, r6) ← parseExpr fuel r5
          let r7 ← expRParen r6
          let (stmts, r8) ← parseStmtList fuel r7
          pure (.calldatacopy a b c :: stmts, r8)
        else if s == "revert" then do    -- `revert(a, b)` → `.revert` (args dropped)
          let r1 ← expLParen rest
          let (_, r2) ← parseExpr fuel r1
          let r3 ← expComma r2
          let (_, r4) ← parseExpr fuel r3
          let r5 ← expRParen r4
          let (stmts, r6) ← parseStmtList fuel r5
          pure (.revert :: stmts, r6)
        else if s == "return" then do    -- `return(off, 0x20)` → `.ret off`
          let r1 ← expLParen rest
          let (off, r2) ← parseExpr fuel r1
          let r3 ← expComma r2
          let (lenE, r4) ← parseExpr fuel r3
          match lenE with
          | .lit 32 => do                -- length MUST be the literal 0x20
              let r5 ← expRParen r4
              let (stmts, r6) ← parseStmtList fuel r5
              pure (.ret off :: stmts, r6)
          | _ => none
        else                             -- bare `x := E` reassignment
          match rest with
          | .assign :: r1 => do
              let (e, r2) ← parseExpr fuel r1
              let (stmts, r3) ← parseStmtList fuel r2
              pure (.setv s e :: stmts, r3)
          | _ => none
    | _ => none

/-! ## Top-level entry point -/

/-- One generous fuel literal for both the tokenizer (≥ 1 unit per token /
    whitespace char; the pinned source is 9,256 chars) and the parser (≥ 1 unit
    per statement in the sequential continuation chain plus nesting; the pinned
    source has ~300). Lazy — an oversized literal costs nothing. -/
def parseFuel : Nat := 16384

/-- Parse a Yul-subset source string to a `List Stmt`, or `none` on ANY
    lexical / grammatical / canonical-shape violation. Total and computable;
    the single `String.toList` is the only string traversal. -/
def parseYul (src : String) : Option (List Stmt) := do
  let toks ← tokenize parseFuel src.toList []
  let (stmts, rest) ← parseStmtList parseFuel toks
  match rest with
  | [] => some stmts
  | _ => none                            -- trailing tokens (e.g. a stray `}`)

/-- `parseYul` with an explicit fuel (batch-6 extension). The optimized v1 source
    (`C10HeadSource.lean`, ~32 kB) needs more tokenizer fuel than `parseFuel`;
    `parseYul` itself is unchanged and is this function at `parseFuel`
    (`parseYul_eq_parseYulFuel`, by `rfl`). -/
def parseYulFuel (fuel : Nat) (src : String) : Option (List Stmt) := do
  let toks ← tokenize fuel src.toList []
  let (stmts, rest) ← parseStmtList fuel toks
  match rest with
  | [] => some stmts
  | _ => none

theorem parseYul_eq_parseYulFuel (src : String) : parseYul src = parseYulFuel parseFuel src := rfl

/-! ## Smoke tests (`#guard` = compile-time; all tstack-safe small fragments)

`Stmt` has no `DecidableEq` (nested `List Stmt` defeats `deriving` in this
toolchain), so the guards pattern-match the expected tree instead of `=`. -/

-- let / lit (hex + dec) / var
#guard (match parseYul "let x := 0x600" with
        | some [.letv "x" (.lit 1536)] => true | _ => false)
#guard (match parseYul "let y := x" with
        | some [.letv "y" (.var "x")] => true | _ => false)

-- setv + binop arg order preserved (Yul `shl(4, i)` → `.bin .shl (.lit 4) (.var "i")`)
#guard (match parseYul "v := shl(4, i)" with
        | some [.setv "v" (.bin .shl (.lit 4) (.var "i"))] => true | _ => false)

-- nested builtins + sig.offset / sig.length atoms
#guard (match parseYul "let R := and(calldataload(sig.offset), N_MASK)" with
        | some [.letv "R" (.bin .band (.calldataload .sigOffset) (.var "N_MASK"))] =>
            true | _ => false)
#guard (match parseYul "if iszero(eq(sig.length, 4008)) { revert(0, 0) }" with
        | some [.ifnz (.iszero (.bin .eq .sigLength (.lit 4008))) [.revert]] =>
            true | _ => false)

-- mstore + mload + comment skipping
#guard (match parseYul "mstore(0x20, mload(OUT)) // trailing comment" with
        | some [.mstore (.lit 32) (.mload (.var "OUT"))] => true | _ => false)

-- the sha256 precompile shape (0x02 target + 32 out-len asserted)…
#guard (match parseYul "pop(staticcall(gas(), 0x02, 0x00, 0xA0, OUT, 32))" with
        | some [.sha256 (.lit 0) (.lit 160) (.var "OUT")] => true | _ => false)
-- …and its two REQUIRED failure modes
#guard (parseYul "pop(staticcall(gas(), 0x03, 0x00, 0xA0, OUT, 32))").isNone
#guard (parseYul "pop(staticcall(gas(), 0x02, 0x00, 0xA0, OUT, 64))").isNone

-- return: len must be the literal 0x20
#guard (match parseYul "return(0x00, 0x20)" with
        | some [.ret (.lit 0)] => true | _ => false)
#guard (parseYul "return(0x00, 0x40)").isNone

-- canonical for → forRange; ANY non-canonical shape fails
#guard (match parseYul "for { let i := 0 } lt(i, 12) { i := add(i, 1) } { x := i }" with
        | some [.forRange "i" (.lit 12) [.setv "x" (.var "i")]] => true | _ => false)
#guard (parseYul "for { let i := 1 } lt(i, 12) { i := add(i, 1) } { x := i }").isNone
#guard (parseYul "for { let i := 0 } lt(j, 12) { i := add(i, 1) } { x := i }").isNone
#guard (parseYul "for { let i := 0 } lt(i, 12) { i := add(i, 2) } { x := i }").isNone
#guard (parseYul "for { let i := 0 } lt(i, 12) { i := sub(i, 1) } { x := i }").isNone

-- standalone block scope
#guard (match parseYul "{ let t := 7 }" with
        | some [.block [.letv "t" (.lit 7)]] => true | _ => false)

-- string literal → LEFT-ALIGNED 32-byte word ("ab" = 0x6162 then 30 zero bytes)
#guard (match parseYul "mstore(0x44, \"ab\")" with
        | some [.mstore (.lit 68) (.lit v)] =>
            v == 0x6162000000000000000000000000000000000000000000000000000000000000
        | _ => false)

-- unbalanced / trailing tokens fail
#guard (parseYul "let x := ").isNone
#guard (parseYul "let x := 1 }").isNone

-- batch-6 extension smoke tests
#guard (match parseYul "let b := byte(3, slots)" with
        | some [.letv "b" (.bin .byte (.lit 3) (.var "slots"))] => true | _ => false)
#guard (match parseYul "mstore8(0x37, 12)" with
        | some [.mstore8 (.lit 55) (.lit 12)] => true | _ => false)
#guard (match parseYul "calldatacopy(byte(0, slots), add(authPtr, 0), 16)" with
        | some [.calldatacopy (.bin .byte (.lit 0) (.var "slots"))
                  (.bin .add (.var "authPtr") (.lit 0)) (.lit 16)] => true | _ => false)
#guard (match parseYul "pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))" with
        | some [.sha256h (.lit 0) (.lit 96) (.lit 64)] => true | _ => false)
#guard (parseYul "pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 8))").isNone
#guard (match parseYul "for { let p := and(shr(3, d), 7) } lt(p, 7) { p := add(p, 1) } { mstore8(0x3B, p) }" with
        | some [.forFrom "p" (.bin .band (.bin .shr (.lit 3) (.var "d")) (.lit 7)) (.lit 7)
                  [.mstore8 (.lit 59) (.var "p")]] => true | _ => false)
-- a computed start needs a literal count; a literal non-zero start is still rejected (above)
#guard (parseYul "for { let p := and(d, 7) } lt(p, n) { p := add(p, 1) } { x := p }").isNone
-- and a body that assigns the loop variable is rejected
#guard (parseYul "for { let p := and(d, 7) } lt(p, 7) { p := add(p, 1) } { p := 9 }").isNone
-- and a count that is not a word is rejected (2^256 and above)
#guard (parseYul "for { let p := and(d, 7) } lt(p, 0x10000000000000000000000000000000000000000000000000000000000000000) { p := add(p, 1) } { mstore8(0x3B, p) }").isNone
#guard (match parseYul "for { let p := and(d, 7) } lt(p, 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff) { p := add(p, 1) } { mstore8(0x3B, p) }" with
        | some [.forFrom "p" _ (.lit _) _] => true | _ => false)
-- REGRESSION (Astra batch 6, P2-1): `mstore8` / `calldatacopy` not followed by `(` parse exactly
-- as before the extension, as plain assignments to variables of those names
#guard (match parseYul "mstore8 := 1" with
        | some [.setv "mstore8" (.lit 1)] => true | _ => false)
#guard (match parseYul "calldatacopy := 1" with
        | some [.setv "calldatacopy" (.lit 1)] => true | _ => false)
#guard (match parseYul "let x := byte" with
        | some [.letv "x" (.var "byte")] => true | _ => false)

end SphincsCVerify.Interpreter.YulParse

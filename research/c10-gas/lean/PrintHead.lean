/-
research/c10-gas/lean/PrintHead.lean — prints `parseYulFuel headFuel c10HeadSource` as a Lean
`List Stmt` literal (dot notation), for research/c10-gas/gen_lean_head.py. RESEARCH (#1155
gas track, batch 6). Run from contracts/verification/lean with `lake env lean`.
-/
import SphincsCVerify.Interpreter.C10HeadSource

open SphincsCVerify.Interpreter
open SphincsCVerify.Interpreter.YulParse
open SphincsCVerify.Interpreter.C10

def numL (n : Nat) : String :=
  if n < 65536 then toString n else "0x" ++ String.mk (Nat.toDigits 16 n)

def opL : BinOp → String
  | .add => "add" | .sub => "sub" | .mul => "mul" | .band => "band" | .bor => "bor"
  | .bxor => "bxor" | .shl => "shl" | .shr => "shr" | .eq => "eq" | .lt => "lt" | .byte => "byte"

def exprL : Expr → String
  | .lit n => s!"(.lit {numL n})"
  | .var s => s!"(.var \"{s}\")"
  | .sigOffset => ".sigOffset"
  | .sigLength => ".sigLength"
  | .bin op a b => s!"(.bin .{opL op} {exprL a} {exprL b})"
  | .iszero a => s!"(.iszero {exprL a})"
  | .mload a => s!"(.mload {exprL a})"
  | .calldataload a => s!"(.calldataload {exprL a})"

mutual
partial def stmtL (ind : String) : Stmt → String
  | .letv x e => ".letv \"" ++ x ++ "\" " ++ exprL e
  | .setv x e => ".setv \"" ++ x ++ "\" " ++ exprL e
  | .mstore a b => ".mstore " ++ exprL a ++ " " ++ exprL b
  | .sha256 a b c => ".sha256 " ++ exprL a ++ " " ++ exprL b ++ " " ++ exprL c
  | .ifnz c body => ".ifnz " ++ exprL c ++ " " ++ listL (ind ++ "  ") body
  | .forRange v c body => ".forRange \"" ++ v ++ "\" " ++ exprL c ++ " " ++ listL (ind ++ "  ") body
  | .block body => ".block " ++ listL (ind ++ "  ") body
  | .revert => ".revert"
  | .ret o => ".ret " ++ exprL o
  | .mstore8 a b => ".mstore8 " ++ exprL a ++ " " ++ exprL b
  | .calldatacopy a b c => ".calldatacopy " ++ exprL a ++ " " ++ exprL b ++ " " ++ exprL c
  | .sha256h a b c => ".sha256h " ++ exprL a ++ " " ++ exprL b ++ " " ++ exprL c
  | .forFrom v st c body =>
      ".forFrom \"" ++ v ++ "\" " ++ exprL st ++ " " ++ exprL c ++ " " ++ listL (ind ++ "  ") body
partial def listL (ind : String) : List Stmt → String
  | [] => "[]"
  | ss => "\n" ++ ind ++ "[ " ++ items ind ss ++ " ]"
partial def items (ind : String) : List Stmt → String
  | [] => ""
  | [s] => stmtL ind s
  | s :: rest => stmtL ind s ++ "\n" ++ ind ++ ", " ++ items ind rest
end

#eval do
  match parseYulFuel 65536 c10HeadSource with
  | none => IO.println "PARSE-FAILED"
  | some prog =>
      IO.println s!"STMTS {prog.length}"
      IO.println "BEGIN-AST"
      IO.println ("  [ " ++ items "  " prog ++ " ]")
      IO.println "END-AST"

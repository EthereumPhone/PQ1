/-
research/c10-gas/lean/EntryProbe.lean — batch 9 executed probe (NOT a proof, not part of the
SphincsCVerify build). Runs BOTH real programs (`c10Program`, `c10HeadProgram`) to the entry of
layer 0 and of layer 1, under one common oracle that is input-sensitive in digest bytes 0..13
(the bytes node values keep) and has digit sum 205 in its low bytes (so both digit-sum gates
pass), and evaluates every hypothesis of `RelWotsEntry.wots_phase_rel` as a Bool. The two
`ctrl_*` rows must be false; the `#guard`s at the end enforce all of it. Run from contracts/verification/lean:
  lake env lean ../../../research/c10-gas/lean/EntryProbe.lean
-/
import SphincsCVerify.Interpreter.RelWotsEntry
open SphincsCVerify.Interpreter SphincsCVerify.Interpreter.C10
open SphincsCVerify.Interpreter.C10.RelChain
open SphincsCVerify.Interpreter.C10.RelE1 (loopBody)
open SphincsCVerify.Spec (ByteVec)
namespace EntryProbe
-- 29 digits of 7, one 2, then zeros: digit sum 205 (the low 17 bytes carry the digits).
def D : Nat := 3 * 2^87 - 1
/-- Input-sensitive in digest bytes 0..13 (byte 14 must stay 0: the forced-zero FORS field, bits 132..142) (the bytes N_MASK keeps for nodes), digit-sum-205
    in bytes 15..31. -/
def mix (xs : List UInt8) : Nat :=
  xs.foldl (fun acc b => (acc * 1099511628211 + b.toNat + 1) % 2^120) 14695981039346656037
def sha (xs : List UInt8) : ByteVec 32 :=
  ⟨Array.ofFn (fun i : Fin 32 => if i.val < 14 then beByte (mix xs) (i.val + 18) else beByte D i.val),
   by simp⟩
def sig : ByteVec 4008 := ⟨Array.ofFn (fun i : Fin 4008 => UInt8.ofNat ((i.val * 7 + 3) % 251)), by simp⟩
def init : VM := ⟨fun _ => 0, fun _ => 0⟩
def pre (prog : List Stmt) : VM × Option Halt := execList sha sig (prog.take 28) init
def atLayer (prog : List Stmt) (layer : Nat) : VM × Option Halt :=
  let p := pre prog
  match p.2 with
  | some h => (p.1, some h)
  | none =>
    if layer = 0 then ({ p.1 with env := setVar p.1.env "layer" 0 }, none)
    else
      let l0 := execList sha sig (loopBody prog[28]?) { p.1 with env := setVar p.1.env "layer" 0 }
      match l0.2 with
      | some h => (l0.1, some h)
      | none => ({ l0.1 with env := setVar l0.1.env "layer" 1 }, none)
def check (r h : VM) : List (String × Bool) :=
  [ ("hlay", r.env "layer" == h.env "layer"), ("hl", decide (r.env "layer" < 2^32)),
    ("hidx", r.env "idxTree" == h.env "idxTree"), ("hidx64", decide (r.env "idxTree" < 2^64)),
    ("hsb", r.env "sigBase" == h.env "sigBase"), ("hso", r.env "sigOff" == h.env "sigOff"),
    ("hwp", decide (r.env "sigBase" + r.env "sigOff" < 4096)),
    ("hseed", r.env "seed" == h.env "seed"),
    ("hnode", (List.range 32).all fun k => h.mem (64 + k) == beByte (r.env "currentNode") k),
    ("htb", (List.range 32).all fun k => h.mem (0x80 + k) == beByte (r.env "seed") k),
    ("hRN", r.env "N_MASK" == NMASK), ("hROUT", r.env "OUT" == 0x600),
    ("hHN", h.env "N_MASK" == NMASK), ("hHTB", h.env "TB" == 0x80), ("hHOUT", h.env "OUT" == 0x620),
    ("node_nonzero", r.env "currentNode" != 0),
    -- controls: each must be false, or the matching check above could not fail
    ("ctrl_node_flipped", (List.range 32).all fun k =>
        h.mem (64 + k) == beByte (r.env "currentNode" ^^^ 2^255) k),
    ("ctrl_tb_vs_node", (List.range 32).all fun k => h.mem (0x80 + k) == beByte (r.env "currentNode") k) ]
#eval (let r := atLayer c10Program 0; let h := atLayer c10HeadProgram 0
       (r.2.isNone, h.2.isNone, check r.1 h.1))
#eval (let r := atLayer c10Program 1; let h := atLayer c10HeadProgram 1
       (r.2.isNone, h.2.isNone, check r.1 h.1))
-- enforced, not only printed (batch-10 review): both prefixes fall through, every hypothesis
-- row is true, and both controls are false, at layer 0 and at layer 1
def expected (r h : VM × Option Halt) : Bool :=
  r.2.isNone && h.2.isNone && (check r.1 h.1).all fun p =>
    if p.1.startsWith "ctrl_" then !p.2 else p.2
#guard expected (atLayer c10Program 0) (atLayer c10HeadProgram 0)
#guard expected (atLayer c10Program 1) (atLayer c10HeadProgram 1)
end EntryProbe

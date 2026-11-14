/-
SphincsCVerify.Interpreter.Yul — a small, EXECUTABLE Yul-subset interpreter.

Foundational infrastructure for the A3.1 deductive-closure track (see
`Interpreter.Memory`, `Interpreter.Climb`): the plan to prove
`∀ inputs, execC10Asm = Spec.verify` by interpreter-refinement + loop-induction,
hash kept opaque. This module supplies the **executable operational semantics**
of the exact Yul fragment the deployed `SPHINCsC10Asm.sol` verifier uses — a
faithful model of EVM word arithmetic (mod `2^256`), byte memory, the `0x02`
SHA-256 precompile (threaded as an oracle parameter so the interpreter stays
hash-agnostic and computable), and the three control constructs the target Yul
actually uses (`if`, the canonical `for { let v:=0 } lt(v,count) { v:=v+1 }`
counting loop, and `{ }` scopes), plus `revert`/`return`.

## Design choices that buy faithfulness

* **True byte memory** (`Interpreter.Memory.ByteMemory = Nat → UInt8`): sub-word
  `mstore` aliasing is represented exactly, not assumed.
* **EVM word semantics mod `W := 2^256`** on every arithmetic result; `sub` uses
  the two's-complement form `(x + (W - y%W)) % W` — NOT `(x-y)%W`, since Lean's
  `Nat` subtraction saturates at 0 and would silently corrupt under `x < y`.
* **Yul `shl`/`shr` operand order**: `shl(x,y) = y << x`, `shr(x,y) = y >> x`
  (first operand is the shift amount, second is the value) — the one place the
  operand order is swapped relative to the source AST `(a b)`.
* **`forRange` count evaluated ONCE at loop entry** — faithful because every loop
  in the target Yul has a body-invariant bound.
* **`sha256` precompile = a parameter** `sha : List UInt8 → ByteVec 32`, so the
  interpreter carries no hash and remains `#eval`-able / axiom-free.

Mathlib-free (Lean core only); no `sorry`/`admit`/`axiom`/`native_decide`;
everything is a total computable `def` (no `partial`), so it `#eval`s and the
`#guard` smoke-tests below run at elaboration time.
-/

import SphincsCVerify.Interpreter.Memory
import SphincsCVerify.Spec.Bytes

namespace SphincsCVerify.Interpreter

/-- The EVM word modulus `2^256`. Every arithmetic op is taken mod `W`. -/
def W : Nat := 2 ^ 256

/-- Big-endian `Nat` of a 32-byte `ByteVec` (MSB first), matching `calldataload`'s
    word value. `getD i 0` is total: out-of-range indices read as `0` (cannot
    happen for a well-formed `ByteVec 32`, but keeps the def computable). -/
def wordOfBV (v : Spec.ByteVec 32) : Nat :=
  (List.range 32).foldl (fun acc i => acc * 256 + (v.data.getD i 0).toNat) 0

/-- `calldataload sig off`: the 32-byte big-endian word at `off` in the signature
    blob, zero-padded past the end (EVM `calldataload` semantics, via
    `Spec.ByteVec.loadWord32`). -/
def calldataload {n : Nat} (sig : Spec.ByteVec n) (off : Nat) : Nat :=
  wordOfBV (sig.loadWord32 off)

/-! ## The AST (exactly the constructs the target Yul uses) -/

/-- Binary operators modelled by the interpreter. -/
inductive BinOp | add | sub | mul | band | bor | bxor | shl | shr | eq | lt
  | byte  -- batch-6 extension (appended): Yul `byte(i, x)`, the i-th big-endian byte of x
deriving Repr, DecidableEq

/-- Yul expressions. `sigOffset` models the `sig.offset` calldata base (= 0). -/
inductive Expr
  | lit (n : Nat)
  | var (name : String)
  | sigOffset                       -- Yul `sig.offset`; modeled as 0
  | sigLength                       -- Yul `sig.length`; the calldata blob's byte length
  | bin (op : BinOp) (a b : Expr)
  | iszero (a : Expr)
  | mload (off : Expr)
  | calldataload (off : Expr)
deriving Repr

/-- Yul statements. -/
inductive Stmt
  | letv (name : String) (e : Expr)         -- `let name := e`
  | setv (name : String) (e : Expr)         -- `name := e`
  | mstore (off val : Expr)                 -- `mstore(off, val)`
  | sha256 (inOff inLen outOff : Expr)      -- `pop(staticcall(gas(), 0x02, inOff, inLen, outOff, 32))`
  | ifnz (cond : Expr) (body : List Stmt)   -- Yul `if cond { body }` — body runs iff cond ≠ 0
  | forRange (v : String) (count : Expr) (body : List Stmt)
      -- models `for { let v := 0 } lt(v, count) { v := add(v,1) } { body }`
      -- (count is evaluated ONCE at entry — faithful since bounds are body-invariant)
  | block (body : List Stmt)                -- a `{ ... }` scope (flat env; no shadowing in this Yul)
  | revert                                  -- `revert(...)` → halt-revert
  | ret (off : Expr)                        -- `return(off, 0x20)` → halt-return the 32-byte word at off
  -- ── batch-6 extension for the optimized v1 verifier (APPENDED: every constructor above and
  --    its semantics are unchanged; see the "Extension" section below) ──
  | mstore8 (off val : Expr)                -- `mstore8(off, val)`: the byte `val mod 256` at off
  | calldatacopy (dst src len : Expr)       -- `calldatacopy(dst, src, len)`, zero past the blob
  | sha256h (inOff inLen outOff : Expr)
      -- `pop(staticcall(gas(), 0x02, inOff, inLen, outOff, 16))`: the FIRST 16 digest bytes
  | forFrom (v : String) (start count : Expr) (body : List Stmt)
      -- `for { let v := start } lt(v, count) { v := add(v,1) } { body }`; start and count are
      -- evaluated ONCE at entry, and the body runs with v = start, …, count-1 (none if
      -- start ≥ count), until a halt. This corresponds to the Yul loop under the forRange
      -- convention, on these PREMISES: word-valued inputs and literals, in particular
      -- `eval sig vm start < 2^256` (the interpreter does not reduce every expression mod 2^256:
      -- literals, variables, `sig.length` and some bitwise results are returned as they are; the
      -- parser enforces only the literal count < 2^256; the target's starts `and(…, 7)` are
      -- bounded); the body does not assign v (checked by the parser); v is loop-local (lexical
      -- scope correct in the source); and states are compared on OBSERVABLE state only: like
      -- `forRange`, the driver does not replay the initializer or the final post-increment on v
      -- (start 7, count 7 leaves v's old binding; start 5, count 7 leaves v = 6), which is
      -- unobservable once v is out of scope.
deriving Repr

/-! ## Interpreter state -/

/-- Variable environment: unbound names read as `0`. -/
abbrev VarEnv := String → Nat

/-- Bind `x ↦ v`, shadowing any prior binding. -/
def setVar (env : VarEnv) (x : String) (v : Nat) : VarEnv :=
  fun y => if y = x then v else env y

/-- Interpreter machine state: byte memory + variable environment. -/
structure VM where
  mem : ByteMemory
  env : VarEnv

/-- Halt outcome of a program: a `revert(...)` or a `return(off,0x20)` whose
    32-byte word is recorded. -/
inductive Halt | reverted | returned (w : Nat)

/-! ## Expression evaluation -/

/-- Evaluate an expression against the signature blob and a machine state.
    EVM word semantics: every arithmetic result is taken mod `W = 2^256`, and
    `shl`/`shr` swap the operand order (`shl(shift,value) = value <<< shift`). -/
def eval {n : Nat} (sig : Spec.ByteVec n) (vm : VM) : Expr → Nat
  | .lit k => k
  | .var name => vm.env name
  | .sigOffset => 0
  | .sigLength => n
  | .iszero a => if eval sig vm a = 0 then 1 else 0
  | .mload off => mload32 vm.mem (eval sig vm off)
  | .calldataload off => calldataload sig (eval sig vm off)
  | .bin op a b =>
      let x := eval sig vm a
      let y := eval sig vm b
      match op with
      | .add  => (x + y) % W
      | .sub  => (x + (W - y % W)) % W      -- EVM two's-complement sub (NOT (x-y)%W)
      | .mul  => (x * y) % W
      | .band => x &&& y
      | .bor  => x ||| y
      | .bxor => x ^^^ y
      | .shl  => (y <<< x) % W              -- Yul shl(x,y) = y << x : a=shift, b=value
      | .shr  => y >>> x                    -- Yul shr(x,y) = y >> x : a=shift, b=value
      | .eq   => if x = y then 1 else 0
      | .lt   => if x < y then 1 else 0
      | .byte => if x < 32 then (y >>> (8 * (31 - x))) % 256 else 0  -- EVM BYTE (i = x)

/-! ## Extension helpers (batch 6: byte-granular writes)

`writeBytes` generalizes `writeRegion` (32 bytes) to any length; `mstore8Mem` writes one byte;
`calldataByte` is the blob byte at `i`, zero past the end (consistent with `calldataload`, whose
`loadWord32` zero-pads the same way). Used ONLY by the appended statement forms. -/

/-- Write `len` bytes `f 0 .. f (len-1)` at `off`. -/
def writeBytes (mem : ByteMemory) (off len : Nat) (f : Nat → UInt8) : ByteMemory :=
  fun a => if off ≤ a ∧ a < off + len then f (a - off) else mem a

/-- EVM `mstore8(off, val)`: the byte `val mod 256` at `off`. -/
def mstore8Mem (mem : ByteMemory) (off val : Nat) : ByteMemory :=
  fun a => if a = off then UInt8.ofNat (val % 256) else mem a

/-- The calldata (signature blob) byte at `i`; `0` past the end. -/
def calldataByte {n : Nat} (sig : Spec.ByteVec n) (i : Nat) : UInt8 :=
  sig.data.getD i 0

/-! ## Statement execution

`execStmt`, `execList`, and the loop driver `execFor` are mutually recursive over
the structural size of the `Stmt` / `List Stmt` (and the loop counter for
`execFor`). Each returns `VM × Option Halt`: `none` = fell through, `some h` =
halted. Once halted, the remaining statements / loop iterations are skipped. The
SHA-256 precompile is the `sha` parameter; the digest is always 32 bytes. -/

mutual
  /-- Execute one statement. -/
  def execStmt {n : Nat} (sha : List UInt8 → Spec.ByteVec 32) (sig : Spec.ByteVec n) :
      Stmt → VM → VM × Option Halt
    | .letv name e, vm => ({ vm with env := setVar vm.env name (eval sig vm e) }, none)
    | .setv name e, vm => ({ vm with env := setVar vm.env name (eval sig vm e) }, none)
    | .mstore off val, vm =>
        ({ vm with mem := mstore32 vm.mem (eval sig vm off) (eval sig vm val) }, none)
    | .sha256 inOff inLen outOff, vm =>
        let dig := sha (slice vm.mem (eval sig vm inOff) (eval sig vm inLen))
        ({ vm with mem := writeRegion vm.mem (eval sig vm outOff) (fun i => dig.data.getD i 0) },
         none)
    | .ifnz cond body, vm =>
        if eval sig vm cond ≠ 0 then execList sha sig body vm else (vm, none)
    | .forRange v count body, vm => execFor sha sig v body (eval sig vm count) 0 vm
    | .block body, vm => execList sha sig body vm
    | .revert, vm => (vm, some Halt.reverted)
    | .ret off, vm => (vm, some (Halt.returned (mload32 vm.mem (eval sig vm off))))
    -- batch-6 extension
    | .mstore8 off val, vm =>
        ({ vm with mem := mstore8Mem vm.mem (eval sig vm off) (eval sig vm val) }, none)
    | .calldatacopy dst src len, vm =>
        let s := eval sig vm src
        ({ vm with mem := writeBytes vm.mem (eval sig vm dst) (eval sig vm len)
                            (fun i => calldataByte sig (s + i)) }, none)
    | .sha256h inOff inLen outOff, vm =>
        let dig := sha (slice vm.mem (eval sig vm inOff) (eval sig vm inLen))
        ({ vm with mem := writeBytes vm.mem (eval sig vm outOff) 16 (fun i => dig.data.getD i 0) },
         none)
    | .forFrom v start count body, vm =>
        let s := eval sig vm start
        execFor sha sig v body (eval sig vm count - s) s vm

  /-- Execute a list of statements with short-circuit on the first halt. -/
  def execList {n : Nat} (sha : List UInt8 → Spec.ByteVec 32) (sig : Spec.ByteVec n) :
      List Stmt → VM → VM × Option Halt
    | [], vm => (vm, none)
    | s :: rest, vm =>
        match execStmt sha sig s vm with
        | (vm', none) => execList sha sig rest vm'
        | (vm', some h) => (vm', some h)

  /-- Drive the counting loop `for { let v:=0 } lt(v,count) { v:=v+1 } { body }`.
      `count` (= `N`) is fixed at entry; `i` is the current iteration index.
      Runs `body` with `env v := i` for `i = cur .. cur+remaining-1`, stopping
      early on halt. `remaining` is the structural-recursion fuel. -/
  def execFor {n : Nat} (sha : List UInt8 → Spec.ByteVec 32) (sig : Spec.ByteVec n)
      (v : String) (body : List Stmt) : (remaining cur : Nat) → VM → VM × Option Halt
    | 0, _, vm => (vm, none)
    | remaining + 1, cur, vm =>
        let vm := { vm with env := setVar vm.env v cur }
        match execList sha sig body vm with
        | (vm', none) => execFor sha sig v body remaining (cur + 1) vm'
        | (vm', some h) => (vm', some h)
end

/-! ## Composition + binding-frame lemmas (proof-phase foundation)

These are the workhorses the phase-wise refinement consumes (`docs/A3_1_CLOSURE_PATH.md`
§8 step 4): `execList_append` splits the program at phase boundaries (with the
halt short-circuit threaded), and the `setVar` frame lemmas let a phase carry a
computed binding (e.g. `digest`) past later statements that touch other vars. -/

/-- Reading the just-bound variable returns the bound value. -/
@[simp] theorem setVar_get_eq (env : VarEnv) (x : String) (v : Nat) :
    setVar env x v x = v := by
  unfold setVar; rw [if_pos rfl]

/-- Reading a *different* variable is unaffected by a binding. -/
@[simp] theorem setVar_get_ne (env : VarEnv) (x y : String) (v : Nat) (h : y ≠ x) :
    setVar env x v y = env y := by
  unfold setVar; rw [if_neg h]

/-- **Phase composition.** Running `xs ++ ys` runs `xs`, and — only if `xs` did
    not halt — continues with `ys` from the resulting state; a halt in `xs`
    short-circuits. The structural lemma behind every phase split. -/
theorem execList_append {n : Nat} (sha : List UInt8 → Spec.ByteVec 32) (sig : Spec.ByteVec n)
    (xs ys : List Stmt) (vm : VM) :
    execList sha sig (xs ++ ys) vm
      = match execList sha sig xs vm with
        | (vm', none)   => execList sha sig ys vm'
        | (vm', some h) => (vm', some h) := by
  induction xs generalizing vm with
  | nil => simp only [List.nil_append, execList]
  | cons s rest ih =>
      show execList sha sig (s :: (rest ++ ys)) vm = _
      rw [execList]
      cases hs : execStmt sha sig s vm with
      | mk vm' o =>
        cases o with
        | none => rw [execList, hs]; exact ih vm'
        | some h => rw [execList, hs]

/-- **Loop-induction for `forRange`.** Thread an invariant `R : Nat → VM → Prop`
    through a (halt-free) counting loop: if each iteration from `R cur` runs the
    body without halting and re-establishes `R (cur+1)`, then the whole loop from
    `R cur` finishes without halting in a state satisfying `R (cur+remaining)`.
    The concrete interpreter analogue of `climbMem_eq_specClimb` — the engine every
    C10 climb/accumulate loop (FORS/WOTS/Merkle/root-compress) is refined through.
    Proved by induction on `remaining`. -/
theorem execFor_invariant {n : Nat} (sha : List UInt8 → Spec.ByteVec 32) (sig : Spec.ByteVec n)
    (v : String) (body : List Stmt) (R : Nat → VM → Prop)
    (hstep : ∀ cur vm, R cur vm →
      (execList sha sig body { vm with env := setVar vm.env v cur }).2 = none ∧
      R (cur + 1) (execList sha sig body { vm with env := setVar vm.env v cur }).1) :
    ∀ (remaining cur : Nat) (vm : VM), R cur vm →
      (execFor sha sig v body remaining cur vm).2 = none ∧
      R (cur + remaining) (execFor sha sig v body remaining cur vm).1 := by
  intro remaining
  induction remaining with
  | zero =>
      intro cur vm hR
      simp only [execFor, Nat.add_zero]
      exact ⟨trivial, hR⟩
  | succ rem ih =>
      intro cur vm hR
      obtain ⟨hnone, hR1⟩ := hstep cur vm hR
      rw [execFor]
      -- The match scrutinee is `execList … { vm with env := setVar vm.env v cur }`;
      -- `hnone` says its `.2` is `none`, so the match takes the continue branch.
      revert hR1
      rcases hp : execList sha sig body { vm with env := setVar vm.env v cur } with ⟨pvm, po⟩
      rw [hp] at hnone
      subst hnone
      intro hR1
      have hih := ih (cur + 1) pvm hR1
      rw [show cur + (rem + 1) = (cur + 1) + rem by omega]
      exact hih

/-- **Bounded loop-induction for `forRange`.** The `execFor_invariant` variant in
    which the per-iteration step `hstep` may *assume* the index is in range
    (`cur < N`). This is what a sound climb engine needs: the invariant
    `R cur w` is only re-established for `cur < N`, so a hypothesis bounded by
    `cur < N` (e.g. `H_adrs`/`H_sib` quantified `h < A`) is dischargeable at every
    iteration the engine actually runs. Proved by generalizing over the remaining
    fuel `rem` with `cur + rem = N` (so `cur < N` whenever `rem = j+1`), mirroring
    `execFor_invariant`'s `rcases`/`subst` match handling. -/
theorem execFor_invariant_lt {n : Nat} (sha : List UInt8 → Spec.ByteVec 32) (sig : Spec.ByteVec n)
    (v : String) (body : List Stmt) (N : Nat) (R : Nat → VM → Prop)
    (hstep : ∀ cur vm, cur < N → R cur vm →
      (execList sha sig body { vm with env := setVar vm.env v cur }).2 = none ∧
      R (cur + 1) (execList sha sig body { vm with env := setVar vm.env v cur }).1) :
    ∀ vm, R 0 vm →
      (execFor sha sig v body N 0 vm).2 = none ∧ R N (execFor sha sig v body N 0 vm).1 := by
  -- Generalize: from index `cur` with `rem` iterations left and `cur + rem = N`.
  suffices hgen : ∀ rem cur vm, cur + rem = N → R cur vm →
      (execFor sha sig v body rem cur vm).2 = none ∧
      R (cur + rem) (execFor sha sig v body rem cur vm).1 by
    intro vm hR0
    have h := hgen N 0 vm (by omega) hR0
    rwa [Nat.zero_add] at h
  intro rem
  induction rem with
  | zero =>
      intro cur vm _ hR
      simp only [execFor, Nat.add_zero]
      exact ⟨trivial, hR⟩
  | succ rem ih =>
      intro cur vm hsum hR
      -- `cur < N` since `cur + (rem + 1) = N`.
      obtain ⟨hnone, hR1⟩ := hstep cur vm (by omega) hR
      rw [execFor]
      revert hR1
      rcases hp : execList sha sig body { vm with env := setVar vm.env v cur } with ⟨pvm, po⟩
      rw [hp] at hnone
      subst hnone
      intro hR1
      have hih := ih (cur + 1) pvm (by omega) hR1
      rw [show cur + (rem + 1) = (cur + 1) + rem by omega]
      exact hih

/-! ## Top-level program execution -/

/-- Run a program from a caller-supplied initial memory (`mem0` lets the caller
    preload pkSeed / pkRoot / message). The Bool verdict mirrors the on-chain
    verifier: `return(off,0x20)` of the word `1` ⇒ `true`; a returned word `≠ 1`,
    a `revert`, or fall-through ⇒ `false`. -/
def execFrom {n : Nat} (sha : List UInt8 → Spec.ByteVec 32) (sig : Spec.ByteVec n)
    (program : List Stmt) (env0 : VarEnv) (mem0 : ByteMemory) : Bool :=
  match (execList sha sig program { mem := mem0, env := env0 }).2 with
  | some (Halt.returned w) => decide (w = 1)
  | some Halt.reverted     => false
  | none                   => false

/-- Run a program from an all-zero initial environment. Thin wrapper over
    `execFrom`; the real C10 verifier (`execC10Asm`) uses `execFrom` to inject
    `pkSeed`/`pkRoot`/`message` as the function's parameter bindings. -/
def execProgram {n : Nat} (sha : List UInt8 → Spec.ByteVec 32) (sig : Spec.ByteVec n)
    (program : List Stmt) (mem0 : ByteMemory) : Bool :=
  execFrom sha sig program (fun _ => 0) mem0

/-! ## Validation: compile-time shake-out (`#guard` = test; a failure won't compile)

A dummy oracle (32 zero bytes), an empty signature blob, and an all-zero initial
memory. We exercise: `mload`-after-`mstore` round-trip via the `ret`/Bool path;
`forRange` accumulation via the env; and `shl`/`shr`/`band` operand order. -/

/-- The hash-agnostic dummy precompile: always 32 zero bytes. -/
private def dummySha : List UInt8 → Spec.ByteVec 32 := fun _ => Spec.ByteVec.zero 32

/-- An empty calldata blob (none of the smoke programs touch `calldataload`). -/
private def sig0 : Spec.ByteVec 0 := Spec.ByteVec.zero 0

/-- All-zero initial memory. -/
private def mem0 : ByteMemory := fun _ => 0

private def vm0 : VM := { mem := mem0, env := fun _ => 0 }

-- (1) mstore→mload→ret round-trip: store `1` at offset 0, then `return(0,0x20)`.
--     `mload32` of the freshly-stored word is `1`, so the Bool verdict is `true`.
#guard execProgram dummySha sig0 [Stmt.mstore (.lit 0) (.lit 1), Stmt.ret (.lit 0)] mem0 = true

-- (1b) storing a non-1 word reverts the Bool verdict to false (return path, w≠1).
#guard execProgram dummySha sig0 [Stmt.mstore (.lit 0) (.lit 7), Stmt.ret (.lit 0)] mem0 = false

-- (1c) round-trip a large value through memory (off 64), confirm exact readback.
#guard execProgram dummySha sig0
    [Stmt.mstore (.lit 64) (.lit 123456789),
     Stmt.ifnz (.bin .eq (.mload (.lit 64)) (.lit 123456789))
       [Stmt.mstore (.lit 0) (.lit 1), Stmt.ret (.lit 0)],
     Stmt.revert] mem0 = true

-- (2) forRange accumulation: acc := Σ_{i=0}^{4} i = 0+1+2+3+4 = 10.
#guard (execList dummySha sig0
    [Stmt.letv "acc" (.lit 0),
     Stmt.forRange "i" (.lit 5)
       [Stmt.setv "acc" (.bin .add (.var "acc") (.var "i"))]] vm0).1.env "acc" = 10

-- (2b) forRange runs exactly `count` times: counting 0,1,...,9 leaves "i" = 9 on
--      the last iteration (loop var keeps the final index after the body runs).
#guard (execList dummySha sig0
    [Stmt.forRange "i" (.lit 10) [Stmt.letv "_" (.lit 0)]] vm0).1.env "i" = 9

-- (2c) forRange with count 0 runs the body zero times (acc stays 0).
#guard (execList dummySha sig0
    [Stmt.letv "acc" (.lit 7),
     Stmt.forRange "i" (.lit 0) [Stmt.setv "acc" (.lit 99)]] vm0).1.env "acc" = 7

-- (2d) forRange short-circuits on halt: revert inside the loop stops it.
#guard (match (execList dummySha sig0
    [Stmt.forRange "i" (.lit 5) [Stmt.revert]] vm0).2 with
    | some Halt.reverted => true | _ => false) = true

-- (3) shl operand order: shl(8, 1) = 1 << 8 = 256  (a = shift = 8, b = value = 1).
#guard eval sig0 vm0 (.bin .shl (.lit 8) (.lit 1)) = 256

-- (3b) shr operand order: shr(4, 256) = 256 >> 4 = 16  (a = shift, b = value).
#guard eval sig0 vm0 (.bin .shr (.lit 4) (.lit 256)) = 16

-- (3c) band: 0xF0 &&& 0x3C = 0x30 = 48.
#guard eval sig0 vm0 (.bin .band (.lit 0xF0) (.lit 0x3C)) = 48

-- (3d) two's-complement sub does NOT saturate: 3 - 5 = W - 2 (EVM underflow wrap),
--      whereas Nat `(3 - 5) % W` would be 0. This guards the landmine.
#guard eval sig0 vm0 (.bin .sub (.lit 3) (.lit 5)) = W - 2

-- (3e) iszero: iszero(0) = 1, iszero(5) = 0.
#guard eval sig0 vm0 (.iszero (.lit 0)) = 1
#guard eval sig0 vm0 (.iszero (.lit 5)) = 0

-- (4) sha256 precompile writes the (dummy = zero) digest into the output window;
--     mload of that window is therefore 0, so the eq-to-0 branch returns true.
#guard execProgram dummySha sig0
    [Stmt.mstore (.lit 0) (.lit 0xdeadbeef),
     Stmt.sha256 (.lit 0) (.lit 32) (.lit 0),
     Stmt.ifnz (.iszero (.mload (.lit 0)))
       [Stmt.mstore (.lit 0) (.lit 1), Stmt.ret (.lit 0)],
     Stmt.revert] mem0 = true

end SphincsCVerify.Interpreter

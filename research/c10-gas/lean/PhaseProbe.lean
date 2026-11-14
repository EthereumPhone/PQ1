/-
research/c10-gas/lean/PhaseProbe.lean — batch 10 executed probe of the RelSkeleton coupling
predicates (NOT a proof, not part of the SphincsCVerify build). It runs BOTH real programs fragment
by fragment, exactly along the skeleton's splits, and evaluates every coupling predicate as a Bool
at its cut point: `HmsgExit`, `ForsExit`, `LayerInv` at layers 0, 1 and 2, `WotsExit` at layers 0
and 1, and after the pk compression the walk's `MInv … 0` (with leaf / treeAdrs / merklePtr read
off the states) and `MidCarry`. Finally it checks that both verdicts agree. The `#guard`s fail
the run if any predicate is false, so a phase obligation that real executions cannot meet shows
up here. Reachable states alone cannot show that an obligation's HYPOTHESIS is strong enough, so
the sweeps (below) also mutate states that satisfy each phase's entry predicate and check that the
phase still reaches its exit predicate.

Two oracles: `mixSha` (input-sensitive in the digest bytes node values keep; digit sum 205 in the
low bytes; zero keys) and the real `c10Oracle` on KAT vector `valid-1` (a valid signature, so
the reference verdict is `true`). Run from contracts/verification/lean; `SphincsCVerify.KatVectors`
is not in the default `lake build` target, so build it first:
  lake build SphincsCVerify.KatVectors
  lake env lean ../../../research/c10-gas/lean/PhaseProbe.lean
-/
import SphincsCVerify.Interpreter.RelSkeleton
import SphincsCVerify.KatVectors
open SphincsCVerify.Interpreter SphincsCVerify.Interpreter.C10
open SphincsCVerify.Interpreter.C10.RelChain
open SphincsCVerify.Interpreter.C10.RelMerkle
open SphincsCVerify.Interpreter.C10.RelWotsEntry
open SphincsCVerify.Interpreter.C10.RelSkeleton
open SphincsCVerify.Spec (ByteVec)
namespace PhaseProbe

def D : Nat := 3 * 2^87 - 1
def mix (xs : List UInt8) : Nat :=
  xs.foldl (fun acc b => (acc * 1099511628211 + b.toNat + 1) % 2^120) 14695981039346656037
def mixSha (xs : List UInt8) : ByteVec 32 :=
  ⟨Array.ofFn (fun i : Fin 32 => if i.val < 14 then beByte (mix xs) (i.val + 18) else beByte D i.val),
   by simp⟩
/-- A second, structurally different oracle (batch 11): position-weighted, xor-folded, with the
    same digest layout constraints (input-sensitive bytes 0..13, digit sum 205 below, byte 14 zero
    for the forced-zero FORS field). -/
def mix2 (xs : List UInt8) : Nat :=
  (xs.foldl (fun (p : Nat × Nat) b =>
      (p.1 + 1, ((p.2 ^^^ (b.toNat * (p.1 + 7))) * 0x9E3779B97F4A7C15 + p.1) % 2^112)) (0, 12345)).2
def mix2Sha (xs : List UInt8) : ByteVec 32 :=
  ⟨Array.ofFn (fun i : Fin 32 => if i.val < 14 then beByte (mix2 xs) (i.val + 18) else beByte D i.val),
   by simp⟩
def mixSig : ByteVec 4008 := ⟨Array.ofFn (fun i : Fin 4008 => UInt8.ofNat ((i.val * 7 + 3) % 251)), by simp⟩

def nibble (c : Char) : Nat := if c ≤ '9' then c.toNat - '0'.toNat else c.toNat - 'a'.toNat + 10
def hexBV (n : Nat) (s : String) : ByteVec n :=
  let a := (s.toList.drop 2).toArray
  ⟨Array.ofFn (fun i : Fin n => UInt8.ofNat (16 * nibble (a.getD (2*i.val) '0') + nibble (a.getD (2*i.val+1) '0'))),
   by simp⟩
def kat := SphincsCVerify.KatVectors.vectors.head!

def all32 (f : Nat → Bool) : Bool := (List.range 32).all f
def low16 (f : Nat → Bool) : Bool := (List.range' 16 16).all f

def chkHmsg (r h : VM) : List (String × Bool) :=
  [ ("seed", h.env "seed" == r.env "seed"),
    ("seedMemR", all32 fun k => r.mem k == beByte (r.env "seed") k),
    ("seedMemH", all32 fun k => h.mem k == beByte (r.env "seed") k),
    ("root", h.env "root" == r.env "root"), ("ht", h.env "htIdx" == r.env "htIdx"),
    ("ht18", decide (r.env "htIdx" < 2^18)), ("dv", h.env "dVal" == r.env "dVal"),
    ("sbR", r.env "sigBase" == 0), ("sbH", h.env "sigBase" == 0),
    ("pad50", low16 fun k => h.mem (64 + k) == 0),
    ("rN", r.env "N_MASK" == NMASK), ("rOUT", r.env "OUT" == 0x600),
    ("hN", h.env "N_MASK" == NMASK), ("hTB", h.env "TB" == 0x80), ("hOUT", h.env "OUT" == 0x620),
    ("zeroH", (List.range' 0xC0 (0x260 - 0xC0)).all fun a => h.mem a == 0) ]

def chkFors (r h : VM) : List (String × Bool) :=
  [ ("node", all32 fun k => h.mem (64 + k) == beByte (r.env "forsPk") k),
    ("pkLow", low16 fun k => beByte (r.env "forsPk") k == 0), ("pkW", decide (r.env "forsPk" < 2^256)),
    ("tb", all32 fun k => h.mem (0x80 + k) == beByte (r.env "seed") k),
    ("seed", h.env "seed" == r.env "seed"), ("root", h.env "root" == r.env "root"),
    ("ht", h.env "htIdx" == r.env "htIdx"), ("ht18", decide (r.env "htIdx" < 2^18)),
    ("sbR", r.env "sigBase" == 0), ("sbH", h.env "sigBase" == 0),
    ("rN", r.env "N_MASK" == NMASK), ("rOUT", r.env "OUT" == 0x600),
    ("hN", h.env "N_MASK" == NMASK), ("hTB", h.env "TB" == 0x80), ("hOUT", h.env "OUT" == 0x620) ]

def chkLayer (c : Nat) (r h : VM) : List (String × Bool) :=
  [ ("idx", h.env "idxTree" == r.env "idxTree"), ("idx64", decide (r.env "idxTree" < 2^64)),
    ("sbR", r.env "sigBase" == 0), ("sbH", h.env "sigBase" == 0),
    ("soR", r.env "sigOff" == 2336 + 836 * c), ("soH", h.env "sigOff" == 2336 + 836 * c),
    ("seed", h.env "seed" == r.env "seed"), ("root", h.env "root" == r.env "root"),
    ("node", all32 fun k => h.mem (64 + k) == beByte (r.env "currentNode") k),
    ("cnLow", low16 fun k => beByte (r.env "currentNode") k == 0),
    ("cnW", decide (r.env "currentNode" < 2^256)),
    ("tb", all32 fun k => h.mem (0x80 + k) == beByte (r.env "seed") k),
    ("rN", r.env "N_MASK" == NMASK), ("rOUT", r.env "OUT" == 0x600),
    ("hN", h.env "N_MASK" == NMASK), ("hTB", h.env "TB" == 0x80), ("hOUT", h.env "OUT" == 0x620) ]

def chkWots (c : Nat) (r h : VM) : List (String × Bool) :=
  [ ("ends", (List.range 43).all fun i => all32 fun k => r.mem (0x80 + 32 * i + k) == h.mem (0xC0 + 32 * i + k)),
    ("seedMem", all32 fun k => h.mem k == r.mem k),
    ("seedR", all32 fun k => r.mem k == beByte (r.env "seed") k),
    ("pad50", low16 fun k => h.mem (64 + k) == 0), ("pad60", all32 fun k => h.mem (96 + k) == 0),
    ("tb", all32 fun k => h.mem (0x80 + k) == beByte (r.env "seed") k),
    ("layerR", r.env "layer" == c), ("layerH", h.env "layer" == c),
    ("idx", h.env "idxTree" == r.env "idxTree"), ("idx64", decide (r.env "idxTree" < 2^64)),
    ("leaf", h.env "idxLeaf" == r.env "idxLeaf"), ("leaf512", decide (r.env "idxLeaf" < 512)),
    ("coR", r.env "countOff" == 2336 + 836 * c + 688), ("coH", h.env "countOff" == r.env "countOff"),
    ("sbR", r.env "sigBase" == 0), ("sbH", h.env "sigBase" == 0),
    ("seed", h.env "seed" == r.env "seed"), ("root", h.env "root" == r.env "root"),
    ("rN", r.env "N_MASK" == NMASK), ("rOUT", r.env "OUT" == 0x600),
    ("hN", h.env "N_MASK" == NMASK), ("hTB", h.env "TB" == 0x80), ("hOUT", h.env "OUT" == 0x620) ]

/-- `MInv leaf ta mp _ _ 0 r h` (its frame clauses are reflexive at `h = 0`) plus the two bounds
    and `MidCarry c r h`, with leaf / ta / mp read off the states. -/
def chkMid (c : Nat) (r h : VM) : List (String × Bool) :=
  let leaf := h.env "idxLeaf"; let ta := r.env "treeAdrs"; let mp := r.env "merklePtr"
  [ ("leaf512", decide (leaf < 512)), ("mp4096", decide (mp < 4096)),
    ("mIdx", r.env "mIdx" == leaf), ("mpH", h.env "merklePtr" == mp),
    ("mN", r.env "N_MASK" == NMASK), ("mOUT", r.env "OUT" == 0x600),
    ("slots", h.env "slots" == slotsOf leaf), ("tbw", h.env "tb" == (ta &&& TM)),
    ("seedMem", all32 fun k => h.mem k == r.mem k),
    ("nodeSlot", all32 fun k => h.mem (nodeAddr leaf 0 + k) == beByte (r.env "merkleNode") k),
    ("mnLow", low16 fun k => beByte (r.env "merkleNode") k == 0),
    ("pad", low16 fun k => h.mem (64 + k) == 0 && h.mem (96 + k) == 0),
    ("idx", h.env "idxTree" == r.env "idxTree"), ("idx64", decide (r.env "idxTree" < 2^64)),
    ("aoR", r.env "authOff" == 2336 + 836 * c + 692), ("aoH", h.env "authOff" == r.env "authOff"),
    ("sbR", r.env "sigBase" == 0), ("sbH", h.env "sigBase" == 0),
    ("seed", h.env "seed" == r.env "seed"), ("root", h.env "root" == r.env "root"),
    ("tb", all32 fun k => h.mem (0x80 + k) == beByte (r.env "seed") k),
    ("mnW", decide (r.env "merkleNode" < 2^256)),
    ("hN", h.env "N_MASK" == NMASK), ("hTB", h.env "TB" == 0x80), ("hOUT", h.env "OUT" == 0x620) ]

def failed (l : List (String × Bool)) : List String := (l.filter (fun p => !p.2)).map (·.1)

/-- Every cut point along the skeleton's splits; a list of (cut, failed fields, fell through). -/
def run (sha : List UInt8 → ByteVec 32) (sig : ByteVec 4008) (v0 : VM) : List (String × List String × Bool) := Id.run do
  let mut out : List (String × List String × Bool) := []
  let r1 := execList sha sig refHmsg v0; let h1 := execList sha sig headHmsg v0
  out := out ++ [("hmsg", failed (chkHmsg r1.1 h1.1), r1.2.isNone && h1.2.isNone)]
  let r2 := execList sha sig refFors r1.1; let h2 := execList sha sig headFors h1.1
  out := out ++ [("fors", failed (chkFors r2.1 h2.1), r2.2.isNone && h2.2.isNone)]
  let r3 := execList sha sig refPreL r2.1; let h3 := execList sha sig headPreL h2.1
  let mut vR := r3.1
  let mut vH := h3.1
  for c in [0, 1] do
    out := out ++ [(s!"layer{c}", failed (chkLayer c vR vH), true)]
    let wR : VM := { vR with env := setVar vR.env "layer" c }
    let wH : VM := { vH with env := setVar vH.env "layer" c }
    let e1 := execList sha sig refWotsPhase wR; let e2 := execList sha sig headWotsPhase wH
    out := out ++ [(s!"wots{c}", failed (chkWots c e1.1 e2.1), e1.2.isNone && e2.2.isNone)]
    let m1 := execList sha sig refMid e1.1; let m2 := execList sha sig headMid e2.1
    out := out ++ [(s!"mid{c}", failed (chkMid c m1.1 m2.1), m1.2.isNone && m2.2.isNone)]
    let k1 := execStmt sha sig refWalk m1.1; let k2 := execList sha sig headWalk m2.1
    let f1 := execList sha sig refFin k1.1; let f2 := execList sha sig headFin k2.1
    vR := f1.1
    vH := f2.1
  out := out ++ [("layer2", failed (chkLayer 2 vR vH), true)]
  return out

def mixV0 : VM := ⟨fun _ => 0, fun _ => 0⟩
def katSig : ByteVec 4008 := hexBV 4008 kat.signature
def katV0 : VM := vm0 (hexBV 32 kat.pkSeed) (hexBV 32 kat.pkRoot) (hexBV 32 kat.message)

def ok (l : List (String × List String × Bool)) : Bool := l.all fun p => p.2.1.isEmpty && p.2.2


/-! ## Hypothesis sweeps (batch 10, strengthened in batch 11)

Reachable states cannot show that an obligation's HYPOTHESIS is strong enough. For each phase the
sweep takes the phase's entry states from a real run, mutates them (one memory byte, or one
variable, on one side), keeps the mutants that still satisfy the phase's ENTRY predicate, runs
the two fragments, and requires equal statuses and, on fall-through, the EXIT predicate. A
mutant that fails under a substitute oracle is a CANDIDATE counterexample: the obligations are
stated for `c10Oracle`, so every failing mutant is replayed under `c10Oracle` from the same entry
states, and only a failure there refutes the obligation (reported as `confirmed`). In batch 10
this found the missing `HmsgExit.zeroH`. Since batch 11 every obligation is proven, so the sweeps
are a regression check on the Bool encodings and the splits, not evidence for the theorems.

Modes (environment variable `SWEEP`): `off` (default), `block` (one byte per 16-byte block over
`[0, 0x640)`, every phase), `full` (every byte over every range FORS reads on either side,
`[0, 0x260)` and `[0x600, 0x640)`, for the FORS phase; the other phases as in `block`).
`SWEEP_CHUNK` / `SWEEP_NCHUNKS` split the mutant list for parallel runs.

Measured runtimes (batch 11, 24-core host, with other jobs running): the probe without sweeps
about 35 s; `SWEEP=block` as one process 2,193 s (about 37 min); `SWEEP=full` in 22 parallel
chunks 759 s wall. Use the chunk variables for anything but `off`. -/

def flip (m : ByteMemory) (a : Nat) : ByteMemory := fun x => if x = a then m x + 1 else m x
def haltEq : Option Halt → Option Halt → Bool
  | none, none => true
  | some .reverted, some .reverted => true
  | some (.returned a), some (.returned b) => a == b
  | _, _ => false
def allOk (l : List (String × Bool)) : Bool := l.all (·.2)

/-- Every variable any fragment or predicate reads. -/
def sweepVars : List String :=
  ["seed", "root", "htIdx", "dVal", "digest", "sigBase", "sigOff", "N_MASK", "OUT", "TB", "R",
   "forsPk", "currentNode", "idxTree", "idxLeaf", "layer", "countOff", "count", "wotsAdrs",
   "wotsPtr", "d", "digitSum", "authOff", "treeAdrs", "merkleNode", "mIdx", "merklePtr", "slots",
   "tb", "message", "pkSeed", "pkRoot", "valid"]

structure Phase where
  name : String
  entryOk : VM → VM → Bool
  runR : VM → VM × Option Halt
  runH : VM → VM × Option Halt
  exitOk : VM → VM → Bool

/-- The mutants of `(r, h)`: memory flips at `addrs` and `+1` on each of `sweepVars`, each side. -/
def mutants (r h : VM) (addrs : List Nat) : List (String × VM × VM) :=
  addrs.flatMap (fun a => [ (s!"R@{a}", { r with mem := flip r.mem a }, h),
                            (s!"H@{a}", r, { h with mem := flip h.mem a }) ])
  ++ sweepVars.flatMap (fun x => [ (s!"R.{x}", { r with env := setVar r.env x (r.env x + 1) }, h),
                                   (s!"H.{x}", r, { h with env := setVar h.env x (h.env x + 1) }) ])

/-- Replay one failing mutant under `c10Oracle`: does it still fail? -/
def confirm (p : Phase) (r' h' : VM) : Bool :=
  let a := p.runR r'
  let b := p.runH h'
  !(haltEq a.2 b.2 && (a.2.isSome || p.exitOk a.1 b.1))

/-- Run the sweep of one phase over the mutants with index `≡ chunk (mod n)`; failing mutants are
    replayed under `pc` (the same phase under `c10Oracle`). Returns (kept mutants, failing labels,
    each marked `confirmed` or `substitute-only`). -/
def sweepPhase (p pc : Phase) (r h : VM) (addrs : List Nat) (chunk n : Nat) : Nat × List String :=
  let ms := ((mutants r h addrs).zip (List.range (mutants r h addrs).length)).filter (fun q => q.2 % n == chunk)
  ms.foldl (fun (acc : Nat × List String) q =>
    let (lbl, r', h') := q.1
    if p.entryOk r' h' then
      let a := p.runR r'
      let b := p.runH h'
      let good := haltEq a.2 b.2 && (a.2.isSome || p.exitOk a.1 b.1)
      (acc.1 + 1, if good then acc.2 else
        acc.2 ++ [p.name ++ ":" ++ lbl ++ (if confirm pc r' h' then "(confirmed)" else "(substitute-only)")])
    else acc) (0, [])

def layerOn (c : Nat) (v : VM) : VM := { v with env := setVar v.env "layer" c }

/-- The phase runners (fragments and predicates) under `sha`. -/
def runners (sha : List UInt8 → ByteVec 32) (sig : ByteVec 4008) : List Phase :=
  [ ⟨"fors", fun r h => allOk (chkHmsg r h), execList sha sig refFors, execList sha sig headFors,
       fun r h => allOk (chkFors r h)⟩,
    ⟨"preL", fun r h => allOk (chkFors r h), execList sha sig refPreL, execList sha sig headPreL,
       fun r h => allOk (chkLayer 0 r h)⟩,
    ⟨"wots0", fun r h => allOk (chkLayer 0 r h), fun v => execList sha sig refWotsPhase (layerOn 0 v),
       fun v => execList sha sig headWotsPhase (layerOn 0 v), fun r h => allOk (chkWots 0 r h)⟩,
    ⟨"mid0", fun r h => allOk (chkWots 0 r h), execList sha sig refMid, execList sha sig headMid,
       fun r h => allOk (chkMid 0 r h)⟩,
    ⟨"walkFin0", fun r h => allOk (chkMid 0 r h),
       fun v => execList sha sig refFin (execStmt sha sig refWalk v).1,
       fun v => execList sha sig headFin (execList sha sig headWalk v).1,
       fun r h => allOk (chkLayer 1 r h)⟩,
    ⟨"tail", fun r h => allOk (chkLayer 2 r h), execList sha sig refTail, execList sha sig headTail,
       fun _ _ => true⟩ ]

/-- The phases' entry states, from a real run under `sha`. -/
def entries (sha : List UInt8 → ByteVec 32) (sig : ByteVec 4008) (v0 : VM) : List (VM × VM) :=
  let r1 := (execList sha sig refHmsg v0).1;  let h1 := (execList sha sig headHmsg v0).1
  let r2 := (execList sha sig refFors r1).1;  let h2 := (execList sha sig headFors h1).1
  let r3 := (execList sha sig refPreL r2).1;  let h3 := (execList sha sig headPreL h2).1
  let e1 := (execList sha sig refWotsPhase (layerOn 0 r3)).1
  let e2 := (execList sha sig headWotsPhase (layerOn 0 h3)).1
  let m1 := (execList sha sig refMid e1).1;   let m2 := (execList sha sig headMid e2).1
  let k1 := (execStmt sha sig refWalk m1).1;  let k2 := (execList sha sig headWalk m2).1
  let l1R := (execList sha sig refFin k1).1;  let l1H := (execList sha sig headFin k2).1
  let f1 := (execList sha sig refBody (layerOn 1 l1R)).1
  let f2 := (execList sha sig headBody (layerOn 1 l1H)).1
  [(r1, h1), (r2, h2), (r3, h3), (e1, e2), (m1, m2), (f1, f2)]

def blockAddrs : List Nat := (List.range 100).map (· * 16)
def forsAddrs : List Nat := List.range 0x260 ++ List.range' 0x600 0x40

/-- Run every phase's sweep under both oracles in the selected mode; print kept counts; fail on
    any failing mutant. -/
def sweepMain : IO Unit := do
  let mode := (← IO.getEnv "SWEEP").getD "off"
  if mode == "off" then return
  let chunk := ((← IO.getEnv "SWEEP_CHUNK").bind String.toNat?).getD 0
  let n := ((← IO.getEnv "SWEEP_NCHUNKS").bind String.toNat?).getD 1
  let mut bad : List String := []
  for (oname, sha) in [("mix", mixSha), ("mix2", mix2Sha)] do
    let ps := runners sha mixSig
    let pcs := runners c10Oracle mixSig
    let es := entries sha mixSig mixV0
    for ((p, pc), (r, h)) in (ps.zip pcs).zip es do
      let addrs := if mode == "full" && p.name == "fors" then forsAddrs else blockAddrs
      let (kept, fails) := sweepPhase p pc r h addrs chunk n
      IO.println s!"sweep[{mode} {chunk}/{n}] {oname} {p.name}: kept {kept}, failing {fails}"
      bad := bad ++ fails.map (oname ++ ":" ++ ·)
  if !bad.isEmpty then throw <| IO.userError s!"sweep failures: {bad}"

#eval run mixSha mixSig mixV0
#eval run c10Oracle katSig katV0
#guard ok (run mixSha mixSig mixV0)
#guard ok (run c10Oracle katSig katV0)
#guard ok (run mix2Sha mixSig mixV0)
-- the verdicts: equal, and true for the valid KAT
#guard execFrom c10Oracle katSig c10HeadProgram katV0.env katV0.mem
    == execFrom c10Oracle katSig c10Program katV0.env katV0.mem
#guard execFrom c10Oracle katSig c10Program katV0.env katV0.mem == true
-- control: a one-byte change to the signature flips both verdicts to false, together
def badSig : ByteVec 4008 := ⟨katSig.data.set! 3000 (katSig.data[3000]! + 1), by simp [katSig, hexBV]⟩
#guard execFrom c10Oracle badSig c10HeadProgram katV0.env katV0.mem == false
#guard execFrom c10Oracle badSig c10Program katV0.env katV0.mem == false
#eval sweepMain
end PhaseProbe

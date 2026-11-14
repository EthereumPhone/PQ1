/-
SphincsCVerify.Interpreter.RelSkeleton — RESEARCH (#1155 gas track, batch 10): the top-down
skeleton of the relational proof. The end theorem, `head_verdict_eq`, says the optimized v1
(`c10HeadProgram`) returns the same verdict as the reference (`c10Program`, the transcription of
the deployed verifier) for every key, message and signature, under the real SHA-256 oracle.

It is proven from a structure of named PHASE OBLIGATIONS (`PhaseObligations`). Each obligation
is one statement about one fragment of the two programs, between named coupling predicates
(`HmsgExit`, `ForsExit`, `LayerInv`, `WotsExit`, `MidCarry`). The glue between the phases is
proven here once: the program and layer-body splits (pins by `rfl`), the WOTS phase
(`RelWotsEntry.wots_phase_rel`), the Merkle walk (`RelMerkle.merkle_walk_rel`), the two-layer
loop, and the prelude end. All five obligations are discharged: `fin_obl` and `tail_obl` here,
`RelHmsg.hmsg_obl`, `RelMid.mid_obl` and `RelFors.fors_obl` in their own files (which import this
one). The unconditional end theorem is `RelFors.head_verdict_eq_full`.

An obligation that is false would make the end theorem vacuous, so every coupling predicate is
meant to be met by real executions (see research/c10-gas/lean/EntryProbe.lean for the probe of
`LayerInv`). Mathlib-free; no `sorry`/`admit`/`native_decide`/`bv_decide` and no new axioms.
-/

import SphincsCVerify.Interpreter.RelWotsEntry
import SphincsCVerify.Interpreter.RelMerkle

namespace SphincsCVerify.Interpreter.C10.RelSkeleton

open SphincsCVerify.Interpreter
open SphincsCVerify.Interpreter.C10
open SphincsCVerify.Interpreter.C10.RelE1 (loopBody execList_single refDigitSumFrag)
open SphincsCVerify.Interpreter.C10.RelChain
open SphincsCVerify.Interpreter.C10.RelWots
open SphincsCVerify.Interpreter.C10.RelWotsEntry
open SphincsCVerify.Interpreter.C10.RelMerkle
open SphincsCVerify.Spec (ByteVec)

/-! ## 1. The two verifiers and their pieces -/

/-- The entry bindings `execC10Asm` uses. -/
def env0 (pkSeed pkRoot message : ByteVec 32) : VarEnv :=
  setVar (setVar (setVar (fun _ => 0) "pkSeed" (wordOf pkSeed)) "pkRoot" (wordOf pkRoot))
    "message" (wordOf message)

def vm0 (pkSeed pkRoot message : ByteVec 32) : VM :=
  { mem := fun _ => 0, env := env0 pkSeed pkRoot message }

/-- The optimized v1, run exactly as `execC10Asm` runs the reference. -/
def execC10HeadAsm (pkSeed pkRoot message : ByteVec 32) (sig : ByteVec Spec.SignatureLen) : Bool :=
  execFrom c10Oracle sig c10HeadProgram (env0 pkSeed pkRoot message) (fun _ => 0)

def refBody : List Stmt := loopBody c10Program[28]?
def headBody : List Stmt := loopBody c10HeadProgram[28]?
/-- H_msg and the gates (reference statements 0..18, optimized 0..19). -/
def refHmsg : List Stmt := c10Program.take 19
def headHmsg : List Stmt := c10HeadProgram.take 20
/-- FORS: 12 trees, the last tree, the root compression (reference 19..24, optimized 20..25). -/
def refFors : List Stmt := (c10Program.drop 19).take 6
def headFors : List Stmt := (c10HeadProgram.drop 20).take 6
/-- The bindings before the layer loop (reference 25..27, optimized 26..27). -/
def refPreL : List Stmt := (c10Program.drop 25).take 3
def headPreL : List Stmt := (c10HeadProgram.drop 26).take 2
/-- After the layer loop: the root comparison and the return (statements 29..31). -/
def refTail : List Stmt := c10Program.drop 29
def headTail : List Stmt := c10HeadProgram.drop 29
/-- Layer body: pk compression and Merkle setup (reference 16..25, optimized 188..197). -/
def refMid : List Stmt := (refBody.drop 16).take 10
def headMid : List Stmt := (headBody.drop 188).take 10
def refWalk : Stmt := .forRange "h" (.lit 9) htClimbBody
def headWalk : List Stmt := (List.range 9).flatMap merkleBlk
/-- Layer body: the finalize (reference 27..28, optimized 225). -/
def refFin : List Stmt :=
  [ .setv "currentNode" (.var "merkleNode"), .setv "sigOff" (.bin .add (.var "authOff") (.lit 144)) ]
def headFin : List Stmt := [ .setv "sigOff" (.bin .add (.var "authOff") (.lit 144)) ]

set_option maxRecDepth 100000 in
set_option maxHeartbeats 8000000 in
theorem ref_program_split :
    c10Program = refHmsg ++ (refFors ++ (refPreL ++ (.forRange "layer" (.lit 2) refBody :: refTail))) :=
  rfl

set_option maxRecDepth 100000 in
set_option maxHeartbeats 8000000 in
theorem head_program_split :
    c10HeadProgram
      = headHmsg ++ (headFors ++ (headPreL ++ (.forRange "layer" (.lit 2) headBody :: headTail))) :=
  rfl

set_option maxRecDepth 100000 in
set_option maxHeartbeats 8000000 in
theorem ref_body_split : refBody = refWotsPhase ++ (refMid ++ (refWalk :: refFin)) := rfl

set_option maxRecDepth 100000 in
set_option maxHeartbeats 8000000 in
theorem head_body_split : headBody = headWotsPhase ++ (headMid ++ (headWalk ++ headFin)) := rfl

/-! ## 2. The coupling predicates between phases -/

/-- After H_msg and the gates (both fell through). -/
structure HmsgExit (r h : VM) : Prop where
  seed : h.env "seed" = r.env "seed"
  seedMemR : ∀ k, k < 32 → r.mem k = beByte (r.env "seed") k
  seedMemH : ∀ k, k < 32 → h.mem k = beByte (r.env "seed") k
  root : h.env "root" = r.env "root"
  ht : h.env "htIdx" = r.env "htIdx"
  ht18 : r.env "htIdx" < 2 ^ 18
  dv : h.env "dVal" = r.env "dVal"
  sbR : r.env "sigBase" = 0
  sbH : h.env "sigBase" = 0
  pad50 : ∀ k, 16 ≤ k → k < 32 → h.mem (64 + k) = 0
  rN : r.env "N_MASK" = NMASK
  rOUT : r.env "OUT" = 0x600
  hN : h.env "N_MASK" = NMASK
  hTB : h.env "TB" = 0x80
  hOUT : h.env "OUT" = 0x620
  /-- The optimized FORS writes each of its 13 roots as 16 bytes into a 32-byte slot at
      `0xC0 + 32i` and then hashes `[0x80, 0x260)`, so it relies on the slots' low halves being
      zero (they are, from the zero initial memory). Without this field `ForsObl` is false
      (batch-10 sweep, `research/c10-gas/lean/PhaseProbe.lean`). -/
  zeroH : ∀ a, 0xC0 ≤ a → a < 0x260 → h.mem a = 0

/-- After FORS: the reference's `forsPk` variable against the optimized node word at `0x40`. -/
structure ForsExit (r h : VM) : Prop where
  node : ∀ k, k < 32 → h.mem (64 + k) = beByte (r.env "forsPk") k
  pkLow : ∀ k, 16 ≤ k → k < 32 → beByte (r.env "forsPk") k = 0
  pkW : r.env "forsPk" < 2 ^ 256
  tb : ∀ k, k < 32 → h.mem (0x80 + k) = beByte (r.env "seed") k
  seed : h.env "seed" = r.env "seed"
  root : h.env "root" = r.env "root"
  ht : h.env "htIdx" = r.env "htIdx"
  ht18 : r.env "htIdx" < 2 ^ 18
  sbR : r.env "sigBase" = 0
  sbH : h.env "sigBase" = 0
  rN : r.env "N_MASK" = NMASK
  rOUT : r.env "OUT" = 0x600
  hN : h.env "N_MASK" = NMASK
  hTB : h.env "TB" = 0x80
  hOUT : h.env "OUT" = 0x620

/-- **The cross-layer invariant**, at the entry of layer `c` (before the loop binds `layer`).
    The optimized node lives in memory at `0x40`, the reference's in `currentNode`. -/
structure LayerInv (c : Nat) (vR vH : VM) : Prop where
  idx : vH.env "idxTree" = vR.env "idxTree"
  idx64 : vR.env "idxTree" < 2 ^ 64
  sbR : vR.env "sigBase" = 0
  sbH : vH.env "sigBase" = 0
  soR : vR.env "sigOff" = 2336 + 836 * c
  soH : vH.env "sigOff" = 2336 + 836 * c
  seed : vH.env "seed" = vR.env "seed"
  root : vH.env "root" = vR.env "root"
  node : ∀ k, k < 32 → vH.mem (64 + k) = beByte (vR.env "currentNode") k
  cnLow : ∀ k, 16 ≤ k → k < 32 → beByte (vR.env "currentNode") k = 0
  cnW : vR.env "currentNode" < 2 ^ 256
  tb : ∀ k, k < 32 → vH.mem (0x80 + k) = beByte (vR.env "seed") k
  rN : vR.env "N_MASK" = NMASK
  rOUT : vR.env "OUT" = 0x600
  hN : vH.env "N_MASK" = NMASK
  hTB : vH.env "TB" = 0x80
  hOUT : vH.env "OUT" = 0x620

/-- After the WOTS phase of layer `c`: everything the pk compression and the Merkle setup read. -/
structure WotsExit (c : Nat) (r h : VM) : Prop where
  ends : ∀ i, i < 43 → ∀ k, k < 32 → r.mem (0x80 + 32 * i + k) = h.mem (0xC0 + 32 * i + k)
  seedMem : ∀ k, k < 32 → h.mem k = r.mem k
  seedR : ∀ k, k < 32 → r.mem k = beByte (r.env "seed") k
  pad50 : ∀ k, 16 ≤ k → k < 32 → h.mem (64 + k) = 0
  pad60 : ∀ k, k < 32 → h.mem (96 + k) = 0
  tb : ∀ k, k < 32 → h.mem (0x80 + k) = beByte (r.env "seed") k
  layerR : r.env "layer" = c
  layerH : h.env "layer" = c
  idx : h.env "idxTree" = r.env "idxTree"
  idx64 : r.env "idxTree" < 2 ^ 64
  leaf : h.env "idxLeaf" = r.env "idxLeaf"
  leaf512 : r.env "idxLeaf" < 512
  coR : r.env "countOff" = 2336 + 836 * c + 688
  coH : h.env "countOff" = r.env "countOff"
  sbR : r.env "sigBase" = 0
  sbH : h.env "sigBase" = 0
  seed : h.env "seed" = r.env "seed"
  root : h.env "root" = r.env "root"
  rN : r.env "N_MASK" = NMASK
  rOUT : r.env "OUT" = 0x600
  hN : h.env "N_MASK" = NMASK
  hTB : h.env "TB" = 0x80
  hOUT : h.env "OUT" = 0x620

/-- What the finalize and the next layer need, carried through the Merkle walk. -/
structure MidCarry (c : Nat) (r h : VM) : Prop where
  idx : h.env "idxTree" = r.env "idxTree"
  idx64 : r.env "idxTree" < 2 ^ 64
  aoR : r.env "authOff" = 2336 + 836 * c + 692
  aoH : h.env "authOff" = r.env "authOff"
  sbR : r.env "sigBase" = 0
  sbH : h.env "sigBase" = 0
  seed : h.env "seed" = r.env "seed"
  root : h.env "root" = r.env "root"
  tb : ∀ k, k < 32 → h.mem (0x80 + k) = beByte (r.env "seed") k
  mnW : r.env "merkleNode" < 2 ^ 256
  rN : r.env "N_MASK" = NMASK
  rOUT : r.env "OUT" = 0x600
  hN : h.env "N_MASK" = NMASK
  hTB : h.env "TB" = 0x80
  hOUT : h.env "OUT" = 0x620

/-! ## 3. The phase obligations -/

/-- **(O1) H_msg and the gates.** -/
def HmsgObl : Prop := ∀ (pkSeed pkRoot message : ByteVec 32) (sig : ByteVec Spec.SignatureLen),
  (execList c10Oracle sig refHmsg (vm0 pkSeed pkRoot message)).2
    = (execList c10Oracle sig headHmsg (vm0 pkSeed pkRoot message)).2
  ∧ ((execList c10Oracle sig refHmsg (vm0 pkSeed pkRoot message)).2 = none →
      HmsgExit (execList c10Oracle sig refHmsg (vm0 pkSeed pkRoot message)).1
        (execList c10Oracle sig headHmsg (vm0 pkSeed pkRoot message)).1)

/-- **(O2) FORS** (12 trees, the last tree, the root compression). -/
def ForsObl : Prop := ∀ (sig : ByteVec Spec.SignatureLen) (r h : VM), HmsgExit r h →
  (execList c10Oracle sig refFors r).2 = (execList c10Oracle sig headFors h).2
  ∧ ((execList c10Oracle sig refFors r).2 = none →
      ForsExit (execList c10Oracle sig refFors r).1 (execList c10Oracle sig headFors h).1)

/-- **(O3) pk compression and Merkle setup**, into the walk's `MInv … 0`. -/
def MidObl : Prop := ∀ (sig : ByteVec Spec.SignatureLen) (c : Nat) (r h : VM), c < 2 →
  WotsExit c r h →
  (execList c10Oracle sig refMid r).2 = none ∧ (execList c10Oracle sig headMid h).2 = none
  ∧ ∃ leaf ta mp, leaf < 512 ∧ mp < 4096
      ∧ MInv leaf ta mp (execList c10Oracle sig refMid r).1.mem (execList c10Oracle sig headMid h).1.mem 0
          (execList c10Oracle sig refMid r).1 (execList c10Oracle sig headMid h).1
      ∧ MidCarry c (execList c10Oracle sig refMid r).1 (execList c10Oracle sig headMid h).1

/-- **(O4) The finalize**, from what the Merkle walk leaves, into the next layer's invariant. -/
def FinObl : Prop := ∀ (sig : ByteVec Spec.SignatureLen) (c : Nat) (r h r2 h2 : VM), c < 2 →
  MidCarry c r h →
  (∀ k, k < 32 → h2.mem (64 + k) = beByte (r2.env "merkleNode") k) →
  (∀ k, 16 ≤ k → k < 32 → beByte (r2.env "merkleNode") k = 0) →
  r2.env "merkleNode" < 2 ^ 256 →
  (∀ a, 128 ≤ a → h2.mem a = h.mem a) →
  (∀ x, x ≠ "h" → x ≠ "sibling" → x ≠ "parentIdx" → x ≠ "s" → x ≠ "merkleNode" → x ≠ "mIdx" →
    r2.env x = r.env x) →
  (∀ x, h2.env x = h.env x) →
  (execList c10Oracle sig refFin r2).2 = none ∧ (execList c10Oracle sig headFin h2).2 = none
  ∧ LayerInv (c + 1) (execList c10Oracle sig refFin r2).1 (execList c10Oracle sig headFin h2).1

/-- **(O5) The tail**: the root comparison and the return. -/
def TailObl : Prop := ∀ (sig : ByteVec Spec.SignatureLen) (vR vH : VM), LayerInv 2 vR vH →
  (execList c10Oracle sig refTail vR).2 = (execList c10Oracle sig headTail vH).2

structure PhaseObligations : Prop where
  hmsg : HmsgObl
  fors : ForsObl
  mid : MidObl
  fin : FinObl
  tail : TailObl

/-! ## 4. Glue, proven once -/

/-- **Two loops in lock step that halt alike.** -/
theorem execFor_rel' {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n)
    (v1 : String) (b1 : List Stmt) (v2 : String) (b2 : List Stmt) (N : Nat)
    (R : Nat → VM → VM → Prop)
    (hstep : ∀ c w1 w2, c < N → R c w1 w2 →
      (execList sha sig b1 { w1 with env := setVar w1.env v1 c }).2
        = (execList sha sig b2 { w2 with env := setVar w2.env v2 c }).2
      ∧ ((execList sha sig b1 { w1 with env := setVar w1.env v1 c }).2 = none →
          R (c + 1) (execList sha sig b1 { w1 with env := setVar w1.env v1 c }).1
            (execList sha sig b2 { w2 with env := setVar w2.env v2 c }).1)) :
    ∀ rem c w1 w2, c + rem = N → R c w1 w2 →
      (execFor sha sig v1 b1 rem c w1).2 = (execFor sha sig v2 b2 rem c w2).2
      ∧ ((execFor sha sig v1 b1 rem c w1).2 = none →
          R N (execFor sha sig v1 b1 rem c w1).1 (execFor sha sig v2 b2 rem c w2).1)
  | 0, c, w1, w2, hN, hR => by
      rw [execFor, execFor]
      rw [Nat.add_zero] at hN
      subst hN
      exact ⟨by first | rfl | trivial, fun _ => hR⟩
  | rem + 1, c, w1, w2, hN, hR => by
      obtain ⟨hs, hi⟩ := hstep c w1 w2 (by omega) hR
      rw [execFor, execFor]
      cases e1 : execList sha sig b1 { w1 with env := setVar w1.env v1 c } with
      | mk a1 o1 =>
        cases e2 : execList sha sig b2 { w2 with env := setVar w2.env v2 c } with
        | mk a2 o2 =>
          rw [e1, e2] at hs
          rw [e1, e2] at hi
          simp only at hs hi
          subst hs
          cases o1 with
          | none =>
            simp only
            exact execFor_rel' sha sig v1 b1 v2 b2 N R hstep rem (c + 1) a1 a2 (by omega) (hi rfl)
          | some hh =>
            simp only
            exact ⟨trivial, fun h => absurd h (by simp)⟩

theorem cons_some {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (s : Stmt)
    (rest : List Stmt) (vm : VM) (hh : Halt) (h : (execStmt sha sig s vm).2 = some hh) :
    (execList sha sig (s :: rest) vm).2 = some hh := by
  rw [execList]
  rcases hp : execStmt sha sig s vm with ⟨v', o⟩
  rw [hp] at h
  cases o with
  | none => exact absurd h (by simp)
  | some _ => simp only at h ⊢; exact h

/-- Values `setup5` leaves that the rest of the reference WOTS phase does not touch. -/
theorem refWotsPhase_vals (sig : ByteVec Spec.SignatureLen) (vR : VM) :
    (execList c10Oracle sig refWotsPhase vR).1.env "idxTree" = vR.env "idxTree" >>> 9
    ∧ (execList c10Oracle sig refWotsPhase vR).1.env "idxLeaf" = vR.env "idxTree" &&& 0x1FF
    ∧ (execList c10Oracle sig refWotsPhase vR).1.env "countOff" = (vR.env "sigOff" + 688) % W := by
  obtain ⟨s0, _, sI, sL, sC, _, _, _⟩ := setup5_eval c10Oracle sig vR
  have e : refWotsPhase = setup5 ++ (wotsDigitHashFragment ++ refDigitSumFrag ++ [gate, wotsPtrStmt]
      ++ [.forRange "i" (.lit 43) wotsChainBody]) := rfl
  rw [e, app_none _ _ _ _ _ s0]
  refine ⟨?_, ?_, ?_⟩
  · rw [execList_env_frame _ _ _ _ _ (by decide), sI]
  · rw [execList_env_frame _ _ _ _ _ (by decide), sL]
  · rw [execList_env_frame _ _ _ _ _ (by decide), sC]

set_option maxHeartbeats 8000000 in
/-- **The WOTS phase from the cross-layer invariant.** With the loop's `layer := c` bound, the
    two WOTS phases halt alike, and when they fall through `WotsExit c` holds. -/
theorem wots_exit (sig : ByteVec Spec.SignatureLen) (c : Nat) (hc : c < 2) (vR vH : VM)
    (hI : LayerInv c vR vH) :
    (execList c10Oracle sig refWotsPhase { vR with env := setVar vR.env "layer" c }).2
      = (execList c10Oracle sig headWotsPhase { vH with env := setVar vH.env "layer" c }).2
    ∧ ((execList c10Oracle sig refWotsPhase { vR with env := setVar vR.env "layer" c }).2 = none →
        WotsExit c (execList c10Oracle sig refWotsPhase { vR with env := setVar vR.env "layer" c }).1
          (execList c10Oracle sig headWotsPhase { vH with env := setVar vH.env "layer" c }).1) := by
  generalize hwR : ({ vR with env := setVar vR.env "layer" c } : VM) = wR
  generalize hwH : ({ vH with env := setVar vH.env "layer" c } : VM) = wH
  have gR : ∀ x, x ≠ "layer" → wR.env x = vR.env x := by
    intro x hx; rw [← hwR]; exact setVar_get_ne _ _ _ _ hx
  have gH : ∀ x, x ≠ "layer" → wH.env x = vH.env x := by
    intro x hx; rw [← hwH]; exact setVar_get_ne _ _ _ _ hx
  have lR : wR.env "layer" = c := by rw [← hwR]; exact setVar_get_eq vR.env "layer" c
  have lH : wH.env "layer" = c := by rw [← hwH]; exact setVar_get_eq vH.env "layer" c
  have mR : wR.mem = vR.mem := by rw [← hwR]
  have mH : wH.mem = vH.mem := by rw [← hwH]
  obtain ⟨hst, himp⟩ := wots_phase_rel sig wR wH (by rw [lR, lH]) (by rw [lR]; omega)
    (by rw [gR _ (by decide), gH _ (by decide), hI.idx])
    (by rw [gR _ (by decide)]; exact hI.idx64)
    (by rw [gR _ (by decide), gH _ (by decide), hI.sbR, hI.sbH])
    (by rw [gR _ (by decide), gH _ (by decide), hI.soR, hI.soH])
    (by rw [gR _ (by decide), gR _ (by decide), hI.sbR, hI.soR]; omega)
    (by rw [gR _ (by decide), gH _ (by decide), hI.seed])
    (by intro k hk; rw [mH, gR _ (by decide)]; exact hI.node k hk)
    (by intro k hk; rw [mH, gR _ (by decide)]; exact hI.tb k hk)
    (by rw [gR _ (by decide)]; exact hI.rN) (by rw [gR _ (by decide)]; exact hI.rOUT)
    (by rw [gH _ (by decide)]; exact hI.hN) (by rw [gH _ (by decide)]; exact hI.hTB)
    (by rw [gH _ (by decide)]; exact hI.hOUT)
  refine ⟨hst, fun h0 => ?_⟩
  obtain ⟨wend, wseed, wRseed, wpad, wpad96, wtb, eL, eI, eLf, eC, eSB, eS, eRN, eROUT, eHN,
    eHTB⟩ := himp h0
  obtain ⟨vI, vL, vC⟩ := refWotsPhase_vals sig wR
  have fR : ∀ x, assignsVarList refWotsPhase x = false →
      (execList c10Oracle sig refWotsPhase wR).1.env x = wR.env x :=
    fun x hx => execList_env_frame _ _ _ _ _ hx
  have fH : ∀ x, assignsVarList headWotsPhase x = false →
      (execList c10Oracle sig headWotsPhase wH).1.env x = wH.env x :=
    fun x hx => execList_env_frame _ _ _ _ _ hx
  have sR : (execList c10Oracle sig refWotsPhase wR).1.env "seed" = vR.env "seed" := by
    rw [fR _ (by decide), gR _ (by decide)]
  refine ⟨wend, wseed, ?_, wpad, wpad96, ?_, ?_, ?_, eI, ?_, eLf, ?_, ?_, eC, ?_, ?_, eS, ?_, eRN,
    eROUT, eHN, eHTB, ?_⟩
  · intro k hk; rw [wRseed k hk, sR, gR _ (by decide)]
  · intro k hk; rw [wtb k hk, sR, gR _ (by decide)]
  · rw [fR _ (by decide), lR]
  · rw [fH _ (by decide), lH]
  · rw [vI, gR _ (by decide)]
    exact Nat.lt_of_le_of_lt (Nat.shiftRight_le _ _) hI.idx64
  · rw [vL]; exact Nat.lt_of_le_of_lt Nat.and_le_right (by decide)
  · rw [vC, gR _ (by decide), hI.soR]
    exact Nat.mod_eq_of_lt (lt_W_of_lt' (by omega))
  · rw [fR _ (by decide), gR _ (by decide), hI.sbR]
  · rw [eSB, fR _ (by decide), gR _ (by decide), hI.sbR]
  · rw [fH _ (by decide), fR _ (by decide), gH _ (by decide), gR _ (by decide), hI.root]
  · rw [fH _ (by decide), gH _ (by decide), hI.hOUT]

/-- The reference walk leaves `merkleNode` below `2^256` (it is a masked digest word). -/
theorem walk_mn_lt {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (leaf ta mp : Nat)
    (r : VM) (hmp : mp < 4096) (hm : r.env "mIdx" = leaf) (hta : r.env "treeAdrs" = ta)
    (hmpR : r.env "merklePtr" = mp) (hN : r.env "N_MASK" = NMASK) (hOUT : r.env "OUT" = 0x600)
    (hW : r.env "merkleNode" < 2 ^ 256) :
    (execStmt sha sig refWalk r).1.env "merkleNode" < 2 ^ 256 := by
  simp only [refWalk, execStmt, eval]
  have hinv := execFor_invariant_lt sha sig "h" htClimbBody 9
    (fun h w => w.env "mIdx" = leaf >>> h ∧ w.env "treeAdrs" = ta ∧ w.env "merklePtr" = mp
      ∧ w.env "N_MASK" = NMASK ∧ w.env "OUT" = 0x600 ∧ w.env "merkleNode" < 2 ^ 256)
    (fun cur w hc hw => by
      obtain ⟨h1, h2, h3, h4, h5, _⟩ := hw
      rw [ref_level_eq sha sig w cur leaf ta mp hc hmp h1 h2 h3 h4 h5]
      refine ⟨by first | rfl | trivial, ?_⟩
      simp only [refLevelOut]
      simp (disch := decide) only [setVar_get_eq, setVar_get_ne]
      exact ⟨by first | rfl | trivial, h2, h3, h4, h5,
        Nat.lt_of_le_of_lt Nat.and_le_left (mload32_lt _ _)⟩)
    r ⟨by rw [hm, Nat.shiftRight_zero], hta, hmpR, hN, hOUT, hW⟩
  exact hinv.2.2.2.2.2.2

set_option maxHeartbeats 8000000 in
/-- **One layer, from the cross-layer invariant to the next one.** -/
theorem layer_rel (O : PhaseObligations) (sig : ByteVec Spec.SignatureLen) (c : Nat) (hc : c < 2)
    (vR vH : VM) (hI : LayerInv c vR vH) :
    (execList c10Oracle sig refBody { vR with env := setVar vR.env "layer" c }).2
      = (execList c10Oracle sig headBody { vH with env := setVar vH.env "layer" c }).2
    ∧ ((execList c10Oracle sig refBody { vR with env := setVar vR.env "layer" c }).2 = none →
        LayerInv (c + 1) (execList c10Oracle sig refBody { vR with env := setVar vR.env "layer" c }).1
          (execList c10Oracle sig headBody { vH with env := setVar vH.env "layer" c }).1) := by
  obtain ⟨hst, himp⟩ := wots_exit sig c hc vR vH hI
  rw [ref_body_split, head_body_split]
  generalize ({ vR with env := setVar vR.env "layer" c } : VM) = wR at hst himp ⊢
  generalize ({ vH with env := setVar vH.env "layer" c } : VM) = wH at hst himp ⊢
  rcases h0 : (execList c10Oracle sig refWotsPhase wR).2 with _ | hh
  · have h0' : (execList c10Oracle sig headWotsPhase wH).2 = none := hst ▸ h0
    have hW := himp h0
    rw [app_none _ _ _ _ _ h0, app_none _ _ _ _ _ h0']
    generalize (execList c10Oracle sig refWotsPhase wR).1 = r at hW ⊢
    generalize (execList c10Oracle sig headWotsPhase wH).1 = h at hW ⊢
    obtain ⟨m0, m0', leaf, ta, mp, hleaf, hmp, hMI, hMC⟩ := O.mid sig c r h hc hW
    rw [app_none _ _ _ _ _ m0, app_none _ _ _ _ _ m0']
    generalize (execList c10Oracle sig refMid r).1 = r1 at hMI hMC ⊢
    generalize (execList c10Oracle sig headMid h).1 = h1 at hMI hMC ⊢
    obtain ⟨w0, w0', wnode, wMI9, wRenv, wHenv⟩ :=
      merkle_walk_rel c10Oracle sig leaf ta mp r1 h1 hleaf hmp hMI
    have mn := walk_mn_lt c10Oracle sig leaf ta mp r1 hmp (by rw [hMI.1, Nat.shiftRight_zero])
      hMI.2.1 hMI.2.2.1 hMI.2.2.2.1 hMI.2.2.2.2.1 hMC.mnW
    obtain ⟨_, _, _, _, _, _, _, _, _, _, _, mlow, _, _, hfr, _⟩ := wMI9
    rw [show (refWalk :: refFin) = (.forRange "h" (.lit 9) htClimbBody :: refFin) from rfl,
      execList_cons_none _ _ _ _ _ w0,
      show (headWalk ++ headFin) = ((List.range 9).flatMap merkleBlk ++ headFin) from rfl,
      app_none _ _ _ _ _ w0']
    obtain ⟨f0, f0', fI⟩ := O.fin sig c r1 h1 _ _ hc hMC wnode mlow mn hfr wRenv wHenv
    exact ⟨f0.trans f0'.symm, fun _ => fI⟩
  · have h0' : (execList c10Oracle sig headWotsPhase wH).2 = some hh := hst ▸ h0
    have a1 := app_some c10Oracle sig _ (refMid ++ (refWalk :: refFin)) _ _ h0
    have a2 := app_some c10Oracle sig _ (headMid ++ (headWalk ++ headFin)) _ _ h0'
    exact ⟨a1.trans a2.symm, fun h => absurd (a1.symm.trans h) (by simp)⟩

/-- **The two-layer loop.** -/
theorem loop_rel (O : PhaseObligations) (sig : ByteVec Spec.SignatureLen) (vR vH : VM)
    (hI : LayerInv 0 vR vH) :
    (execStmt c10Oracle sig (.forRange "layer" (.lit 2) refBody) vR).2
      = (execStmt c10Oracle sig (.forRange "layer" (.lit 2) headBody) vH).2
    ∧ ((execStmt c10Oracle sig (.forRange "layer" (.lit 2) refBody) vR).2 = none →
        LayerInv 2 (execStmt c10Oracle sig (.forRange "layer" (.lit 2) refBody) vR).1
          (execStmt c10Oracle sig (.forRange "layer" (.lit 2) headBody) vH).1) := by
  simp only [execStmt, eval]
  exact execFor_rel' c10Oracle sig "layer" refBody "layer" headBody 2 LayerInv
    (fun c w1 w2 hc hw => layer_rel O sig c hc w1 w2 hw) 2 0 vR vH rfl hI

/-- **The prelude's last bindings**, from FORS into the cross-layer invariant at layer 0. -/
theorem preL_rel (sig : ByteVec Spec.SignatureLen) (r h : VM) (hF : ForsExit r h) :
    (execList c10Oracle sig refPreL r).2 = none ∧ (execList c10Oracle sig headPreL h).2 = none
    ∧ LayerInv 0 (execList c10Oracle sig refPreL r).1 (execList c10Oracle sig headPreL h).1 := by
  rw [show refPreL = [ .letv "currentNode" (.var "forsPk"), .letv "idxTree" (.var "htIdx"),
      .letv "sigOff" (.lit 2336) ] from rfl,
    show headPreL = [ .letv "idxTree" (.var "htIdx"), .letv "sigOff" (.lit 2336) ] from rfl]
  rw [execList_cons_none _ _ _ _ _ (by simp only [execStmt]),
    execList_cons_none _ _ _ _ _ (by simp only [execStmt]), execList_single,
    execList_cons_none _ _ _ _ _ (by simp only [execStmt]), execList_single]
  refine ⟨by simp only [execStmt], by simp only [execStmt], ?_⟩
  simp only [execStmt, eval]
  constructor <;> simp (disch := decide) only [setVar_get_eq, setVar_get_ne]
  all_goals first
    | exact hF.ht
    | exact Nat.lt_of_lt_of_le hF.ht18 (by decide)
    | exact hF.sbR | exact hF.sbH | rfl | exact hF.seed | exact hF.root
    | exact hF.node | exact hF.pkLow | exact hF.pkW | exact hF.tb
    | exact hF.rN | exact hF.rOUT | exact hF.hN | exact hF.hTB | exact hF.hOUT

/-- **The whole verifier, as statuses.** -/
theorem head_status_eq (O : PhaseObligations) (pkSeed pkRoot message : ByteVec 32)
    (sig : ByteVec Spec.SignatureLen) :
    (execList c10Oracle sig c10HeadProgram (vm0 pkSeed pkRoot message)).2
      = (execList c10Oracle sig c10Program (vm0 pkSeed pkRoot message)).2 := by
  obtain ⟨hst, himp⟩ := O.hmsg pkSeed pkRoot message sig
  rw [ref_program_split, head_program_split]
  generalize vm0 pkSeed pkRoot message = v at hst himp ⊢
  rcases h0 : (execList c10Oracle sig refHmsg v).2 with _ | hh
  · have h0' : (execList c10Oracle sig headHmsg v).2 = none := hst ▸ h0
    have hH := himp h0
    rw [app_none _ _ _ _ _ h0, app_none _ _ _ _ _ h0']
    generalize (execList c10Oracle sig refHmsg v).1 = r at hH ⊢
    generalize (execList c10Oracle sig headHmsg v).1 = h at hH ⊢
    obtain ⟨fst, fimp⟩ := O.fors sig r h hH
    rcases f0 : (execList c10Oracle sig refFors r).2 with _ | fh
    · have f0' : (execList c10Oracle sig headFors h).2 = none := fst ▸ f0
      have hF := fimp f0
      rw [app_none _ _ _ _ _ f0, app_none _ _ _ _ _ f0']
      generalize (execList c10Oracle sig refFors r).1 = r1 at hF ⊢
      generalize (execList c10Oracle sig headFors h).1 = h1 at hF ⊢
      obtain ⟨p0, p0', hL⟩ := preL_rel sig r1 h1 hF
      rw [app_none _ _ _ _ _ p0, app_none _ _ _ _ _ p0']
      generalize (execList c10Oracle sig refPreL r1).1 = r2 at hL ⊢
      generalize (execList c10Oracle sig headPreL h1).1 = h2 at hL ⊢
      obtain ⟨lst, limp⟩ := loop_rel O sig r2 h2 hL
      rcases l0 : (execStmt c10Oracle sig (.forRange "layer" (.lit 2) refBody) r2).2 with _ | lh
      · have l0' : (execStmt c10Oracle sig (.forRange "layer" (.lit 2) headBody) h2).2 = none :=
          lst ▸ l0
        rw [execList_cons_none _ _ _ _ _ l0, execList_cons_none _ _ _ _ _ l0']
        exact (O.tail sig _ _ (limp l0)).symm
      · have l0' : (execStmt c10Oracle sig (.forRange "layer" (.lit 2) headBody) h2).2 = some lh :=
          lst ▸ l0
        rw [cons_some _ _ _ _ _ _ l0, cons_some _ _ _ _ _ _ l0']
    · have f0' : (execList c10Oracle sig headFors h).2 = some fh := fst ▸ f0
      rw [app_some _ _ _ _ _ _ f0, app_some _ _ _ _ _ _ f0']
  · have h0' : (execList c10Oracle sig headHmsg v).2 = some hh := hst ▸ h0
    rw [app_some _ _ _ _ _ _ h0, app_some _ _ _ _ _ _ h0']

/-- **The end theorem.** Under the phase obligations, the optimized v1 returns the reference's
    verdict for every key, message and signature. -/
theorem head_verdict_eq (O : PhaseObligations) (pkSeed pkRoot message : ByteVec 32)
    (sig : ByteVec Spec.SignatureLen) :
    execC10HeadAsm pkSeed pkRoot message sig = execC10Asm pkSeed pkRoot message sig := by
  have h := head_status_eq O pkSeed pkRoot message sig
  unfold vm0 env0 at h
  unfold execC10HeadAsm execC10Asm execFrom env0
  rw [h]

/-! ## 5. Obligations discharged -/

/-- **(O4) discharged: the finalize gives the next layer's invariant.** -/
theorem fin_obl : FinObl := by
  intro sig c r h r2 h2 hc hMC wnode mlow mn hfr wRenv wHenv
  unfold refFin headFin
  rw [execList_cons_none _ _ _ _ _ (by simp only [execStmt]), execList_single, execList_single]
  refine ⟨by simp only [execStmt], by simp only [execStmt], ?_⟩
  have rI := wRenv "idxTree" (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
  have rSB := wRenv "sigBase" (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
  have rS := wRenv "seed" (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
  have rRt := wRenv "root" (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
  have rN := wRenv "N_MASK" (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
  have rO := wRenv "OUT" (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
  have rAO := wRenv "authOff" (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
  simp only [execStmt, eval]
  constructor
  all_goals simp (disch := decide) only [setVar_get_eq, setVar_get_ne, wHenv, rI, rSB, rS, rRt, rN, rO,
    rAO]
  · exact hMC.idx
  · exact hMC.idx64
  · exact hMC.sbR
  · exact hMC.sbH
  · rw [hMC.aoR, Nat.mod_eq_of_lt (lt_W_of_lt' (by omega))]; omega
  · rw [hMC.aoH, hMC.aoR, Nat.mod_eq_of_lt (lt_W_of_lt' (by omega))]; omega
  · exact hMC.seed
  · exact hMC.root
  · exact wnode
  · exact mlow
  · exact mn
  · intro k hk; rw [hfr _ (by omega)]; exact hMC.tb k hk
  · exact hMC.rN
  · exact hMC.rOUT
  · exact hMC.hN
  · exact hMC.hTB
  · exact hMC.hOUT

/-- **(O5) discharged: the root comparison and the return agree.** The optimized v1 reads its
    node word from `0x40` and masks it; by the cross-layer invariant that is the reference's
    `currentNode`. -/
theorem tail_obl : TailObl := by
  intro sig vR vH hI
  rw [show refTail = [ .letv "valid" (.bin .eq (.var "currentNode") (.var "root")),
      .mstore (.lit 0) (.var "valid"), .ret (.lit 0) ] from rfl,
    show headTail = [ .setv "valid" (.bin .eq (.bin .band (.mload (.lit 64)) (.var "N_MASK"))
      (.var "root")), .mstore (.lit 0) (.var "valid"), .ret (.lit 0) ] from rfl]
  rw [execList_cons_none _ _ _ _ _ (by simp only [execStmt]),
    execList_cons_none _ _ _ _ _ (by simp only [execStmt]), execList_single,
    execList_cons_none _ _ _ _ _ (by simp only [execStmt]),
    execList_cons_none _ _ _ _ _ (by simp only [execStmt]), execList_single]
  have hkey : mload32 vH.mem 64 &&& NMASK = vR.env "currentNode" := by
    apply eq_of_beByte _ _ (Nat.lt_of_le_of_lt Nat.and_le_left (mload32_lt _ _)) hI.cnW
    intro i hi
    rw [beByte_and_nmask]
    split
    · rw [beByte_mload32 _ _ _ hi]; exact hI.node i hi
    · rw [hI.cnLow i (by omega) hi]
  simp only [execStmt, eval]
  simp only [setVar_get_eq]
  simp only [hI.hN, hkey, hI.root, mload32_mstore32_self]

/-- **The end theorem with O4 and O5 filled in.** O1, O2 and O3 are taken as arguments here only
    because their proofs live in files that import this one (`RelHmsg`, `RelFors`, `RelMid`);
    `RelFors.head_verdict_eq_full` supplies all three. -/
theorem head_verdict_eq_of (hm : HmsgObl) (hf : ForsObl) (hmid : MidObl)
    (pkSeed pkRoot message : ByteVec 32) (sig : ByteVec Spec.SignatureLen) :
    execC10HeadAsm pkSeed pkRoot message sig = execC10Asm pkSeed pkRoot message sig :=
  head_verdict_eq ⟨hm, hf, hmid, fin_obl, tail_obl⟩ pkSeed pkRoot message sig

end SphincsCVerify.Interpreter.C10.RelSkeleton

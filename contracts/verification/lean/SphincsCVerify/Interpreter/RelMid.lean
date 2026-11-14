/-
SphincsCVerify.Interpreter.RelMid — RESEARCH (#1155 gas track, batch 10): obligation O3 of the
skeleton (`RelSkeleton.MidObl`), the WOTS pk compression and the Merkle setup of one layer, into
the Merkle walk's coupling `MInv … 0`.

Reference (layer-body statements 16..25): bind `pkAdrs`, store it at `0x20`, copy the 43 chain
endpoints down from `[0x80, 0x5E0)` to `[0x40, 0x5A0)`, hash `[0, 0x5A0)` into `0x600`, mask the
result into `wotsPk`, then bind `authOff`, `treeAdrs`, `merkleNode`, `mIdx`, `merklePtr`.

Optimized (statements 188..197): store `pkAdrs` at `TB + 0x20`, build the slot word, hash
`[TB, TB + 0x5A0)` straight into the first 16 bytes of the leaf's node slot (`byte(1, slots)`),
then bind `authOff`, `treeAdrs`, `merklePtr`, `tb`.

Both hash the same 1440 bytes: seed, pk ADRS, the 43 endpoints. Mathlib-free; no
`sorry`/`admit`/`native_decide`/`bv_decide` and no new axioms.
-/

import SphincsCVerify.Interpreter.RelSkeleton

namespace SphincsCVerify.Interpreter.C10.RelMid

open SphincsCVerify.Interpreter
open SphincsCVerify.Interpreter.C10
open SphincsCVerify.Interpreter.C10.RelE1 (loopBody execList_single)
open SphincsCVerify.Interpreter.C10.RelChain
open SphincsCVerify.Interpreter.C10.RelWotsEntry
open SphincsCVerify.Interpreter.C10.RelMerkle
open SphincsCVerify.Interpreter.C10.RelSkeleton
open SphincsCVerify.Spec (ByteVec)

/-! ## 1. The endpoint copy (`forsCopyBody`, 43 records) -/

/-- One copy step: `mem[0x40 + 32cur ..] := mem[0x80 + 32cur ..]`. Arbitrary oracle. -/
theorem copy_step {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (cur : Nat) (v : VM)
    (hcur : cur < 43) :
    (execList sha sig forsCopyBody { v with env := setVar v.env "i" cur }).2 = none
    ∧ (∀ a, ¬ (0x40 + 32 * cur ≤ a ∧ a < 0x40 + 32 * cur + 32) →
        (execList sha sig forsCopyBody { v with env := setVar v.env "i" cur }).1.mem a = v.mem a)
    ∧ (∀ k, k < 32 →
        (execList sha sig forsCopyBody { v with env := setVar v.env "i" cur }).1.mem
          (0x40 + 32 * cur + k) = v.mem (0x80 + 32 * cur + k)) := by
  unfold forsCopyBody
  rw [execList_single]
  simp only [execStmt, eval, setVar, ite_true]
  have hdest : (0x40 + cur <<< 5 % W) % W = 64 + 32 * cur := by
    rw [shl5_small cur (by omega), Nat.mod_eq_of_lt (lt_W_of_lt (show 64 + 32 * cur < 4096 by omega))]
  have hsrc : (0x80 + cur <<< 5 % W) % W = 128 + 32 * cur := by
    rw [shl5_small cur (by omega), Nat.mod_eq_of_lt (lt_W_of_lt (show 128 + 32 * cur < 4096 by omega))]
  rw [hdest, hsrc]
  refine ⟨trivial, ?_, ?_⟩
  · intro a ha
    rw [mstore32_frame _ (64 + 32 * cur) _ a (by omega)]
  · intro k hk
    rw [show (0x40 + 32 * cur + k) = ((64 + 32 * cur) + k) by omega,
      mstore32_get _ (64 + 32 * cur) _ k hk, beByte_mload32 v.mem (128 + 32 * cur) k hk]

set_option maxHeartbeats 8000000 in
/-- **The 43-record copy.** It falls through; afterwards record `t` at `0x40 + 32t` is the old
    record at `0x80 + 32t`, and `[0, 0x40)` is unchanged. (Each read is above every earlier
    write: record `t`'s source `0x80 + 32t` is only overwritten by step `t + 2`.) -/
theorem copy_loop {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (vm : VM) :
    (execFor sha sig "i" forsCopyBody 43 0 vm).2 = none
    ∧ (∀ t, t < 43 → ∀ k, k < 32 →
        (execFor sha sig "i" forsCopyBody 43 0 vm).1.mem (0x40 + 32 * t + k) = vm.mem (0x80 + 32 * t + k))
    ∧ (∀ a, a < 0x40 → (execFor sha sig "i" forsCopyBody 43 0 vm).1.mem a = vm.mem a) := by
  let R : Nat → VM → Prop := fun cur w =>
    (∀ t, t < cur → ∀ k, k < 32 → w.mem (0x40 + 32 * t + k) = vm.mem (0x80 + 32 * t + k))
    ∧ (∀ a, 0x40 + 32 * cur ≤ a → w.mem a = vm.mem a)
    ∧ (∀ a, a < 0x40 → w.mem a = vm.mem a)
  have hstep : ∀ cur w, cur < 43 → R cur w →
      (execList sha sig forsCopyBody { w with env := setVar w.env "i" cur }).2 = none ∧
      R (cur + 1) (execList sha sig forsCopyBody { w with env := setVar w.env "i" cur }).1 := by
    intro cur w hcur hR
    obtain ⟨hcopied, hhigh, hlow⟩ := hR
    obtain ⟨hnone, hframe, hcopy⟩ := copy_step sha sig cur w hcur
    refine ⟨hnone, ?_, ?_, ?_⟩
    · intro t ht k hk
      by_cases htc : t < cur
      · rw [hframe _ (by omega)]; exact hcopied t htc k hk
      · have : t = cur := by omega
        subst this
        rw [hcopy k hk]; exact hhigh _ (by omega)
    · intro a ha
      rw [hframe _ (by omega)]; exact hhigh a (by omega)
    · intro a ha
      rw [hframe _ (by omega)]; exact hlow a ha
  have hR0 : R 0 vm := ⟨fun t ht => absurd ht (Nat.not_lt_zero t), fun _ _ => rfl, fun _ _ => rfl⟩
  obtain ⟨h0, hc, _, hl⟩ := execFor_invariant_lt sha sig "i" forsCopyBody 43 R hstep vm hR0
  exact ⟨h0, hc, hl⟩

/-! ## 2. The reference side -/

/-- The pk ADRS word both sides compute from `layer`, `idxTree`, `idxLeaf`. -/
def pkVal (e : VarEnv) : Nat :=
  (e "layer" <<< 224) % W ||| ((e "idxTree" <<< 160) % W ||| ((1 <<< 128) % W ||| (e "idxLeaf" <<< 96) % W))

/-- The tree ADRS word both sides compute. -/
def taVal (e : VarEnv) : Nat :=
  (e "layer" <<< 224) % W ||| ((e "idxTree" <<< 160) % W ||| (2 <<< 128) % W)

def refMidHead : List Stmt :=
  [ .letv "pkAdrs" (.bin .bor (.bin .shl (.lit 224) (.var "layer")) (.bin .bor (.bin .shl (.lit 160)
      (.var "idxTree")) (.bin .bor (.bin .shl (.lit 128) (.lit 1)) (.bin .shl (.lit 96) (.var "idxLeaf")))))
  , .mstore (.lit 32) (.var "pkAdrs") ]

def refMidTail : List Stmt :=
  [ .sha256 (.lit 0) (.lit 1440) (.var "OUT")
  , .letv "wotsPk" (.bin .band (.mload (.var "OUT")) (.var "N_MASK"))
  , .letv "authOff" (.bin .add (.var "countOff") (.lit 4))
  , .letv "treeAdrs" (.bin .bor (.bin .shl (.lit 224) (.var "layer")) (.bin .bor (.bin .shl (.lit 160)
      (.var "idxTree")) (.bin .shl (.lit 128) (.lit 2))))
  , .letv "merkleNode" (.var "wotsPk")
  , .letv "mIdx" (.var "idxLeaf")
  , .letv "merklePtr" (.bin .add (.var "sigBase") (.var "authOff")) ]

set_option maxRecDepth 100000 in
theorem refMid_split : refMid = refMidHead ++ (.forRange "i" (.lit 43) forsCopyBody :: refMidTail) := rfl

set_option maxHeartbeats 8000000 in
/-- **The reference pk compression and Merkle setup, executed.** It falls through. The hash
    input `M` holds the seed bytes, the pk ADRS, and the 43 endpoints moved down by `0x40`;
    `merkleNode` is the masked digest of `M[0, 1440)`. -/
theorem ref_mid_eval {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (r : VM)
    (hOUT : r.env "OUT" = 0x600) :
    (execList sha sig refMid r).2 = none
    ∧ (∃ M : ByteMemory, (∀ i, i < 32 → M i = r.mem i)
        ∧ (∀ k, k < 32 → M (32 + k) = beByte (pkVal r.env) k)
        ∧ (∀ t, t < 43 → ∀ k, k < 32 → M (0x40 + 32 * t + k) = r.mem (0x80 + 32 * t + k))
        ∧ (execList sha sig refMid r).1.env "merkleNode" = wordOf (sha (slice M 0 1440)) &&& r.env "N_MASK")
    ∧ (∀ a, a < 32 → (execList sha sig refMid r).1.mem a = r.mem a)
    ∧ (execList sha sig refMid r).1.env "authOff" = (r.env "countOff" + 4) % W
    ∧ (execList sha sig refMid r).1.env "treeAdrs" = taVal r.env
    ∧ (execList sha sig refMid r).1.env "mIdx" = r.env "idxLeaf"
    ∧ (execList sha sig refMid r).1.env "merklePtr" = (r.env "sigBase" + (r.env "countOff" + 4) % W) % W
    ∧ (∀ x, x ≠ "pkAdrs" → x ≠ "i" → x ≠ "wotsPk" → x ≠ "authOff" → x ≠ "treeAdrs" →
        x ≠ "merkleNode" → x ≠ "mIdx" → x ≠ "merklePtr" → (execList sha sig refMid r).1.env x = r.env x) := by
  rw [refMid_split]
  have hA : execList sha sig refMidHead r
      = ({ mem := mstore32 r.mem 32 (pkVal r.env), env := setVar r.env "pkAdrs" (pkVal r.env) }, none) := by
    unfold refMidHead
    rw [execList_cons_none _ _ _ _ _ (by simp only [execStmt]), execList_single]
    simp only [execStmt, eval, setVar_get_eq]
    rfl
  rw [app_none _ _ _ _ _ (by rw [hA]), hA]
  generalize hvA : ({ mem := mstore32 r.mem 32 (pkVal r.env), env := setVar r.env "pkAdrs" (pkVal r.env) } : VM)
    = vA
  obtain ⟨c0, cM, cL⟩ := copy_loop sha sig vA
  have hS2 : execStmt sha sig (.forRange "i" (.lit 43) forsCopyBody) vA
      = execFor sha sig "i" forsCopyBody 43 0 vA := by simp only [execStmt, eval]
  rw [execList_cons_none _ _ _ _ _ (by rw [hS2]; exact c0), hS2]
  have fB : ∀ x, x ≠ "i" → (execFor sha sig "i" forsCopyBody 43 0 vA).1.env x = vA.env x :=
    fun x hx => execFor_env_frame sha sig "i" forsCopyBody x (Ne.symm hx) (by
      unfold forsCopyBody; simp [assignsVarList, assignsVar]) _ _ _
  generalize hvB : (execFor sha sig "i" forsCopyBody 43 0 vA).1 = vB at cM cL fB
  have eA : ∀ x, x ≠ "pkAdrs" → vA.env x = r.env x := by
    intro x hx; rw [← hvA]; exact setVar_get_ne _ _ _ _ hx
  have eP : vA.env "pkAdrs" = pkVal r.env := by rw [← hvA]; exact setVar_get_eq r.env "pkAdrs" (pkVal r.env)
  have mA : vA.mem = mstore32 r.mem 32 (pkVal r.env) := by rw [← hvA]
  have eOUT : vB.env "OUT" = 0x600 := by
    rw [fB _ (by decide), eA _ (by decide), hOUT]
  have bL : vB.env "layer" = r.env "layer" := by rw [fB _ (by decide), eA _ (by decide)]
  have bI : vB.env "idxTree" = r.env "idxTree" := by rw [fB _ (by decide), eA _ (by decide)]
  have bLf : vB.env "idxLeaf" = r.env "idxLeaf" := by rw [fB _ (by decide), eA _ (by decide)]
  have bC : vB.env "countOff" = r.env "countOff" := by rw [fB _ (by decide), eA _ (by decide)]
  have bSB : vB.env "sigBase" = r.env "sigBase" := by rw [fB _ (by decide), eA _ (by decide)]
  have bN : vB.env "N_MASK" = r.env "N_MASK" := by rw [fB _ (by decide), eA _ (by decide)]
  unfold refMidTail
  repeat rw [execList_cons_none _ _ _ _ _ (by simp only [execStmt])]
  simp only [execList, execStmt, eval, eOUT]
  refine ⟨trivial, ⟨vB.mem, ?_, ?_, ?_, ?_⟩, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro i hi; rw [cL i (by omega), mA, mstore32_frame _ 32 _ i (by omega)]
  · intro k hk; rw [cL _ (by omega), mA, mstore32_get _ _ _ _ hk]
  · intro t ht k hk; rw [cM t ht k hk, mA, mstore32_frame _ 32 _ _ (by omega)]
  · simp (disch := decide) only [setVar_get_eq, setVar_get_ne, bN]
    rw [mload32_digest]
  · intro a ha
    rw [writeRegion_frame _ 0x600 _ a (by omega), cL a (by omega), mA, mstore32_frame _ 32 _ a (by omega)]
  · simp (disch := decide) only [setVar_get_eq, setVar_get_ne, bC]
  · simp (disch := decide) only [setVar_get_eq, setVar_get_ne, bL, bI]
    rfl
  · simp (disch := decide) only [setVar_get_eq, setVar_get_ne, bLf]
  · simp (disch := decide) only [setVar_get_eq, setVar_get_ne, bSB, bC]
  · intro x a1 a2 a3 a4 a5 a6 a7 a8
    simp only [setVar_get_ne _ _ _ _ a8, setVar_get_ne _ _ _ _ a7, setVar_get_ne _ _ _ _ a6,
      setVar_get_ne _ _ _ _ a5, setVar_get_ne _ _ _ _ a4, setVar_get_ne _ _ _ _ a3]
    rw [fB _ a2, eA _ a1]

/-! ## 3. The optimized side -/

def headMidHead : List Stmt :=
  [ .letv "pkAdrs" (.bin .bor (.bin .shl (.lit 224) (.var "layer")) (.bin .bor (.bin .shl (.lit 160)
      (.var "idxTree")) (.bin .bor (.bin .shl (.lit 128) (.lit 1)) (.bin .shl (.lit 96) (.var "idxLeaf")))))
  , .mstore (.bin .add (.var "TB") (.lit 32)) (.var "pkAdrs") ]

def headMidTail : List Stmt :=
  [ .sha256h (.var "TB") (.lit 1440) (.bin .byte (.lit 1) (.var "slots"))
  , .letv "authOff" (.bin .add (.var "countOff") (.lit 4))
  , .letv "treeAdrs" (.bin .bor (.bin .shl (.lit 224) (.var "layer")) (.bin .bor (.bin .shl (.lit 160)
      (.var "idxTree")) (.bin .shl (.lit 128) (.lit 2))))
  , .letv "merklePtr" (.bin .add (.var "sigBase") (.var "authOff"))
  , .letv "tb" (.bin .band (.var "treeAdrs") (.lit TM)) ]

set_option maxRecDepth 100000 in
theorem headMid_split : headMid = headMidHead ++ (slotsSetup ++ headMidTail) := rfl

set_option maxHeartbeats 8000000 in
/-- **The optimized pk compression and Merkle setup, executed.** It falls through. With `M` the
    memory after the pk ADRS store at `TB + 0x20 = 0xA0`, the compression writes the first 16
    digest bytes of `M[0x80, 0x80 + 1440)` into the leaf's node slot `nodeAddr leaf 0`. -/
theorem head_mid_eval {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (h : VM)
    (hTB : h.env "TB" = 0x80) (hleaf : h.env "idxLeaf" < 512) :
    (execList sha sig headMid h).2 = none
    ∧ (∃ M : ByteMemory, (∀ a, a < 0xA0 → M a = h.mem a)
        ∧ (∀ k, k < 32 → M (0xA0 + k) = beByte (pkVal h.env) k)
        ∧ (∀ a, 0xC0 ≤ a → M a = h.mem a)
        ∧ (execList sha sig headMid h).1.mem
            = writeBytes M (nodeAddr (h.env "idxLeaf") 0) 16 (fun i => (sha (slice M 0x80 1440)).data.getD i 0))
    ∧ (execList sha sig headMid h).1.env "slots" = slotsOf (h.env "idxLeaf")
    ∧ (execList sha sig headMid h).1.env "authOff" = (h.env "countOff" + 4) % W
    ∧ (execList sha sig headMid h).1.env "treeAdrs" = taVal h.env
    ∧ (execList sha sig headMid h).1.env "merklePtr" = (h.env "sigBase" + (h.env "countOff" + 4) % W) % W
    ∧ (execList sha sig headMid h).1.env "tb" = (taVal h.env &&& TM)
    ∧ (∀ x, x ≠ "pkAdrs" → x ≠ "t" → x ≠ "sbit" → x ≠ "slots" → x ≠ "authOff" → x ≠ "treeAdrs" →
        x ≠ "merklePtr" → x ≠ "tb" → (execList sha sig headMid h).1.env x = h.env x) := by
  rw [headMid_split]
  have hA : execList sha sig headMidHead h
      = ({ mem := mstore32 h.mem 0xA0 (pkVal h.env), env := setVar h.env "pkAdrs" (pkVal h.env) }, none) := by
    unfold headMidHead
    rw [execList_cons_none _ _ _ _ _ (by simp only [execStmt]), execList_single]
    simp only [execStmt, eval, setVar_get_eq]
    rw [setVar_get_ne _ _ _ _ (by decide), hTB]
    rfl
  rw [app_none _ _ _ _ _ (by rw [hA]), hA]
  generalize hvA : ({ mem := mstore32 h.mem 0xA0 (pkVal h.env), env := setVar h.env "pkAdrs" (pkVal h.env) } : VM)
    = vA
  have eA : ∀ x, x ≠ "pkAdrs" → vA.env x = h.env x := by
    intro x hx; rw [← hvA]; exact setVar_get_ne _ _ _ _ hx
  have mA : vA.mem = mstore32 h.mem 0xA0 (pkVal h.env) := by rw [← hvA]
  obtain ⟨s0, sSl, sM⟩ := slotsSetup_eval sha sig vA
  have fS : ∀ x, assignsVarList slotsSetup x = false →
      (execList sha sig slotsSetup vA).1.env x = vA.env x :=
    fun x hx => execList_env_frame _ _ _ _ _ hx
  rw [app_none _ _ _ _ _ s0]
  generalize hvB : (execList sha sig slotsSetup vA).1 = vB at sSl sM fS
  have bL : vB.env "layer" = h.env "layer" := by rw [fS _ (by decide), eA _ (by decide)]
  have bI : vB.env "idxTree" = h.env "idxTree" := by rw [fS _ (by decide), eA _ (by decide)]
  have bC : vB.env "countOff" = h.env "countOff" := by rw [fS _ (by decide), eA _ (by decide)]
  have bSB : vB.env "sigBase" = h.env "sigBase" := by rw [fS _ (by decide), eA _ (by decide)]
  have bTB : vB.env "TB" = 0x80 := by rw [fS _ (by decide), eA _ (by decide), hTB]
  have bSl : vB.env "slots" = slotsOf (h.env "idxLeaf") := by rw [sSl, eA _ (by decide)]
  have hout : byteAt 1 (slotsOf (h.env "idxLeaf")) = nodeAddr (h.env "idxLeaf") 0 :=
    (slots_decode _ hleaf 0 (by decide)).2
  unfold headMidTail
  repeat rw [execList_cons_none _ _ _ _ _ (by simp only [execStmt])]
  simp only [execList, execStmt, eval, bTB, bSl, byteAt_unfold, hout]
  refine ⟨trivial, ⟨vB.mem, ?_, ?_, ?_, ?_⟩, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro a ha; rw [sM, mA, mstore32_frame _ 0xA0 _ a (by omega)]
  · intro k hk; rw [sM, mA, mstore32_get _ _ _ _ hk]
  · intro a ha; rw [sM, mA, mstore32_frame _ 0xA0 _ a (by omega)]
  · rfl
  · simp (disch := decide) only [setVar_get_eq, setVar_get_ne, bSl]
  · simp (disch := decide) only [setVar_get_eq, setVar_get_ne, bC]
  · simp (disch := decide) only [setVar_get_eq, setVar_get_ne, bL, bI]
    rfl
  · simp (disch := decide) only [setVar_get_eq, setVar_get_ne, bSB, bC]
  · simp (disch := decide) only [setVar_get_eq, setVar_get_ne, bL, bI]
    rfl
  · intro x a1 a2 a3 a4 a5 a6 a7 a8
    simp only [setVar_get_ne _ _ _ _ a8, setVar_get_ne _ _ _ _ a7, setVar_get_ne _ _ _ _ a6,
      setVar_get_ne _ _ _ _ a5]
    have hx : assignsVarList slotsSetup x = false := by
      unfold slotsSetup
      simp [assignsVarList, assignsVar, Ne.symm a2, Ne.symm a3, Ne.symm a4]
    rw [fS _ hx, eA _ a1]

/-! ## 4. O3 discharged -/

theorem slice_congr' (m1 m2 : ByteMemory) (o1 o2 n : Nat)
    (h : ∀ i, i < n → m1 (o1 + i) = m2 (o2 + i)) : slice m1 o1 n = slice m2 o2 n := by
  unfold slice
  apply List.map_congr_left
  intro i hi
  exact h i (List.mem_range.mp hi)

set_option maxHeartbeats 16000000 in
/-- **(O3) discharged.** From `WotsExit c`, the pk compressions hash the same 1440 bytes; the
    Merkle setups give `MInv … 0` (leaf `idxLeaf`, ADRS base `taVal`, auth-path pointer
    `2336 + 836c + 692`) and `MidCarry c`. -/
theorem mid_obl : MidObl := by
  intro sig c r h hc hW
  obtain ⟨r0, ⟨M, mLow, mP, mEnds, mNode⟩, rMem, rAO, rTA, rMI, rMP, rFr⟩ :=
    ref_mid_eval c10Oracle sig r hW.rOUT
  obtain ⟨h0, ⟨MH, hLow, hP, hHigh, hMem⟩, hSl, hAO, hTA, hMP, hTb, hFr⟩ :=
    head_mid_eval c10Oracle sig h hW.hTB (by rw [hW.leaf]; exact hW.leaf512)
  have hpk : pkVal h.env = pkVal r.env := by
    unfold pkVal; rw [hW.layerH, hW.layerR, hW.idx, hW.leaf]
  have hta : taVal h.env = taVal r.env := by
    unfold taVal; rw [hW.layerH, hW.layerR, hW.idx]
  have hsl : slice M 0 1440 = slice MH 0x80 1440 := by
    apply slice_congr'
    intro i hi
    rcases (by omega : i < 32 ∨ (32 ≤ i ∧ i < 64) ∨ 64 ≤ i) with h1 | h1 | h1
    · rw [Nat.zero_add, mLow i h1, hLow _ (by omega), hW.seedR i h1, hW.tb i h1]
    · rw [Nat.zero_add, show i = 32 + (i - 32) by omega, mP _ (by omega),
        show 0x80 + (32 + (i - 32)) = 0xA0 + (i - 32) by omega, hP _ (by omega), hpk]
    · have ht : (i - 64) / 32 < 43 := by omega
      have hk : (i - 64) % 32 < 32 := Nat.mod_lt _ (by decide)
      have e1 : 0 + i = 0x40 + 32 * ((i - 64) / 32) + (i - 64) % 32 := by omega
      have e2 : 0x80 + i = 0xC0 + 32 * ((i - 64) / 32) + (i - 64) % 32 := by omega
      rw [e1, e2, mEnds _ ht _ hk, hW.ends _ ht _ hk, hHigh _ (by omega)]
  have hleaf : r.env "idxLeaf" < 512 := hW.leaf512
  have hb := bitOf_le (r.env "idxLeaf") 0
  have hslot : nodeAddr (h.env "idxLeaf") 0 = 64 + 32 * bitOf (r.env "idxLeaf") 0 := by
    unfold nodeAddr; rw [hW.leaf]
  have rN : r.env "N_MASK" = NMASK := hW.rN
  have hmp : (r.env "sigBase" + (r.env "countOff" + 4) % W) % W = 2336 + 836 * c + 692 := by
    rw [hW.sbR, hW.coR,
      Nat.mod_eq_of_lt (lt_W_of_lt' (show 2336 + 836 * c + 688 + 4 < 2 ^ 200 by omega)), Nat.zero_add,
      Nat.mod_eq_of_lt (lt_W_of_lt' (show 2336 + 836 * c + 688 + 4 < 2 ^ 200 by omega))]
  -- the HEAD node slot, outside its 16 written bytes, is the old memory
  have hNodeFr : ∀ a, (a < 64 + 32 * bitOf (r.env "idxLeaf") 0
      ∨ 64 + 32 * bitOf (r.env "idxLeaf") 0 + 16 ≤ a) →
      (execList c10Oracle sig headMid h).1.mem a = MH a := by
    intro a ha; rw [hMem, hslot, writeBytes_frame _ _ _ _ a ha]
  refine ⟨r0, h0, r.env "idxLeaf", taVal r.env, 2336 + 836 * c + 692, hleaf, by omega, ?_, ?_⟩
  · refine ⟨by rw [rMI, Nat.shiftRight_zero], rTA, by rw [rMP, hmp],
      by rw [rFr _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), rN], by rw [rFr _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), hW.rOUT],
      by rw [hSl, hW.leaf], by rw [hTb, hta], by rw [hFr _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), hW.leaf],
      by rw [hMP, hW.sbH, hW.coH, ← hW.sbR, hmp], ?_, ?_, ?_, ?_, fun _ _ _ => rfl, fun _ _ => rfl,
      fun _ _ => rfl⟩
    · intro k hk
      rw [hNodeFr k (Or.inl (by omega)), hLow k (by omega), rMem k hk]
      exact hW.seedMem k hk
    · intro k hk
      rw [mNode, rN, show nodeAddr (r.env "idxLeaf") 0 + k = 64 + 32 * bitOf (r.env "idxLeaf") 0 + k from rfl]
      by_cases h16 : k < 16
      · rw [hMem, hslot, writeBytes_get MH (64 + 32 * bitOf (r.env "idxLeaf") 0) 16 _
            (64 + 32 * bitOf (r.env "idxLeaf") 0 + k) ⟨by omega, by omega⟩,
          beByte_and_nmask, if_pos h16, beByte_wordOf_getD _ _ hk, hsl,
          show 64 + 32 * bitOf (r.env "idxLeaf") 0 + k - (64 + 32 * bitOf (r.env "idxLeaf") 0) = k by omega]
      · rw [hNodeFr (64 + 32 * bitOf (r.env "idxLeaf") 0 + k) (Or.inr (by omega)),
          beByte_masked_low _ _ (by omega), hLow (64 + 32 * bitOf (r.env "idxLeaf") 0 + k) (by omega)]
        rcases (by omega : bitOf (r.env "idxLeaf") 0 = 0 ∨ bitOf (r.env "idxLeaf") 0 = 1) with e | e
        · rw [e, show 64 + 32 * 0 + k = 64 + k by omega]; exact hW.pad50 k (by omega) hk
        · rw [e, show 64 + 32 * 1 + k = 96 + k by omega]; exact hW.pad60 k hk
    · intro k h1 h2
      rw [mNode, rN]; exact beByte_masked_low _ _ h1
    · intro k h1 h2
      refine ⟨?_, ?_⟩
      · rw [hNodeFr (64 + k) (by omega), hLow (64 + k) (by omega)]; exact hW.pad50 k h1 h2
      · rw [hNodeFr (96 + k) (by omega), hLow (96 + k) (by omega)]; exact hW.pad60 k h2
  · refine ⟨by rw [hFr _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), rFr _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)]; exact hW.idx,
      by rw [rFr _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)]; exact hW.idx64,
      by rw [rAO, hW.coR, Nat.mod_eq_of_lt (lt_W_of_lt' (show 2336 + 836 * c + 688 + 4 < 2 ^ 200 by omega))],
      by rw [hAO, rAO, hW.coH],
      by rw [rFr _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)]; exact hW.sbR, by rw [hFr _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)]; exact hW.sbH,
      by rw [hFr _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), rFr _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)]; exact hW.seed,
      by rw [hFr _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), rFr _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)]; exact hW.root, ?_, ?_,
      by rw [rFr _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)]; exact rN, by rw [rFr _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)]; exact hW.rOUT,
      by rw [hFr _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)]; exact hW.hN, by rw [hFr _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)]; exact hW.hTB,
      by rw [hFr _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)]; exact hW.hOUT⟩
    · intro k hk
      rw [hNodeFr (0x80 + k) (Or.inr (by omega)), hLow (0x80 + k) (by omega), rFr _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)]
      exact hW.tb k hk
    · rw [mNode, rN]
      exact Nat.lt_of_le_of_lt Nat.and_le_left (wordOf_lt _)

/-- **The end theorem with O3, O4, O5 discharged.** H_msg (O1) and FORS (O2) are arguments here
    only because their proofs live in files that import this one (`RelHmsg`, `RelFors`);
    `RelFors.head_verdict_eq_full` is the unconditional form. -/
theorem head_verdict_eq_of' (hm : HmsgObl) (hf : ForsObl)
    (pkSeed pkRoot message : ByteVec 32) (sig : ByteVec Spec.SignatureLen) :
    execC10HeadAsm pkSeed pkRoot message sig = execC10Asm pkSeed pkRoot message sig :=
  head_verdict_eq_of hm hf mid_obl pkSeed pkRoot message sig

end SphincsCVerify.Interpreter.C10.RelMid

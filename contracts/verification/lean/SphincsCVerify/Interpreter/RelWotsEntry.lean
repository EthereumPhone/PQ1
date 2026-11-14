/-
SphincsCVerify.Interpreter.RelWotsEntry — RESEARCH (#1155 gas track, batch 9): the layer-setup
glue in front of the WOTS chain phase. Both layer bodies start with the same five setup
statements, then the digit hash, the digit sum and the gate, then `wotsPtr`. From a coupled
layer entry, `wots_entry_rel` shows that the two prefixes halt alike and, when they fall
through, establish every entry hypothesis of `wots_layer_rel` (RelWots.lean).
`wots_phase_rel` chains the two: from the layer entry through the 43 chains.

The digit sum is E1 (`e1_digitSum_rel`), which is stated for `c10Oracle` and the real signature
length, so this file is too. Mathlib-free; no `sorry`/`admit`/`native_decide`/`bv_decide` and
no new axioms.
-/

import SphincsCVerify.Interpreter.RelWots

namespace SphincsCVerify.Interpreter.C10.RelWotsEntry

open SphincsCVerify.Interpreter
open SphincsCVerify.Interpreter.C10
open SphincsCVerify.Interpreter.C10.RelE1
open SphincsCVerify.Interpreter.C10.RelChain
open SphincsCVerify.Interpreter.C10.RelWots
open SphincsCVerify.Spec (ByteVec)

/-! ## 1. The two prefixes, pinned -/

/-- The five setup statements both layer bodies open with (statements 0..4). -/
def setup5 : List Stmt :=
  [ .letv "idxLeaf" (.bin .band (.var "idxTree") (.lit 0x1FF))
  , .setv "idxTree" (.bin .shr (.lit 9) (.var "idxTree"))
  , .letv "wotsAdrs"
      (.bin .bor (.bin .shl (.lit 224) (.var "layer"))
        (.bin .bor (.bin .shl (.lit 160) (.var "idxTree")) (.bin .shl (.lit 96) (.var "idxLeaf"))))
  , .letv "countOff" (.bin .add (.var "sigOff") (.lit 688))
  , .letv "count" (.bin .shr (.lit 224) (.calldataload (.bin .add (.var "sigBase") (.var "countOff")))) ]

/-- The optimized v1's digit hash (statements 5..10). The node word is already at `0x40`, so
    there is no store there; `0x60..0x80` is zeroed again after the hash. -/
def headDigitHash : List Stmt :=
  [ .mstore (.lit 0) (.var "seed"), .mstore (.lit 32) (.var "wotsAdrs"), .mstore (.lit 96) (.var "count")
  , .sha256 (.lit 0) (.lit 128) (.var "OUT"), .letv "d" (.mload (.var "OUT"))
  , .mstore (.lit 96) (.lit 0) ]

/-- The digit-sum gate (statement 13). -/
def gate : Stmt := .ifnz (.iszero (.bin .eq (.var "digitSum") (.lit 205))) [ .revert ]

/-- `let wotsPtr := add(sigBase, sigOff)` (statement 14). -/
def wotsPtrStmt : Stmt := .letv "wotsPtr" (.bin .add (.var "sigBase") (.var "sigOff"))

/-- The reference's statements 0..14. -/
def refPre : List Stmt := setup5 ++ wotsDigitHashFragment ++ refDigitSumFrag ++ [gate, wotsPtrStmt]

/-- The optimized v1's statements 0..14. -/
def headPre : List Stmt := setup5 ++ headDigitHash ++ headDigitSumFrag ++ [gate, wotsPtrStmt]

set_option maxRecDepth 100000 in
set_option maxHeartbeats 4000000 in
theorem ref_pre_pin : (loopBody c10Program[28]?).take 15 = refPre := rfl

set_option maxRecDepth 100000 in
set_option maxHeartbeats 4000000 in
theorem head_pre_pin : (loopBody c10HeadProgram[28]?).take 15 = headPre := rfl

/-! ## 2. The shared setup -/

/-- Running `setup5`: it falls through, leaves memory alone, binds the five variables, and
    keeps every other variable. -/
theorem setup5_eval {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (vm : VM) :
    (execList sha sig setup5 vm).2 = none
    ∧ (execList sha sig setup5 vm).1.mem = vm.mem
    ∧ (execList sha sig setup5 vm).1.env "idxTree" = vm.env "idxTree" >>> 9
    ∧ (execList sha sig setup5 vm).1.env "idxLeaf" = vm.env "idxTree" &&& 0x1FF
    ∧ (execList sha sig setup5 vm).1.env "countOff" = (vm.env "sigOff" + 688) % W
    ∧ (execList sha sig setup5 vm).1.env "wotsAdrs"
        = ((vm.env "layer" <<< 224) % W ||| (((vm.env "idxTree" >>> 9) <<< 160) % W
            ||| ((vm.env "idxTree" &&& 0x1FF) <<< 96) % W))
    ∧ (execList sha sig setup5 vm).1.env "count"
        = calldataload sig ((vm.env "sigBase" + (vm.env "sigOff" + 688) % W) % W) >>> 224
    ∧ (∀ x, x ≠ "idxLeaf" → x ≠ "idxTree" → x ≠ "wotsAdrs" → x ≠ "countOff" → x ≠ "count" →
        (execList sha sig setup5 vm).1.env x = vm.env x) := by
  unfold setup5
  rw [execList_cons_none sha sig _ _ _ (by simp only [execStmt]),
    execList_cons_none sha sig _ _ _ (by simp only [execStmt]),
    execList_cons_none sha sig _ _ _ (by simp only [execStmt]),
    execList_cons_none sha sig _ _ _ (by simp only [execStmt]), execList_single]
  refine ⟨by simp only [execStmt], by simp only [execStmt], ?_, ?_, ?_, ?_, ?_, ?_⟩
  · simp only [execStmt, eval]
    simp (disch := decide) only [setVar_get_eq, setVar_get_ne]
  · simp only [execStmt, eval]
    simp (disch := decide) only [setVar_get_eq, setVar_get_ne]
  · simp only [execStmt, eval]
    simp (disch := decide) only [setVar_get_eq, setVar_get_ne]
  · simp only [execStmt, eval]
    simp (disch := decide) only [setVar_get_eq, setVar_get_ne]
  · simp only [execStmt, eval]
    simp (disch := decide) only [setVar_get_eq, setVar_get_ne]
  · intro x h1 h2 h3 h4 h5
    simp only [execStmt]
    rw [setVar_get_ne _ _ _ _ h5, setVar_get_ne _ _ _ _ h4, setVar_get_ne _ _ _ _ h3,
      setVar_get_ne _ _ _ _ h2, setVar_get_ne _ _ _ _ h1]

/-! ## 3. The digit hash -/

/-- After the precompile writes `dig` at `off`, `mload32` there is `wordOf dig` (the same
    statement as a private lemma in `Phases.lean`). -/
theorem mload32_digest (mem : ByteMemory) (off : Nat) (dig : ByteVec 32) :
    mload32 (writeRegion mem off (fun i => dig.data.getD i 0)) off = wordOf dig := by
  rw [mload32_writeRegion mem off (fun i => dig.data.getD i 0), ← wordOfBV_eq_wordOf]
  rfl

/-- Both digit hashes read the same 128 bytes: seed, ADRS, node, count. The optimized v1 has
    the node at `0x40` already, which `hnode` states. -/
theorem digit_slice_eq (mR mH : ByteMemory) (seed wa cn cnt : Nat)
    (hnode : ∀ k, k < 32 → mH (64 + k) = beByte cn k) :
    slice (mstore32 (mstore32 (mstore32 (mstore32 mR 0 seed) 32 wa) 64 cn) 96 cnt) 0 128
      = slice (mstore32 (mstore32 (mstore32 mH 0 seed) 32 wa) 96 cnt) 0 128 := by
  apply slice_congr
  intro i hi
  rw [Nat.zero_add]
  rcases (by omega : i < 32 ∨ (32 ≤ i ∧ i < 64) ∨ (64 ≤ i ∧ i < 96) ∨ (96 ≤ i ∧ i < 128))
    with h | h | h | h
  · rw [mstore32_frame _ 96 cnt i (by omega), mstore32_frame _ 64 cn i (by omega),
      mstore32_frame _ 32 wa i (by omega), mstore32_frame _ 96 cnt i (by omega),
      mstore32_frame _ 32 wa i (by omega)]
    have e : i = 0 + i := by omega
    rw [e, mstore32_get _ _ _ _ h, mstore32_get _ _ _ _ h]
  · rw [mstore32_frame _ 96 cnt i (by omega), mstore32_frame _ 64 cn i (by omega),
      mstore32_frame _ 96 cnt i (by omega)]
    have e : i = 32 + (i - 32) := by omega
    rw [e, mstore32_get _ _ _ _ (by omega), mstore32_get _ _ _ _ (by omega)]
  · rw [mstore32_frame _ 96 cnt i (by omega), mstore32_frame _ 96 cnt i (by omega),
      mstore32_frame _ 32 wa i (by omega), mstore32_frame _ 0 seed i (by omega)]
    have e : i = 64 + (i - 64) := by omega
    rw [e, mstore32_get _ _ _ _ (by omega), hnode _ (by omega)]
  · have e : i = 96 + (i - 96) := by omega
    rw [e, mstore32_get _ _ _ _ (by omega), mstore32_get _ _ _ _ (by omega)]

/-- **The two digit hashes.** From states that agree on `seed`, `wotsAdrs` and `count`, with the
    reference's `OUT = 0x600`, the optimized `OUT = 0x620`, and the optimized node bytes at
    `0x40` equal to the reference's `currentNode`: both fall through, bind the same `d` (the
    word of the one digest), write the same seed bytes, and keep every other variable. Memory
    outside the writes is kept: the reference writes `[0, 0x80)` and `[0x600, 0x620)`; the
    optimized v1 writes `[0, 0x40)`, `[0x60, 0x80)` (left zero) and `[0x620, 0x640)`. -/
theorem digit_hash_rel {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (vR vH : VM)
    (hseed : vR.env "seed" = vH.env "seed") (hwa : vR.env "wotsAdrs" = vH.env "wotsAdrs")
    (hcnt : vR.env "count" = vH.env "count")
    (hROUT : vR.env "OUT" = 0x600) (hHOUT : vH.env "OUT" = 0x620)
    (hnode : ∀ k, k < 32 → vH.mem (64 + k) = beByte (vR.env "currentNode") k) :
    (execList sha sig wotsDigitHashFragment vR).2 = none
    ∧ (execList sha sig headDigitHash vH).2 = none
    ∧ (execList sha sig wotsDigitHashFragment vR).1.env "d"
        = wordOf (sha (slice (mstore32 (mstore32 (mstore32 (mstore32 vR.mem 0 (vR.env "seed")) 32
            (vR.env "wotsAdrs")) 64 (vR.env "currentNode")) 96 (vR.env "count")) 0 128))
    ∧ (execList sha sig headDigitHash vH).1.env "d"
        = (execList sha sig wotsDigitHashFragment vR).1.env "d"
    ∧ (∀ k, k < 32 → (execList sha sig headDigitHash vH).1.mem k
        = (execList sha sig wotsDigitHashFragment vR).1.mem k)
    ∧ (∀ k, k < 32 → (execList sha sig wotsDigitHashFragment vR).1.mem k = beByte (vR.env "seed") k)
    ∧ (∀ k, 16 ≤ k → k < 32 → (execList sha sig headDigitHash vH).1.mem (64 + k) = vH.mem (64 + k))
    ∧ (∀ k, k < 32 → (execList sha sig headDigitHash vH).1.mem (96 + k) = 0)
    ∧ (∀ a, 0x80 ≤ a → (a < 0x600 ∨ 0x620 ≤ a) →
        (execList sha sig wotsDigitHashFragment vR).1.mem a = vR.mem a)
    ∧ (∀ a, 0x40 ≤ a → (a < 0x60 ∨ 0x80 ≤ a) → (a < 0x620 ∨ 0x640 ≤ a) →
        (execList sha sig headDigitHash vH).1.mem a = vH.mem a)
    ∧ (∀ x, x ≠ "d" → (execList sha sig wotsDigitHashFragment vR).1.env x = vR.env x)
    ∧ (∀ x, x ≠ "d" → (execList sha sig headDigitHash vH).1.env x = vH.env x) := by
  unfold wotsDigitHashFragment headDigitHash
  repeat rw [execList_cons_none sha sig _ _ _ (by simp only [execStmt])]
  simp only [execList, execStmt, eval, hROUT, hHOUT]
  refine ⟨trivial, trivial, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · rw [setVar_get_eq, mload32_digest]
  · rw [setVar_get_eq, setVar_get_eq, mload32_digest, mload32_digest, hseed, hwa, hcnt,
      digit_slice_eq _ _ _ _ _ _ hnode]
  · intro k hk
    rw [mstore32_frame _ 96 0 k (by omega), writeRegion_frame _ 0x620 _ k (by omega),
      mstore32_frame _ 96 _ k (by omega), mstore32_frame _ 32 _ k (by omega),
      writeRegion_frame _ 0x600 _ k (by omega), mstore32_frame _ 96 _ k (by omega),
      mstore32_frame _ 64 _ k (by omega), mstore32_frame _ 32 _ k (by omega), hseed]
    have e : k = 0 + k := by omega
    rw [e, mstore32_get _ _ _ _ hk, mstore32_get _ _ _ _ hk]
  · intro k hk
    rw [writeRegion_frame _ 0x600 _ k (by omega), mstore32_frame _ 96 _ k (by omega),
      mstore32_frame _ 64 _ k (by omega), mstore32_frame _ 32 _ k (by omega)]
    have h0 := mstore32_get vR.mem 0 (vR.env "seed") k hk
    rw [Nat.zero_add] at h0
    exact h0
  · intro k h1 h2
    rw [mstore32_frame _ 96 0 _ (by omega), writeRegion_frame _ 0x620 _ _ (by omega),
      mstore32_frame _ 96 _ _ (by omega), mstore32_frame _ 32 _ _ (by omega),
      mstore32_frame _ 0 _ _ (by omega)]
  · intro k hk
    rw [mstore32_get _ _ _ _ hk, beByte_small 0 k (by decide) hk]
    split <;> rfl
  · intro a h1 h2
    rw [writeRegion_frame _ 0x600 _ a (by omega), mstore32_frame _ 96 _ a (by omega),
      mstore32_frame _ 64 _ a (by omega), mstore32_frame _ 32 _ a (by omega),
      mstore32_frame _ 0 _ a (by omega)]
  · intro a h1 h2 h3
    rw [mstore32_frame _ 96 0 a (by omega), writeRegion_frame _ 0x620 _ a (by omega),
      mstore32_frame _ 96 _ a (by omega), mstore32_frame _ 32 _ a (by omega),
      mstore32_frame _ 0 _ a (by omega)]
  · intro x hx; rw [setVar_get_ne _ _ _ _ hx]
  · intro x hx; rw [setVar_get_ne _ _ _ _ hx]

/-! ## 4. The gate and `wotsPtr`, then the whole prefix -/

theorem app_none {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (xs ys : List Stmt)
    (vm : VM) (h : (execList sha sig xs vm).2 = none) :
    execList sha sig (xs ++ ys) vm = execList sha sig ys (execList sha sig xs vm).1 := by
  rw [execList_append]
  rcases hp : execList sha sig xs vm with ⟨v', o⟩
  rw [hp] at h
  cases o with
  | none => rfl
  | some _ => exact absurd h (by simp)

/-- The gate passes exactly when `digitSum = 205`; then `wotsPtr` is bound. -/
theorem tail_eval {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (vm : VM) :
    execList sha sig [gate, wotsPtrStmt] vm
      = if vm.env "digitSum" = 205 then
          ({ vm with env := setVar vm.env "wotsPtr" ((vm.env "sigBase" + vm.env "sigOff") % W) }, none)
        else (vm, some Halt.reverted) := by
  unfold gate wotsPtrStmt
  by_cases h : vm.env "digitSum" = 205
  · rw [if_pos h, execList_cons_none sha sig _ _ _ (by simp [execStmt, eval, h]), execList_single]
    simp [execStmt, eval, h]
  · rw [if_neg h]
    have hc : (execStmt sha sig (.ifnz (.iszero (.bin .eq (.var "digitSum") (.lit 205))) [ .revert ]) vm)
        = (vm, some Halt.reverted) := by
      simp [execStmt, eval, h, execList_single]
    rw [execList, hc]

set_option maxHeartbeats 4000000 in
/-- **The layer-setup glue in front of the WOTS chains.** From a coupled layer entry (the same
    `layer`, `idxTree`, `sigBase`, `sigOff` and `seed`; the optimized node bytes at `0x40` equal
    to the reference's `currentNode`; each side's constants), the two prefixes (statements
    0..14) halt alike. When they fall through, every entry hypothesis of `wots_layer_rel` holds
    for the states they leave. The digit sums agree by E1. -/
theorem wots_entry_rel (sig : ByteVec Spec.SignatureLen) (vR vH : VM)
    (hlay : vR.env "layer" = vH.env "layer") (hl : vR.env "layer" < 2 ^ 32)
    (hidx : vR.env "idxTree" = vH.env "idxTree") (hidx64 : vR.env "idxTree" < 2 ^ 64)
    (hsb : vR.env "sigBase" = vH.env "sigBase") (hso : vR.env "sigOff" = vH.env "sigOff")
    (hwp : vR.env "sigBase" + vR.env "sigOff" < 4096)
    (hseed : vR.env "seed" = vH.env "seed")
    (hnode : ∀ k, k < 32 → vH.mem (64 + k) = beByte (vR.env "currentNode") k)
    (hRN : vR.env "N_MASK" = NMASK) (hROUT : vR.env "OUT" = 0x600)
    (hHN : vH.env "N_MASK" = NMASK) (hHTB : vH.env "TB" = 0x80) (hHOUT : vH.env "OUT" = 0x620) :
    (execList c10Oracle sig refPre vR).2 = (execList c10Oracle sig headPre vH).2
    ∧ ((execList c10Oracle sig refPre vR).2 = none →
        (execList c10Oracle sig refPre vR).1.env "wotsPtr" < 4096
        ∧ (∀ j, 23 ≤ j → j ≤ 26 → beByte ((execList c10Oracle sig refPre vR).1.env "wotsAdrs") j = 0)
        ∧ (execList c10Oracle sig headPre vH).1.env "d" = (execList c10Oracle sig refPre vR).1.env "d"
        ∧ (execList c10Oracle sig headPre vH).1.env "wotsPtr"
            = (execList c10Oracle sig refPre vR).1.env "wotsPtr"
        ∧ (execList c10Oracle sig headPre vH).1.env "wotsAdrs"
            = (execList c10Oracle sig refPre vR).1.env "wotsAdrs"
        ∧ (execList c10Oracle sig refPre vR).1.env "N_MASK" = NMASK
        ∧ (execList c10Oracle sig refPre vR).1.env "OUT" = 0x600
        ∧ (execList c10Oracle sig headPre vH).1.env "N_MASK" = NMASK
        ∧ (execList c10Oracle sig headPre vH).1.env "TB" = 0x80
        ∧ (∀ k, k < 32 → (execList c10Oracle sig headPre vH).1.mem k
            = (execList c10Oracle sig refPre vR).1.mem k)
        ∧ (∀ k, k < 32 → (execList c10Oracle sig refPre vR).1.mem k = beByte (vR.env "seed") k)
        ∧ (∀ k, k < 32 → (execList c10Oracle sig headPre vH).1.mem (96 + k) = 0)
        ∧ (∀ k, k < 32 → (execList c10Oracle sig headPre vH).1.mem (0x80 + k) = vH.mem (0x80 + k))
        ∧ (execList c10Oracle sig headPre vH).1.env "layer" = (execList c10Oracle sig refPre vR).1.env "layer"
        ∧ (execList c10Oracle sig headPre vH).1.env "idxTree"
            = (execList c10Oracle sig refPre vR).1.env "idxTree"
        ∧ (execList c10Oracle sig headPre vH).1.env "idxLeaf"
            = (execList c10Oracle sig refPre vR).1.env "idxLeaf"
        ∧ (execList c10Oracle sig headPre vH).1.env "countOff"
            = (execList c10Oracle sig refPre vR).1.env "countOff"
        ∧ (execList c10Oracle sig headPre vH).1.env "sigBase"
            = (execList c10Oracle sig refPre vR).1.env "sigBase"
        ∧ (execList c10Oracle sig headPre vH).1.env "seed" = (execList c10Oracle sig refPre vR).1.env "seed"
        ∧ (execList c10Oracle sig refPre vR).1.env "seed" = vR.env "seed") := by
  -- the shared setup
  obtain ⟨sR0, sRmem, sRidx, sRleaf, sRco, sRwa, sRcnt, sRfr⟩ := setup5_eval c10Oracle sig vR
  obtain ⟨sH0, sHmem, sHidx, sHleaf, sHco, sHwa, sHcnt, sHfr⟩ := setup5_eval c10Oracle sig vH
  -- the digit hashes
  have hd := digit_hash_rel c10Oracle sig (execList c10Oracle sig setup5 vR).1
    (execList c10Oracle sig setup5 vH).1
    (by rw [sRfr _ (by decide) (by decide) (by decide) (by decide) (by decide),
          sHfr _ (by decide) (by decide) (by decide) (by decide) (by decide), hseed])
    (by rw [sRwa, sHwa, hlay, hidx])
    (by rw [sRcnt, sHcnt, hsb, hso])
    (by rw [sRfr _ (by decide) (by decide) (by decide) (by decide) (by decide), hROUT])
    (by rw [sHfr _ (by decide) (by decide) (by decide) (by decide) (by decide), hHOUT])
    (by intro k hk
        rw [sHmem, sRfr _ (by decide) (by decide) (by decide) (by decide) (by decide)]
        exact hnode k hk)
  obtain ⟨dR0, dH0, dRd, dHd, dseed, dRseed, _, dzero, _, dHfr, dRenv, dHenv⟩ := hd
  -- the digit sums (E1)
  obtain ⟨eR0, eH0, eds, eRmem, eHmem, eRenv, eHenv⟩ :=
    e1_digitSum_rel sig (execList c10Oracle sig wotsDigitHashFragment (execList c10Oracle sig setup5 vR).1).1
      (execList c10Oracle sig headDigitHash (execList c10Oracle sig setup5 vH).1).1 _ dRd (dHd.trans dRd)
  -- unfold both prefixes down to the gate
  have eqR : execList c10Oracle sig refPre vR
      = execList c10Oracle sig [gate, wotsPtrStmt]
          (execList c10Oracle sig refDigitSumFrag (execList c10Oracle sig wotsDigitHashFragment
            (execList c10Oracle sig setup5 vR).1).1).1 := by
    rw [show refPre = setup5 ++ (wotsDigitHashFragment ++ (refDigitSumFrag ++ [gate, wotsPtrStmt]))
      from rfl, app_none _ _ _ _ _ sR0, app_none _ _ _ _ _ dR0, app_none _ _ _ _ _ eR0]
  have eqH : execList c10Oracle sig headPre vH
      = execList c10Oracle sig [gate, wotsPtrStmt]
          (execList c10Oracle sig headDigitSumFrag (execList c10Oracle sig headDigitHash
            (execList c10Oracle sig setup5 vH).1).1).1 := by
    rw [show headPre = setup5 ++ (headDigitHash ++ (headDigitSumFrag ++ [gate, wotsPtrStmt]))
      from rfl, app_none _ _ _ _ _ sH0, app_none _ _ _ _ _ dH0, app_none _ _ _ _ _ eH0]
  rw [eqR, eqH, tail_eval, tail_eval]
  generalize hR3 : (execList c10Oracle sig refDigitSumFrag (execList c10Oracle sig wotsDigitHashFragment
      (execList c10Oracle sig setup5 vR).1).1).1 = R3 at *
  generalize hH3 : (execList c10Oracle sig headDigitSumFrag (execList c10Oracle sig headDigitHash
      (execList c10Oracle sig setup5 vH).1).1).1 = H3 at *
  -- variables carried from the entry to the gate
  have fR : ∀ x, x ≠ "digitSum" → x ≠ "ii" → x ≠ "d" → x ≠ "idxLeaf" → x ≠ "idxTree" →
      x ≠ "wotsAdrs" → x ≠ "countOff" → x ≠ "count" → R3.env x = vR.env x := by
    intro x a1 a2 a3 a4 a5 a6 a7 a8
    rw [eRenv x a1 a2, dRenv x a3, sRfr x a4 a5 a6 a7 a8]
  have fH : ∀ x, x ≠ "digitSum" → x ≠ "lanes" → x ≠ "d" → x ≠ "idxLeaf" → x ≠ "idxTree" →
      x ≠ "wotsAdrs" → x ≠ "countOff" → x ≠ "count" → H3.env x = vH.env x := by
    intro x a1 a2 a3 a4 a5 a6 a7 a8
    rw [eHenv x a1 a2, dHenv x a3, sHfr x a4 a5 a6 a7 a8]
  have waR : R3.env "wotsAdrs" = ((vR.env "layer" <<< 224) % W ||| (((vR.env "idxTree" >>> 9) <<< 160) % W
      ||| ((vR.env "idxTree" &&& 0x1FF) <<< 96) % W)) := by
    rw [eRenv _ (by decide) (by decide), dRenv _ (by decide), sRwa]
  have waH : H3.env "wotsAdrs" = R3.env "wotsAdrs" := by
    rw [eHenv _ (by decide) (by decide), dHenv _ (by decide), sHwa, waR, hlay, hidx]
  have dH : H3.env "d" = R3.env "d" := by
    rw [eHenv _ (by decide) (by decide), eRenv _ (by decide) (by decide), dHd]
  by_cases hds : R3.env "digitSum" = 205
  · have hds' : H3.env "digitSum" = 205 := eds ▸ hds
    rw [if_pos hds, if_pos hds']
    refine ⟨rfl, fun _ => ?_⟩
    simp only
    simp (disch := decide) only [setVar_get_eq, setVar_get_ne]
    have eRSB : R3.env "sigBase" = vR.env "sigBase" := fR _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
    have eRSO : R3.env "sigOff" = vR.env "sigOff" := fR _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
    have eHSB : H3.env "sigBase" = vH.env "sigBase" := fH _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
    have eHSO : H3.env "sigOff" = vH.env "sigOff" := fH _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
    have eRN : R3.env "N_MASK" = vR.env "N_MASK" := fR _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
    have eROUT : R3.env "OUT" = vR.env "OUT" := fR _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
    have eHN : H3.env "N_MASK" = vH.env "N_MASK" := fH _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
    have eHTB : H3.env "TB" = vH.env "TB" := fH _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
    rw [eRSB, eRSO, eHSB, eHSO, eRN, eROUT, eHN, eHTB, waH, dH, ← hsb, ← hso,
      Nat.mod_eq_of_lt (lt_W_of_lt' (Nat.lt_trans hwp (by decide)))]
    have eRL : R3.env "layer" = vR.env "layer" := fR _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
    have eHL : H3.env "layer" = vH.env "layer" := fH _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
    have eRS : R3.env "seed" = vR.env "seed" := fR _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
    have eHS : H3.env "seed" = vH.env "seed" := fH _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
    have eRI : R3.env "idxTree" = vR.env "idxTree" >>> 9 := by
      rw [eRenv _ (by decide) (by decide), dRenv _ (by decide), sRidx]
    have eHI : H3.env "idxTree" = vH.env "idxTree" >>> 9 := by
      rw [eHenv _ (by decide) (by decide), dHenv _ (by decide), sHidx]
    have eRLf : R3.env "idxLeaf" = vR.env "idxTree" &&& 0x1FF := by
      rw [eRenv _ (by decide) (by decide), dRenv _ (by decide), sRleaf]
    have eHLf : H3.env "idxLeaf" = vH.env "idxTree" &&& 0x1FF := by
      rw [eHenv _ (by decide) (by decide), dHenv _ (by decide), sHleaf]
    have eRC : R3.env "countOff" = (vR.env "sigOff" + 688) % W := by
      rw [eRenv _ (by decide) (by decide), dRenv _ (by decide), sRco]
    have eHC : H3.env "countOff" = (vH.env "sigOff" + 688) % W := by
      rw [eHenv _ (by decide) (by decide), dHenv _ (by decide), sHco]
    rw [eRL, eHL, eRS, eHS, eRI, eHI, eRLf, eHLf, eRC, eHC]
    refine ⟨hwp, ?_, rfl, rfl, rfl, hRN, hROUT, hHN, hHTB, ?_, ?_, ?_, ?_, hlay.symm,
      by rw [hidx], by rw [hidx], by rw [hso], rfl, hseed.symm, rfl⟩
    · rw [waR]
      exact wotsAdrs_zero_field _ _ _ hl
        (Nat.lt_of_le_of_lt (Nat.shiftRight_le _ _) hidx64)
        (Nat.lt_of_le_of_lt (Nat.and_le_right) (by decide))
    · intro k hk
      subst hR3 hH3
      rw [eHmem, eRmem]
      exact dseed k hk
    · intro k hk
      subst hR3
      rw [eRmem, dRseed k hk, sRfr _ (by decide) (by decide) (by decide) (by decide) (by decide)]
    · intro k hk
      subst hH3
      rw [eHmem, dzero k hk]
    · intro k hk
      subst hH3
      rw [eHmem, dHfr _ (by omega) (by omega) (by omega), sHmem]
  · have hds' : ¬ H3.env "digitSum" = 205 := eds ▸ hds
    rw [if_neg hds, if_neg hds']
    exact ⟨rfl, fun h => absurd h (by simp)⟩

/-! ## 5. From the layer entry through the 43 chains -/

theorem app_some {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (xs ys : List Stmt)
    (vm : VM) (hh : Halt) (h : (execList sha sig xs vm).2 = some hh) :
    (execList sha sig (xs ++ ys) vm).2 = some hh := by
  rw [execList_append]
  rcases hp : execList sha sig xs vm with ⟨v', o⟩
  rw [hp] at h
  cases o with
  | none => exact absurd h (by simp)
  | some _ => simp only at h ⊢; exact h

/-- The reference's statements 0..15: the prefix, then the chain loop. -/
def refWotsPhase : List Stmt := refPre ++ [.forRange "i" (.lit 43) wotsChainBody]

/-- The optimized v1's statements 0..187: the prefix, then `mstore(0x20, wotsAdrs)` and the 43
    chain blocks. -/
def headWotsPhase : List Stmt :=
  headPre ++ (.mstore (.lit 32) (.var "wotsAdrs") :: (List.range 43).flatMap chainBlock)

set_option maxRecDepth 100000 in
set_option maxHeartbeats 4000000 in
theorem ref_wotsPhase_pin : (loopBody c10Program[28]?).take 16 = refWotsPhase := rfl

set_option maxRecDepth 100000 in
set_option maxHeartbeats 4000000 in
theorem head_wotsPhase_pin : (loopBody c10HeadProgram[28]?).take 188 = headWotsPhase := rfl

set_option maxHeartbeats 4000000 in
/-- **The WOTS phase of a layer, from the layer entry.** Under the layer-entry coupling of
    `wots_entry_rel`, plus the optimized seed copy at `TB = 0x80` equal to the seed, the two
    phases halt alike. When they fall through:
    - the 43 chain endpoints are equal (reference `0x80 + 32i`, optimized `0xC0 + 32i`);
    - the seed bytes `[0, 32)` are coupled and are the seed's bytes;
    - the optimized padding `[0x50, 0x60)` and `[0x60, 0x80)` is zero, and its seed copy
      `[0x80, 0xA0)` is still the seed;
    - `layer`, `idxTree`, `idxLeaf`, `countOff`, `sigBase` and `seed` are equal across the two
      programs, and these constants hold: the reference's `N_MASK` and `OUT = 0x600`, the
      optimized `N_MASK` and `TB = 0x80` (the optimized `OUT` is assumed, not exported).
    These are the inputs the pk compression and the Merkle setup that follow read. -/
theorem wots_phase_rel (sig : ByteVec Spec.SignatureLen) (vR vH : VM)
    (hlay : vR.env "layer" = vH.env "layer") (hl : vR.env "layer" < 2 ^ 32)
    (hidx : vR.env "idxTree" = vH.env "idxTree") (hidx64 : vR.env "idxTree" < 2 ^ 64)
    (hsb : vR.env "sigBase" = vH.env "sigBase") (hso : vR.env "sigOff" = vH.env "sigOff")
    (hwp : vR.env "sigBase" + vR.env "sigOff" < 4096)
    (hseed : vR.env "seed" = vH.env "seed")
    (hnode : ∀ k, k < 32 → vH.mem (64 + k) = beByte (vR.env "currentNode") k)
    (htb : ∀ k, k < 32 → vH.mem (0x80 + k) = beByte (vR.env "seed") k)
    (hRN : vR.env "N_MASK" = NMASK) (hROUT : vR.env "OUT" = 0x600)
    (hHN : vH.env "N_MASK" = NMASK) (hHTB : vH.env "TB" = 0x80) (hHOUT : vH.env "OUT" = 0x620) :
    (execList c10Oracle sig refWotsPhase vR).2 = (execList c10Oracle sig headWotsPhase vH).2
    ∧ ((execList c10Oracle sig refWotsPhase vR).2 = none →
        (∀ i, i < 43 → ∀ k, k < 32 → (execList c10Oracle sig refWotsPhase vR).1.mem (0x80 + 32 * i + k) = (execList c10Oracle sig headWotsPhase vH).1.mem (0xC0 + 32 * i + k))
        ∧ (∀ k, k < 32 → (execList c10Oracle sig headWotsPhase vH).1.mem k = (execList c10Oracle sig refWotsPhase vR).1.mem k)
        ∧ (∀ k, k < 32 → (execList c10Oracle sig refWotsPhase vR).1.mem k = beByte (vR.env "seed") k)
        ∧ (∀ k, 16 ≤ k → k < 32 → (execList c10Oracle sig headWotsPhase vH).1.mem (64 + k) = 0)
        ∧ (∀ k, k < 32 → (execList c10Oracle sig headWotsPhase vH).1.mem (96 + k) = 0)
        ∧ (∀ k, k < 32 → (execList c10Oracle sig headWotsPhase vH).1.mem (0x80 + k) = beByte (vR.env "seed") k)
        ∧ (execList c10Oracle sig headWotsPhase vH).1.env "layer" = (execList c10Oracle sig refWotsPhase vR).1.env "layer"
        ∧ (execList c10Oracle sig headWotsPhase vH).1.env "idxTree" = (execList c10Oracle sig refWotsPhase vR).1.env "idxTree"
        ∧ (execList c10Oracle sig headWotsPhase vH).1.env "idxLeaf" = (execList c10Oracle sig refWotsPhase vR).1.env "idxLeaf"
        ∧ (execList c10Oracle sig headWotsPhase vH).1.env "countOff" = (execList c10Oracle sig refWotsPhase vR).1.env "countOff"
        ∧ (execList c10Oracle sig headWotsPhase vH).1.env "sigBase" = (execList c10Oracle sig refWotsPhase vR).1.env "sigBase"
        ∧ (execList c10Oracle sig headWotsPhase vH).1.env "seed" = (execList c10Oracle sig refWotsPhase vR).1.env "seed"
        ∧ (execList c10Oracle sig refWotsPhase vR).1.env "N_MASK" = NMASK ∧ (execList c10Oracle sig refWotsPhase vR).1.env "OUT" = 0x600
        ∧ (execList c10Oracle sig headWotsPhase vH).1.env "N_MASK" = NMASK ∧ (execList c10Oracle sig headWotsPhase vH).1.env "TB" = 0x80) := by
  obtain ⟨hst, himp⟩ := wots_entry_rel sig vR vH hlay hl hidx hidx64 hsb hso hwp hseed hnode
    hRN hROUT hHN hHTB hHOUT
  rcases h0 : (execList c10Oracle sig refPre vR).2 with _ | hh
  · have h0' : (execList c10Oracle sig headPre vH).2 = none := hst ▸ h0
    obtain ⟨hwp', hz, hd, hwpE, hwaE, hRN', hROUT', hHN', hHTB', hseedE, hRseed, hpad96, htbF,
      eL, eI, eLf, eC, eSB, eS, eRS⟩ := himp h0
    obtain ⟨w1, w2, wend, wseed, wRseed, wpad, _, wHfr, wRenv, wHenv⟩ :=
      wots_layer_rel c10Oracle sig _ _ _ (execList c10Oracle sig refPre vR).1
        (execList c10Oracle sig headPre vH).1 hwp' hz rfl rfl rfl hRN' hROUT' hd hwpE hwaE hHN' hHTB'
        hseedE
    rw [show refWotsPhase = refPre ++ [.forRange "i" (.lit 43) wotsChainBody] from rfl,
      app_none _ _ _ _ _ h0, execList_single,
      show headWotsPhase = headPre ++ (.mstore (.lit 32) (.var "wotsAdrs")
        :: (List.range 43).flatMap chainBlock) from rfl, app_none _ _ _ _ _ h0']
    refine ⟨w1.trans w2.symm, fun _ => ⟨wend, wseed, ?_, wpad, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
      ?_, ?_, ?_, ?_⟩⟩
    · intro k hk; rw [wRseed k hk, hRseed k hk]
    · intro k hk; rw [wHfr _ (by omega) (by omega), hpad96 k hk]
    · intro k hk; rw [wHfr _ (by omega) (by omega), htbF k hk, htb k hk]
    · rw [wHenv _ (by decide), wRenv _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), eL]
    · rw [wHenv _ (by decide), wRenv _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), eI]
    · rw [wHenv _ (by decide), wRenv _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), eLf]
    · rw [wHenv _ (by decide), wRenv _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), eC]
    · rw [wHenv _ (by decide), wRenv _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), eSB]
    · rw [wHenv _ (by decide), wRenv _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), eS]
    · rw [wRenv _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), hRN']
    · rw [wRenv _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), hROUT']
    · rw [wHenv _ (by decide), hHN']
    · rw [wHenv _ (by decide), hHTB']
  · have h0' : (execList c10Oracle sig headPre vH).2 = some hh := hst ▸ h0
    rw [show refWotsPhase = refPre ++ [.forRange "i" (.lit 43) wotsChainBody] from rfl,
      app_some _ _ _ _ _ _ h0,
      show headWotsPhase = headPre ++ (.mstore (.lit 32) (.var "wotsAdrs")
        :: (List.range 43).flatMap chainBlock) from rfl, app_some _ _ _ _ _ _ h0']
    exact ⟨rfl, fun h => absurd h (by simp)⟩

end SphincsCVerify.Interpreter.C10.RelWotsEntry

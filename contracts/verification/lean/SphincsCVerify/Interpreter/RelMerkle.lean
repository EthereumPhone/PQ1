/-
SphincsCVerify.Interpreter.RelMerkle — RESEARCH (#1155 gas track, batch 8): the relational pilot
for the hypertree MERKLE WALK of one layer (9 levels), the family expected to be the hardest.

Reference (`forRange "h" 9 htClimbBody`): the node is the variable `merkleNode`; each level loads
the sibling with `calldataload`, writes the ADRS word to `0x20`, places node and sibling at
`0x40 ^ s` / `0x60 ^ s` (`s = 32 ·` bit 0 of the current `mIdx`, which `htClimbBody` halves
each level, so bit `h` of the original leaf index), hashes `[0, 0x80)` into `0x600` and masks the
result back into `merkleNode`.

Optimized (9 unrolled level blocks, `merkleBlk 0 … merkleBlk 8`): the node lives IN MEMORY in a
32-byte slot chosen by a precomputed word `slots` (`byte(2h, slots)` is the sibling slot,
`byte(2h+1, slots)` the node slot, D1); each level copies the sibling's 16 bytes in with
`calldatacopy`, writes the ADRS word, and hashes `[0, 0x80)` writing the first 16 digest bytes
straight into the next level's node slot (the last level into `0x40`).

`slots_decode` (by `decide`, all 512 leaf indices × 9 levels) is the D1 identity. `merkle_walk_rel`
relates the two walks through a byte-level coupling with an arbitrary hash oracle: both fall
through and the reference's final `merkleNode` has exactly the bytes the optimized v1 leaves at
`0x40`. Pins tie both walks to the two programs by `rfl`. Spec-free.

Mathlib-free; no `sorry`/`admit`/`native_decide`/`bv_decide` and no new axiom declarations.
-/

import SphincsCVerify.Interpreter.RelWots
import SphincsCVerify.Interpreter.HypertreePhase

namespace SphincsCVerify.Interpreter.C10.RelMerkle

open SphincsCVerify.Interpreter
open SphincsCVerify.Interpreter.C10
open SphincsCVerify.Interpreter.C10.RelE1 (loopBody execList_single)
open SphincsCVerify.Interpreter.C10.RelChain
open SphincsCVerify.Interpreter.C10.RelWots
open SphincsCVerify.Spec (ByteVec)

/-! ## 1. Calldata bytes (one-time infrastructure) -/

/-- Byte `j < 32` of the 32-byte calldata word at `off` is the blob byte at `off + j` (zero past
    the end): the byte-level view of `calldataload`, matching `calldatacopy`. -/
theorem loadWord32_byte {m : Nat} (sig : ByteVec m) (off j : Nat) (hj : j < 32) :
    (ByteVec.loadWord32 sig off).data.getD j 0 = calldataByte sig (off + j) := by
  unfold ByteVec.loadWord32 calldataByte
  rw [Array.getD_eq_getD_getElem?, Array.getElem?_extract]
  rw [Array.size_append, Array.size_extract, Array.size_replicate, sig.size_eq]
  rw [if_pos (show j < min 32 (min (off + 32) m - off + 32) - 0 by omega), Nat.zero_add]
  rw [Array.getElem?_append]
  rw [Array.size_extract, sig.size_eq]
  rw [Array.getD_eq_getD_getElem?]
  by_cases hc : off + j < m
  · rw [if_pos (show j < min (off + 32) m - off by omega)]
    rw [Array.getElem?_extract, sig.size_eq, if_pos (show j < min (off + 32) m - off by omega)]
  · rw [if_neg (show ¬ j < min (off + 32) m - off by omega)]
    rw [Array.getElem?_replicate]
    rw [Array.getElem?_eq_none (show sig.data.size ≤ off + j by rw [sig.size_eq]; omega)]
    by_cases hr : j - (min (off + 32) m - off) < 32
    · rw [if_pos hr]; rfl
    · rw [if_neg hr]

theorem beByte_calldataload {m : Nat} (sig : ByteVec m) (off i : Nat) (hi : i < 32) :
    beByte (calldataload sig off) i = calldataByte sig (off + i) := by
  unfold calldataload
  rw [wordOfBV_eq_wordOf, beByte_wordOf_getD _ _ hi, loadWord32_byte _ _ _ hi]

/-! ## 2. The slot word (D1) -/

/-- The optimized v1's slot word for leaf index `t`, exactly as the interpreter evaluates
    `let sbit := and(mul(t, MAGIC), MASK)` and `let slots := sub(add(BASE, shl(1, sbit)), shl(9, sbit))`. -/
def slotsOf (t : Nat) : Nat :=
  let sbit := (t * 0x10000800040002000100008000400020001000080004000000000000000000 % W)
    &&& 0x10001000100010001000100010001000100010001000000000000000000000
  ((0x6040604060406040604060406040604060406040604000000000000000000000 + (sbit <<< 1) % W) % W
    + (W - (sbit <<< 9) % W % W)) % W

/-- `byte(i, x)` as the interpreter evaluates it. -/
def byteAt (i x : Nat) : Nat := if i < 32 then (x >>> (8 * (31 - i))) % 256 else 0

/-- Bit `h` of the leaf index. -/
def bitOf (t h : Nat) : Nat := (t >>> h) % 2

set_option maxRecDepth 100000 in
/-- **D1, the slot decode, for every leaf index and level** (`decide`): byte `2j` of the slot word
    is the sibling slot `0x60 - 32·bit`, byte `2j + 1` the node slot `0x40 + 32·bit`. -/
theorem slots_decode : ∀ t, t < 512 → ∀ j, j < 9 →
    byteAt (2 * j) (slotsOf t) = 0x60 - 32 * bitOf t j
    ∧ byteAt (2 * j + 1) (slotsOf t) = 0x40 + 32 * bitOf t j := by
  unfold bitOf
  decide

/-! ## 3. The level blocks, and the pins -/

/-- The reference's `treeAdrs` mask (`C10Program`'s private `TREEADRS_MASK`). -/
def TM : Nat := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000

/-- The optimized v1's level block `h` (`h < 8`: sibling copy, ADRS word, hash into the next
    node slot; `h = 8`: the last level, hash into `0x40`). -/
def merkleBlk (h : Nat) : List Stmt :=
  if h < 8 then
    [ .calldatacopy (.bin .byte (.lit (2 * h)) (.var "slots")) (.bin .add (.var "merklePtr") (.lit (16 * h)))
        (.lit 16)
    , .mstore (.lit 32) (.bin .bor (.bin .bor (.var "tb") (.bin .shl (.lit 32) (.lit (h + 1))))
        (.bin .shr (.lit (h + 1)) (.var "idxLeaf")))
    , .sha256h (.lit 0) (.lit 128) (.bin .byte (.lit (2 * h + 3)) (.var "slots")) ]
  else
    [ .calldatacopy (.bin .byte (.lit 16) (.var "slots")) (.bin .add (.var "merklePtr") (.lit 128)) (.lit 16)
    , .mstore (.lit 32) (.bin .bor (.var "tb") (.bin .shl (.lit 32) (.lit 9)))
    , .sha256h (.lit 0) (.lit 128) (.lit 64) ]

set_option maxRecDepth 100000 in
set_option maxHeartbeats 4000000 in
/-- The reference's Merkle walk is `forRange "h" 9 htClimbBody` (statement 26 of its layer loop). -/
theorem ref_merkleLoop_pin :
    (loopBody c10Program[28]?)[26]? = some (.forRange "h" (.lit 9) htClimbBody) := rfl

set_option maxRecDepth 100000 in
set_option maxHeartbeats 4000000 in
/-- The optimized layer loop's statements 198..224 are exactly `merkleBlk 0 … merkleBlk 8`. -/
theorem head_merkleBlocks_pin :
    ((loopBody c10HeadProgram[28]?).drop 198).take 27 = (List.range 9).flatMap merkleBlk := rfl


/-! ## 4. One level: the hashed bytes -/

/-- Node and sibling slot of level `h`, `0x40 + 32·bit` and `0x60 - 32·bit`. -/
def nodeAddr (t h : Nat) : Nat := 64 + 32 * bitOf t h

theorem bitOf_le (t h : Nat) : bitOf t h ≤ 1 := by
  unfold bitOf; have := Nat.mod_lt (t >>> h) (show 0 < 2 by decide); omega

/-- **One level hashes the same 128 bytes.** With the seed coupled, the optimized node slot
    holding the reference node's bytes and both slots' low halves zero, the reference's memory
    after its three stores (ADRS at `0x20`, node at `64 + 32b`, masked sibling at `96 - 32b`) and
    the optimized memory after the sibling copy and the ADRS store agree on `[0, 128)`. -/
theorem merkle_slice_eq {n : Nat} (sig : ByteVec n) (memR memH : ByteMemory) (A X b off : Nat)
    (hb : b ≤ 1)
    (hseed : ∀ k, k < 32 → memH k = memR k)
    (hnode : ∀ k, k < 32 → memH (64 + 32 * b + k) = beByte X k)
    (hpad : ∀ k, 16 ≤ k → k < 32 → memH (64 + k) = 0 ∧ memH (96 + k) = 0) :
    slice (mstore32 (mstore32 (mstore32 memR 32 A) (64 + 32 * b) X) (96 - 32 * b)
        (calldataload sig off &&& NMASK)) 0 128
      = slice (mstore32 (writeBytes memH (96 - 32 * b) 16 (fun i => calldataByte sig (off + i))) 32 A) 0 128 := by
  apply slice_congr
  intro i hi
  simp only [Nat.zero_add]
  by_cases hi32 : i < 32
  · rw [mstore32_frame _ _ _ i (by omega), mstore32_frame _ _ _ i (by omega), mstore32_frame _ 32 _ i (by omega),
      mstore32_frame _ 32 _ i (by omega), writeBytes_frame _ _ _ _ _ (by omega), hseed i hi32]
  · by_cases hi64 : i < 64
    · rw [mstore32_frame _ _ _ i (by omega), mstore32_frame _ _ _ i (by omega)]
      have e := mstore32_get memR 32 A (i - 32) (by omega)
      have e' := mstore32_get (writeBytes memH (96 - 32 * b) 16 (fun i => calldataByte sig (off + i))) 32 A
        (i - 32) (by omega)
      rw [show 32 + (i - 32) = i by omega] at e e'
      rw [e, e']
    · -- the two slots
      rw [mstore32_frame _ 32 _ i (by omega)]
      have hsib : ∀ k, k < 32 → beByte (calldataload sig off &&& NMASK) k
          = if k < 16 then calldataByte sig (off + k) else 0 := by
        intro k hk
        rw [beByte_and_nmask]
        by_cases h16 : k < 16
        · rw [if_pos h16, if_pos h16, beByte_calldataload _ _ _ hk]
        · rw [if_neg h16, if_neg h16]
      by_cases hsl : 96 - 32 * b ≤ i ∧ i < 96 - 32 * b + 32
      · -- the sibling slot
        have e := mstore32_get (mstore32 (mstore32 memR 32 A) (64 + 32 * b) X) (96 - 32 * b)
          (calldataload sig off &&& NMASK) (i - (96 - 32 * b)) (by omega)
        rw [show 96 - 32 * b + (i - (96 - 32 * b)) = i by omega] at e
        rw [e, hsib _ (by omega)]
        by_cases h16 : i - (96 - 32 * b) < 16
        · rw [if_pos h16, writeBytes_get _ _ _ _ _ (by omega)]
        · rw [if_neg h16, writeBytes_frame _ _ _ _ _ (by omega)]
          have := hpad (i - (96 - 32 * b)) (by omega) (by omega)
          have hb' : b = 0 ∨ b = 1 := by omega
          rcases hb' with hb0 | hb1
          · subst hb0; rw [show i = 96 + (i - 96) by omega]; exact this.2.symm
          · subst hb1; rw [show i = 64 + (i - 64) by omega]; exact this.1.symm
      · -- the node slot
        rw [mstore32_frame _ _ _ i (by omega)]
        have e := mstore32_get (mstore32 memR 32 A) (64 + 32 * b) X (i - (64 + 32 * b)) (by omega)
        rw [show 64 + 32 * b + (i - (64 + 32 * b)) = i by omega] at e
        rw [e, writeBytes_frame _ _ _ _ _ (by omega)]
        have := hnode (i - (64 + 32 * b)) (by omega)
        rw [show 64 + 32 * b + (i - (64 + 32 * b)) = i by omega] at this
        exact this.symm

/-! ## 5. One level, executed -/

/-- The coupling between levels (`h` = the level about to run; `mR0` / `mH0` = memories at walk
    entry, for the frames). -/
def MInv (leaf ta mp : Nat) (mR0 mH0 : ByteMemory) (h : Nat) (wR wH : VM) : Prop :=
  wR.env "mIdx" = leaf >>> h ∧ wR.env "treeAdrs" = ta ∧ wR.env "merklePtr" = mp
  ∧ wR.env "N_MASK" = NMASK ∧ wR.env "OUT" = 0x600
  ∧ wH.env "slots" = slotsOf leaf ∧ wH.env "tb" = (ta &&& TM) ∧ wH.env "idxLeaf" = leaf
  ∧ wH.env "merklePtr" = mp
  ∧ (∀ k, k < 32 → wH.mem k = wR.mem k)
  ∧ (∀ k, k < 32 → wH.mem (nodeAddr leaf h + k) = beByte (wR.env "merkleNode") k)
  ∧ (∀ k, 16 ≤ k → k < 32 → beByte (wR.env "merkleNode") k = 0)
  ∧ (∀ k, 16 ≤ k → k < 32 → wH.mem (64 + k) = 0 ∧ wH.mem (96 + k) = 0)
  ∧ (∀ a, 128 ≤ a → (a < 0x600 ∨ 0x620 ≤ a) → wR.mem a = mR0 a)
  ∧ (∀ a, 128 ≤ a → wH.mem a = mH0 a)
  ∧ (∀ k, k < 32 → wR.mem k = mR0 k)

theorem byteAt_unfold (i x : Nat) :
    (if i < 32 then x >>> (8 * (31 - i)) % 256 else 0) = byteAt i x := rfl

theorem xor64 (b : Nat) (hb : b ≤ 1) : 64 ^^^ 32 * b = 64 + 32 * b := by
  have : b = 0 ∨ b = 1 := by omega
  rcases this with h | h <;> subst h <;> decide

theorem xor96 (b : Nat) (hb : b ≤ 1) : 96 ^^^ 32 * b = 96 - 32 * b := by
  have : b = 0 ∨ b = 1 := by omega
  rcases this with h | h <;> subst h <;> decide

theorem sOf (m : Nat) : (m &&& 1) <<< 5 % W = 32 * (m % 2) := by
  rw [Nat.and_one_is_mod, Nat.shiftLeft_eq, show (2 : Nat) ^ 5 = 32 from rfl, Nat.mul_comm]
  exact Nat.mod_eq_of_lt (lt_W_of_lt (by have := Nat.mod_lt m (show 0 < 2 by decide); omega))

/-- The level's reference state after the body, written out (one shared form for both blocks). -/
def refLevelOut {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (wR : VM) (h leaf ta mp : Nat) : VM :=
  let b := bitOf leaf h
  let A := (ta &&& TM) ||| ((h + 1) <<< 32 % W ||| leaf >>> (h + 1))
  let sib := calldataload sig (mp + 16 * h) &&& NMASK
  let m3 := mstore32 (mstore32 (mstore32 wR.mem 32 A) (64 + 32 * b) (wR.env "merkleNode")) (96 - 32 * b) sib
  let m4 := writeRegion m3 0x600 (fun i => (sha (slice m3 0 128)).data.getD i 0)
  { mem := m4,
    env := setVar (setVar (setVar (setVar (setVar (setVar wR.env "h" h) "sibling" sib) "parentIdx" (leaf >>> (h + 1)))
      "s" (32 * b)) "merkleNode" (mload32 m4 0x600 &&& NMASK)) "mIdx" (leaf >>> (h + 1)) }

/-- The reference level body, executed (from `MInv`). -/
theorem ref_level_eq {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (wR : VM)
    (h leaf ta mp : Nat) (hh : h < 9) (hmp : mp < 4096)
    (hm : wR.env "mIdx" = leaf >>> h) (hta : wR.env "treeAdrs" = ta) (hmpR : wR.env "merklePtr" = mp)
    (hN : wR.env "N_MASK" = NMASK) (hOUT : wR.env "OUT" = 0x600) :
    execList sha sig htClimbBody { wR with env := setVar wR.env "h" h } = (refLevelOut sha sig wR h leaf ta mp, none) := by
  have h16 : h <<< 4 % W = 16 * h := by
    rw [Nat.shiftLeft_eq, show (2 : Nat) ^ 4 = 16 from rfl, Nat.mul_comm]
    exact Nat.mod_eq_of_lt (lt_W_of_lt (by omega))
  have hmp16 : (mp + 16 * h) % W = mp + 16 * h := Nat.mod_eq_of_lt (lt_W_of_lt' (by omega))
  have hh1 : (h + 1) % W = h + 1 := Nat.mod_eq_of_lt (lt_W_of_lt (by omega))
  have hpar : leaf >>> h >>> 1 = leaf >>> (h + 1) := (Nat.shiftRight_add leaf h 1).symm
  have hb := bitOf_le leaf h
  unfold htClimbBody
  rw [execList_cons_none sha sig _ _ _ (by simp only [execStmt]),
    execList_cons_none sha sig _ _ _ (by simp only [execStmt]),
    execList_cons_none sha sig _ _ _ (by simp only [execStmt]),
    execList_cons_none sha sig _ _ _ (by simp only [execStmt]),
    execList_cons_none sha sig _ _ _ (by simp only [execStmt]),
    execList_cons_none sha sig _ _ _ (by simp only [execStmt]),
    execList_cons_none sha sig _ _ _ (by simp only [execStmt]),
    execList_cons_none sha sig _ _ _ (by simp only [execStmt]), execList_single]
  simp only [execStmt, eval, setVar, ite_true, ite_false, String.reduceEq, hm, hta, hmpR, hN, hOUT,
    h16, hmp16, hh1, hpar, sOf]
  rw [show (leaf >>> h) % 2 = bitOf leaf h from rfl, xor64 _ hb, xor96 _ hb]
  rfl

/-- The level's optimized state after the block, written out (one form for both block shapes). -/
def headLevelOut {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (wH : VM) (h leaf ta mp : Nat) : VM :=
  let b := bitOf leaf h
  let A := (ta &&& TM) ||| ((h + 1) <<< 32 % W ||| leaf >>> (h + 1))
  let n2 := mstore32 (writeBytes wH.mem (96 - 32 * b) 16 (fun i => calldataByte sig (mp + 16 * h + i))) 32 A
  { mem := writeBytes n2 (nodeAddr leaf (h + 1)) 16 (fun i => (sha (slice n2 0 128)).data.getD i 0),
    env := wH.env }

theorem bitOf_9 (leaf : Nat) (hleaf : leaf < 512) : bitOf leaf 9 = 0 := by
  unfold bitOf
  rw [Nat.shiftRight_eq_div_pow, Nat.div_eq_of_lt (by exact Nat.lt_of_lt_of_le hleaf (by decide))]

/-- The optimized level block, executed (from `MInv`'s env facts), for both block shapes. -/
theorem head_level_eq {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (wH : VM)
    (h leaf ta mp : Nat) (hh : h < 9) (hleaf : leaf < 512) (hmp : mp < 4096)
    (hsl : wH.env "slots" = slotsOf leaf) (htb : wH.env "tb" = (ta &&& TM)) (hil : wH.env "idxLeaf" = leaf)
    (hmpH : wH.env "merklePtr" = mp) :
    execList sha sig (merkleBlk h) wH = (headLevelOut sha sig wH h leaf ta mp, none) := by
  have hmp16 : (mp + 16 * h) % W = mp + 16 * h := Nat.mod_eq_of_lt (lt_W_of_lt' (by omega))
  by_cases h8 : h < 8
  · unfold merkleBlk
    rw [if_pos h8]
    rw [execList_cons_none sha sig _ _ _ (by simp only [execStmt]),
      execList_cons_none sha sig _ _ _ (by simp only [execStmt]), execList_single]
    simp only [execStmt, eval, hsl, htb, hil, hmpH, hmp16, byteAt_unfold]
    rw [(slots_decode leaf hleaf h hh).1, show 2 * h + 3 = 2 * (h + 1) + 1 by omega,
      (slots_decode leaf hleaf (h + 1) (by omega)).2, Nat.or_assoc]
    rfl
  · have h8' : h = 8 := by omega
    subst h8'
    unfold merkleBlk
    rw [if_neg (by decide)]
    rw [execList_cons_none sha sig _ _ _ (by simp only [execStmt]),
      execList_cons_none sha sig _ _ _ (by simp only [execStmt]), execList_single]
    have hmp128 : (mp + 128) % W = mp + 128 := Nat.mod_eq_of_lt (lt_W_of_lt' (by omega))
    simp only [execStmt, eval, hsl, htb, hmpH, byteAt_unfold, hmp128]
    rw [show (16 : Nat) = 2 * 8 from rfl, (slots_decode leaf hleaf 8 (by decide)).1]
    have h9 : leaf >>> (8 + 1) = 0 := by
      rw [Nat.shiftRight_eq_div_pow]; exact Nat.div_eq_of_lt (Nat.lt_of_lt_of_le hleaf (by decide))
    unfold headLevelOut
    simp only [h9, Nat.or_zero, show (8 : Nat) + 1 = 9 from rfl, show (16 : Nat) * 8 = 128 from rfl]
    rw [show nodeAddr leaf 9 = 64 by unfold nodeAddr; rw [bitOf_9 leaf hleaf]]

set_option maxHeartbeats 8000000 in
/-- **One level, related.** From coupled states, the reference level (`h` set by its loop
    driver) and the optimized level block `h` both fall through and leave states coupled at
    level `h + 1`: same seed bytes, the optimized next node slot (`0x40 + 32·bit (h+1)`, the last
    level `0x40`) holding the bytes of the reference's new `merkleNode`, slot padding zero,
    frames. Arbitrary hash oracle. -/
theorem merkle_step_rel {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n)
    (leaf ta mp : Nat) (mR0 mH0 : ByteMemory) (h : Nat) (wR wH : VM)
    (hh : h < 9) (hleaf : leaf < 512) (hmp : mp < 4096)
    (hI : MInv leaf ta mp mR0 mH0 h wR wH) :
    (execList sha sig htClimbBody { wR with env := setVar wR.env "h" h }).2 = none
    ∧ (execList sha sig (merkleBlk h) wH).2 = none
    ∧ MInv leaf ta mp mR0 mH0 (h + 1)
        (execList sha sig htClimbBody { wR with env := setVar wR.env "h" h }).1
        (execList sha sig (merkleBlk h) wH).1 := by
  obtain ⟨hm, hta, hmpR, hN, hOUT, hsl, htb, hil, hmpH, hseed, hnode, hnlo, hpad, hfR, hfH, hsR⟩ := hI
  rw [ref_level_eq sha sig wR h leaf ta mp hh hmp hm hta hmpR hN hOUT,
    head_level_eq sha sig wH h leaf ta mp hh hleaf hmp hsl htb hil hmpH]
  refine ⟨rfl, rfl, ?_⟩
  have hb := bitOf_le leaf h
  have hb1 := bitOf_le leaf (h + 1)
  have hS := merkle_slice_eq sig wR.mem wH.mem ((ta &&& TM) ||| ((h + 1) <<< 32 % W ||| leaf >>> (h + 1)))
    (wR.env "merkleNode") (bitOf leaf h) (mp + 16 * h) hb hseed hnode hpad
  unfold refLevelOut headLevelOut
  simp only []
  rw [hS]
  generalize hD : sha (slice (mstore32 (writeBytes wH.mem (96 - 32 * bitOf leaf h) 16
    (fun i => calldataByte sig (mp + 16 * h + i))) 32
    ((ta &&& TM) ||| ((h + 1) <<< 32 % W ||| leaf >>> (h + 1)))) 0 128) = D
  have hoA : nodeAddr leaf (h + 1) = 64 + 32 * bitOf leaf (h + 1) := rfl
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · dsimp only; exact setVar_get_eq _ _ _
  · dsimp only; simp only [setVar, String.reduceEq, ite_false]; exact hta
  · dsimp only; simp only [setVar, String.reduceEq, ite_false]; exact hmpR
  · dsimp only; simp only [setVar, String.reduceEq, ite_false]; exact hN
  · dsimp only; simp only [setVar, String.reduceEq, ite_false]; exact hOUT
  · exact hsl
  · exact htb
  · exact hil
  · exact hmpH
  · intro k hk
    dsimp only
    rw [writeBytes_frame _ _ _ _ _ (by rw [hoA]; omega), mstore32_frame _ 32 _ k (by omega),
      writeBytes_frame _ _ _ _ _ (by omega), writeRegion_frame _ _ _ _ (by omega),
      mstore32_frame _ _ _ k (by omega), mstore32_frame _ _ _ k (by omega), mstore32_frame _ 32 _ k (by omega),
      hseed k hk]
  · intro k hk
    dsimp only
    simp only [setVar, String.reduceEq, ite_false, ite_true]
    rw [beByte_and_nmask]
    by_cases hk16 : k < 16
    · rw [if_pos hk16, writeBytes_get _ _ _ _ _ (by omega), beByte_mload32 _ _ _ hk,
        writeRegion_get _ _ _ _ (by omega)]
      simp only [Nat.add_sub_cancel_left]
    · rw [if_neg hk16, writeBytes_frame _ _ _ _ _ (by omega), mstore32_frame _ 32 _ _ (by rw [hoA]; omega),
        writeBytes_frame _ _ _ _ _ (by rw [hoA]; omega)]
      have hp := hpad k (by omega) hk
      rw [hoA]
      have : bitOf leaf (h + 1) = 0 ∨ bitOf leaf (h + 1) = 1 := by omega
      rcases this with e | e <;> rw [e]
      · simpa using hp.1
      · simpa using hp.2
  · intro k hk16 _
    dsimp only
    simp only [setVar, String.reduceEq, ite_false, ite_true]
    exact beByte_masked_low _ k hk16
  · intro k hk1 hk2
    dsimp only
    have hp := hpad k hk1 hk2
    constructor
    · rw [writeBytes_frame _ _ _ _ _ (by rw [hoA]; omega), mstore32_frame _ 32 _ _ (by omega),
        writeBytes_frame _ _ _ _ _ (by omega)]
      exact hp.1
    · rw [writeBytes_frame _ _ _ _ _ (by rw [hoA]; omega), mstore32_frame _ 32 _ _ (by omega),
        writeBytes_frame _ _ _ _ _ (by omega)]
      exact hp.2
  · intro a ha hout
    dsimp only
    rw [writeRegion_frame _ _ _ _ (by omega), mstore32_frame _ _ _ a (by omega),
      mstore32_frame _ _ _ a (by omega), mstore32_frame _ 32 _ a (by omega)]
    exact hfR a ha hout
  · intro a ha
    dsimp only
    rw [writeBytes_frame _ _ _ _ _ (by rw [hoA]; omega), mstore32_frame _ 32 _ a (by omega),
      writeBytes_frame _ _ _ _ _ (by omega)]
    exact hfH a ha
  · intro k hk
    dsimp only
    rw [writeRegion_frame _ _ _ _ (by omega), mstore32_frame _ _ _ k (by omega),
      mstore32_frame _ _ _ k (by omega), mstore32_frame _ 32 _ k (by omega)]
    exact hsR k hk

/-! ## 6. The whole walk -/

set_option maxHeartbeats 4000000 in
/-- **The Merkle walk of one layer, related.** The reference's `forRange "h" 9 htClimbBody` and
    the optimized `merkleBlk 0 … merkleBlk 8`, from states coupled at level 0 (`MInv … 0`: the
    optimized node slot `0x40 + 32·bit 0` holds the bytes of the reference's `merkleNode`, the
    seed is shared, the slot word is `slotsOf leaf`), both fall through, and the reference's
    final `merkleNode` has exactly the 32 bytes the optimized v1 leaves at `0x40` (the value both
    programs compare with the root). The full coupling at level 9 is exported too. Arbitrary
    hash oracle. -/
theorem merkle_walk_rel {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n)
    (leaf ta mp : Nat) (vR vH : VM) (hleaf : leaf < 512) (hmp : mp < 4096)
    (hI : MInv leaf ta mp vR.mem vH.mem 0 vR vH) :
    (execStmt sha sig (.forRange "h" (.lit 9) htClimbBody) vR).2 = none
    ∧ (execList sha sig ((List.range 9).flatMap merkleBlk) vH).2 = none
    ∧ (∀ k, k < 32 → (execList sha sig ((List.range 9).flatMap merkleBlk) vH).1.mem (64 + k)
        = beByte ((execStmt sha sig (.forRange "h" (.lit 9) htClimbBody) vR).1.env "merkleNode") k)
    ∧ MInv leaf ta mp vR.mem vH.mem 9 (execStmt sha sig (.forRange "h" (.lit 9) htClimbBody) vR).1
        (execList sha sig ((List.range 9).flatMap merkleBlk) vH).1
    ∧ (∀ x, x ≠ "h" → x ≠ "sibling" → x ≠ "parentIdx" → x ≠ "s" → x ≠ "merkleNode" → x ≠ "mIdx" →
        (execStmt sha sig (.forRange "h" (.lit 9) htClimbBody) vR).1.env x = vR.env x)
    ∧ (∀ x, (execList sha sig ((List.range 9).flatMap merkleBlk) vH).1.env x = vH.env x) := by
  have henvR : ∀ x, x ≠ "h" → x ≠ "sibling" → x ≠ "parentIdx" → x ≠ "s" → x ≠ "merkleNode" → x ≠ "mIdx" →
      (execStmt sha sig (.forRange "h" (.lit 9) htClimbBody) vR).1.env x = vR.env x := by
    intro x a1 a2 a3 a4 a5 a6
    simp only [execStmt, eval]
    exact execFor_env_frame sha sig "h" htClimbBody x (Ne.symm a1)
      (by unfold htClimbBody; simp [assignsVarList, assignsVar]; exact ⟨Ne.symm a2, Ne.symm a3, Ne.symm a4, Ne.symm a5, Ne.symm a6⟩)
      _ _ _
  have henvH : ∀ x, (execList sha sig ((List.range 9).flatMap merkleBlk) vH).1.env x = vH.env x := by
    intro x
    exact execList_env_frame sha sig _ x vH
      (by simp [List.range_succ, merkleBlk, assignsVarList, assignsVar])
  simp only [execStmt, eval]
  simp only [execStmt, eval] at henvR
  rw [List.range_eq_range'] at henvH ⊢
  have r := execFor_vs_blocks sha sig "h" htClimbBody merkleBlk 9 (MInv leaf ta mp vR.mem vH.mem)
    (fun h w1 w2 hh hI' => merkle_step_rel sha sig leaf ta mp vR.mem vH.mem h w1 w2 hh hleaf hmp hI')
    9 0 vR vH (by omega) hI
  obtain ⟨hnR, hnH, hfin⟩ := r
  refine ⟨hnR, hnH, ?_, hfin, henvR, henvH⟩
  intro k hk
  have := hfin.2.2.2.2.2.2.2.2.2.2.1 k hk
  rwa [show nodeAddr leaf 9 = 64 by unfold nodeAddr; rw [bitOf_9 leaf hleaf]] at this

/-! ## 7. The slot word and the ADRS base come from the program -/

/-- The optimized v1's three statements that build the slot word (statements 190..192 of its
    layer loop). -/
def slotsSetup : List Stmt :=
  [ .letv "t" (.var "idxLeaf")
  , .letv "sbit" (.bin .band (.bin .mul (.var "t") (.lit 0x10000800040002000100008000400020001000080004000000000000000000))
      (.lit 0x10001000100010001000100010001000100010001000000000000000000000))
  , .letv "slots" (.bin .sub (.bin .add (.lit 0x6040604060406040604060406040604060406040604000000000000000000000)
      (.bin .shl (.lit 1) (.var "sbit"))) (.bin .shl (.lit 9) (.var "sbit"))) ]

/-- Its ADRS-base statement (statement 197): `let tb := and(treeAdrs, TM)`. -/
def tbSetup : List Stmt := [ .letv "tb" (.bin .band (.var "treeAdrs") (.lit TM)) ]

set_option maxRecDepth 100000 in
set_option maxHeartbeats 4000000 in
theorem head_slotsSetup_pin : ((loopBody c10HeadProgram[28]?).drop 190).take 3 = slotsSetup := rfl

set_option maxRecDepth 100000 in
set_option maxHeartbeats 4000000 in
theorem head_tbSetup_pin : ((loopBody c10HeadProgram[28]?).drop 197).take 1 = tbSetup := rfl

/-- Executing `slotsSetup` binds `slots = slotsOf idxLeaf` (and touches no memory). -/
theorem slotsSetup_eval {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (vm : VM) :
    (execList sha sig slotsSetup vm).2 = none
    ∧ (execList sha sig slotsSetup vm).1.env "slots" = slotsOf (vm.env "idxLeaf")
    ∧ (execList sha sig slotsSetup vm).1.mem = vm.mem := by
  unfold slotsSetup
  rw [execList_cons_none sha sig _ _ _ (by simp only [execStmt]),
    execList_cons_none sha sig _ _ _ (by simp only [execStmt]), execList_single]
  refine ⟨by simp only [execStmt], ?_, by simp only [execStmt]⟩
  simp only [execStmt]
  rw [setVar_get_eq]
  simp only [eval]
  rw [setVar_get_eq, setVar_get_eq]
  rfl

/-- Executing `tbSetup` binds `tb = treeAdrs &&& TM`. -/
theorem tbSetup_eval {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (vm : VM) :
    (execList sha sig tbSetup vm).2 = none
    ∧ (execList sha sig tbSetup vm).1.env "tb" = (vm.env "treeAdrs" &&& TM)
    ∧ (execList sha sig tbSetup vm).1.mem = vm.mem := by
  unfold tbSetup
  rw [execList_single]
  refine ⟨by simp only [execStmt], ?_, by simp only [execStmt]⟩
  simp only [execStmt]
  rw [setVar_get_eq]
  rfl

end SphincsCVerify.Interpreter.C10.RelMerkle

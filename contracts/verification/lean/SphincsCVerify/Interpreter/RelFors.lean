/-
SphincsCVerify.Interpreter.RelFors — RESEARCH (#1155 gas track, batches 10-11): obligation O2 of
the skeleton (`RelSkeleton.ForsObl`), FORS, and with it the unconditional end theorem.

Reference (statements 19..24): 12 trees, each a leaf hash into `node` and an 11-level climb
(`forRange "h" 11`), the root stored as a full word at `0x80 + 32i`; the last tree's leaf at
`0x200`; the root ADRS; the 13 roots copied down by `0x40`; the compression of `[0, 0x1E0)`.

Optimized (statements 20..25): the seed copied to `TB = 0x80`, `0x60` cleared; per tree the leaf
hashed as 16 bytes into the slot chosen by the `C10-LANES` slot word (`RelMerkle.slotsOf`, decoded
here by `fors_slots_decode`), 11 unrolled levels, the last into the root slot `0xC0 + 32i`; the
last tree's leaf at `0x240`; the root ADRS at `0xA0`; the compression of `[0x80, 0x260)` into
`0x40` (16 bytes).

`fors_obl : ForsObl`. Then `head_verdict_eq_full`: the optimized v1 returns the reference's
verdict for every key, message and signature, with no obligation assumed; and
`execC10HeadAsm_eq`, its composition with the reference's `execC10Asm_eq`. Mathlib-free; no
`sorry`/`admit`/`native_decide`/`bv_decide` and no new axioms.
-/

import SphincsCVerify.Interpreter.RelHmsg
import SphincsCVerify.Interpreter.C10Refine

namespace SphincsCVerify.Interpreter.C10.RelFors

open SphincsCVerify.Interpreter
open SphincsCVerify.Interpreter.C10
open SphincsCVerify.Interpreter.C10.RelE1 (execList_single)
open SphincsCVerify.Interpreter.C10.RelChain
open SphincsCVerify.Interpreter.C10.RelWots
open SphincsCVerify.Interpreter.C10.RelWotsEntry
open SphincsCVerify.Interpreter.C10.RelMerkle
open SphincsCVerify.Interpreter.C10.RelSkeleton
open SphincsCVerify.Interpreter.C10.RelMid
open SphincsCVerify.Spec (ByteVec)

set_option maxRecDepth 100000 in
/-- **The FORS slot decode, for every 11-bit tree index and all 11 levels** (`decide`): byte `2j`
    of the slot word is the sibling slot `0x60 - 32·bit_j`, byte `2j + 1` the node slot
    `0x40 + 32·bit_j`. -/
theorem fors_slots_decode : ∀ t, t < 2048 → ∀ j, j < 11 →
    byteAt (2 * j) (slotsOf t) = 0x60 - 32 * bitOf t j
    ∧ byteAt (2 * j + 1) (slotsOf t) = 0x40 + 32 * bitOf t j := by
  decide

/-! ## 2. The two FORS fragments -/

/-- The reference's per-level climb body (the inner `for h < 11`). -/
def forsClimbBody : List Stmt :=
  [ .letv "sibling" (.bin .band (.calldataload (.bin .add (.var "authPtr") (.bin .shl (.lit 4) (.var "h"))))
      (.var "N_MASK"))
  , .letv "parentIdx" (.bin .shr (.lit 1) (.var "pathIdx"))
  , .mstore (.lit 32) (.bin .bor (.var "treeAdrsBase") (.bin .bor (.bin .shl (.lit 32)
      (.bin .add (.var "h") (.lit 1))) (.var "parentIdx")))
  , .letv "s" (.bin .shl (.lit 5) (.bin .band (.var "pathIdx") (.lit 1)))
  , .mstore (.bin .bxor (.lit 64) (.var "s")) (.var "node")
  , .mstore (.bin .bxor (.lit 96) (.var "s")) (.var "sibling")
  , .sha256 (.lit 0) (.lit 128) (.var "OUT")
  , .setv "node" (.bin .band (.mload (.var "OUT")) (.var "N_MASK"))
  , .setv "pathIdx" (.var "parentIdx") ]

/-- The optimized level block `h` (`h < 10`: sibling copy, ADRS word, hash into the next node
    slot; `h = 10`: the last level, hash into the tree's root slot `TB + 0x40 + 32i`). -/
def forsBlk (h : Nat) : List Stmt :=
  if h < 10 then
    [ .calldatacopy (.bin .byte (.lit (2 * h)) (.var "slots")) (.bin .add (.var "authPtr") (.lit (16 * h)))
        (.lit 16)
    , .mstore (.lit 32) (.bin .bor (.bin .bor (.var "treeAdrsBase") (.bin .shl (.lit 32) (.lit (h + 1))))
        (.bin .shr (.lit (h + 1)) (.var "treeIdx")))
    , .sha256h (.lit 0) (.lit 128) (.bin .byte (.lit (2 * h + 3)) (.var "slots")) ]
  else
    [ .calldatacopy (.bin .byte (.lit 20) (.var "slots")) (.bin .add (.var "authPtr") (.lit 160)) (.lit 16)
    , .mstore (.lit 32) (.bin .bor (.var "treeAdrsBase") (.bin .shl (.lit 32) (.lit 11)))
    , .sha256h (.lit 0) (.lit 128) (.bin .add (.bin .add (.var "TB") (.lit 64)) (.bin .shl (.lit 5) (.var "i"))) ]

def treeIdxS : Stmt :=
  .letv "treeIdx" (.bin .band (.bin .shr (.bin .mul (.var "i") (.lit 11)) (.var "dVal")) (.lit 2047))
def secretS : Stmt :=
  .letv "secretVal" (.bin .band (.calldataload (.bin .add (.var "sigBase") (.bin .add (.lit 16)
    (.bin .shl (.lit 4) (.var "i"))))) (.var "N_MASK"))
def leafAdrsS : Stmt :=
  .letv "leafAdrs" (.bin .bor (.bin .shl (.lit 160) (.var "htIdx")) (.bin .bor (.bin .shl (.lit 128) (.lit 3))
    (.bin .bor (.bin .shl (.lit 96) (.var "i")) (.var "treeIdx"))))
def tabS : Stmt :=
  .letv "treeAdrsBase" (.bin .bor (.bin .shl (.lit 160) (.var "htIdx")) (.bin .bor (.bin .shl (.lit 128) (.lit 3))
    (.bin .shl (.lit 96) (.var "i"))))
def authS : Stmt :=
  .letv "authPtr" (.bin .add (.var "sigBase") (.bin .add (.lit 224) (.bin .mul (.var "i") (.lit 176))))

/-- The shared opening of a tree body: tree index, secret, leaf ADRS and its two stores. -/
def treeOpen : List Stmt :=
  [ treeIdxS, secretS, leafAdrsS, .mstore (.lit 32) (.var "leafAdrs"), .mstore (.lit 64) (.var "secretVal") ]

def refTreeBody : List Stmt :=
  treeOpen ++
  [ .sha256 (.lit 0) (.lit 96) (.var "OUT"), .letv "node" (.bin .band (.mload (.var "OUT")) (.var "N_MASK"))
  , tabS, .letv "pathIdx" (.var "treeIdx"), authS
  , .forRange "h" (.lit 11) forsClimbBody
  , .mstore (.bin .add (.lit 128) (.bin .shl (.lit 5) (.var "i"))) (.var "node") ]

/-- The optimized slot word for the tree index. -/
def forsSlotsSetup : List Stmt :=
  [ .letv "t" (.var "treeIdx")
  , .letv "sbit" (.bin .band (.bin .mul (.var "t") (.lit 0x10000800040002000100008000400020001000080004000000000000000000))
      (.lit 0x10001000100010001000100010001000100010001000000000000000000000))
  , .letv "slots" (.bin .sub (.bin .add (.lit 0x6040604060406040604060406040604060406040604000000000000000000000)
      (.bin .shl (.lit 1) (.var "sbit"))) (.bin .shl (.lit 9) (.var "sbit"))) ]

def headTreeBody : List Stmt :=
  treeOpen ++ (forsSlotsSetup ++ ([ .sha256h (.lit 0) (.lit 96) (.bin .byte (.lit 1) (.var "slots")), tabS, authS ]
    ++ (List.range 11).flatMap forsBlk))

def lastSecretS : Stmt :=
  .letv "lastSecret" (.bin .band (.calldataload (.bin .add (.var "sigBase") (.bin .add (.lit 16)
    (.bin .shl (.lit 4) (.lit 12))))) (.var "N_MASK"))
def lastAdrsE : Expr :=
  .bin .bor (.bin .shl (.lit 160) (.var "htIdx")) (.bin .bor (.bin .shl (.lit 128) (.lit 3)) (.bin .shl (.lit 96) (.lit 12)))
def rootAdrsE : Expr := .bin .bor (.bin .shl (.lit 160) (.var "htIdx")) (.bin .shl (.lit 128) (.lit 4))

def refLast : List Stmt :=
  [ lastSecretS, .mstore (.lit 32) lastAdrsE, .mstore (.lit 64) (.var "lastSecret")
  , .sha256 (.lit 0) (.lit 96) (.var "OUT"), .mstore (.lit 512) (.bin .band (.mload (.var "OUT")) (.var "N_MASK")) ]
def headLast : List Stmt :=
  [ lastSecretS, .mstore (.lit 32) lastAdrsE, .mstore (.lit 64) (.var "lastSecret")
  , .sha256h (.lit 0) (.lit 96) (.bin .add (.var "TB") (.lit 448)) ]

set_option maxRecDepth 100000 in
theorem refFors_split : refFors =
    [ .forRange "i" (.lit 12) refTreeBody, .block refLast, .mstore (.lit 32) rootAdrsE
    , .forRange "i" (.lit 13) forsCopyBody, .sha256 (.lit 0) (.lit 480) (.var "OUT")
    , .letv "forsPk" (.bin .band (.mload (.var "OUT")) (.var "N_MASK")) ] := rfl

set_option maxRecDepth 100000 in
theorem headFors_split : headFors =
    [ .mstore (.var "TB") (.var "seed"), .mstore (.lit 96) (.lit 0)
    , .forRange "i" (.lit 12) headTreeBody, .block headLast
    , .mstore (.bin .add (.var "TB") (.lit 32)) rootAdrsE
    , .sha256h (.var "TB") (.lit 480) (.lit 64) ] := rfl

/-! ## 3. One climb level, executed -/

/-- Where the optimized node of level `h` lives: the slot `0x40 + 32·bit_h` for `h < 11`, the
    tree's root slot `0xC0 + 32i` after the last level. -/
def nodeAt (t i h : Nat) : Nat := if h < 11 then 64 + 32 * bitOf t h else 0xC0 + 32 * i

/-- The FORS climb ADRS word of level `h` (both sides). -/
def forsA (ta t h : Nat) : Nat := ta ||| ((h + 1) <<< 32 % W ||| t >>> (h + 1))

def forsRefLevelOut {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (wR : VM) (h t ta ap : Nat) : VM :=
  let b := bitOf t h
  let sib := calldataload sig (ap + 16 * h) &&& NMASK
  let m3 := mstore32 (mstore32 (mstore32 wR.mem 32 (forsA ta t h)) (64 + 32 * b) (wR.env "node")) (96 - 32 * b) sib
  let m4 := writeRegion m3 0x600 (fun i => (sha (slice m3 0 128)).data.getD i 0)
  { mem := m4,
    env := setVar (setVar (setVar (setVar (setVar (setVar wR.env "h" h) "sibling" sib) "parentIdx" (t >>> (h + 1)))
      "s" (32 * b)) "node" (mload32 m4 0x600 &&& NMASK)) "pathIdx" (t >>> (h + 1)) }

theorem fors_ref_level_eq {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (wR : VM)
    (h t ta ap : Nat) (hh : h < 11) (hap : ap < 4096)
    (hm : wR.env "pathIdx" = t >>> h) (hta : wR.env "treeAdrsBase" = ta) (hapR : wR.env "authPtr" = ap)
    (hN : wR.env "N_MASK" = NMASK) (hOUT : wR.env "OUT" = 0x600) :
    execList sha sig forsClimbBody { wR with env := setVar wR.env "h" h }
      = (forsRefLevelOut sha sig wR h t ta ap, none) := by
  have h16 : h <<< 4 % W = 16 * h := by
    rw [Nat.shiftLeft_eq, show (2 : Nat) ^ 4 = 16 from rfl, Nat.mul_comm]
    exact Nat.mod_eq_of_lt (lt_W_of_lt (by omega))
  have hap16 : (ap + 16 * h) % W = ap + 16 * h := Nat.mod_eq_of_lt (lt_W_of_lt' (by omega))
  have hh1 : (h + 1) % W = h + 1 := Nat.mod_eq_of_lt (lt_W_of_lt (by omega))
  have hpar : t >>> h >>> 1 = t >>> (h + 1) := (Nat.shiftRight_add t h 1).symm
  have hb := bitOf_le t h
  unfold forsClimbBody
  repeat rw [execList_cons_none sha sig _ _ _ (by simp only [execStmt])]
  simp only [execList, execStmt, eval, setVar, ite_true, ite_false, String.reduceEq, hm, hta, hapR, hN, hOUT,
    h16, hap16, hh1, hpar, sOf]
  rw [show (t >>> h) % 2 = bitOf t h from rfl, xor64 _ hb, xor96 _ hb]
  rfl

def forsHeadLevelOut {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (wH : VM) (h t ta ap i : Nat) : VM :=
  let b := bitOf t h
  let n2 := mstore32 (writeBytes wH.mem (96 - 32 * b) 16 (fun j => calldataByte sig (ap + 16 * h + j))) 32
    (forsA ta t h)
  { mem := writeBytes n2 (nodeAt t i (h + 1)) 16 (fun j => (sha (slice n2 0 128)).data.getD j 0),
    env := wH.env }

theorem fors_head_level_eq {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (wH : VM)
    (h t ta ap i : Nat) (hh : h < 11) (ht : t < 2048) (hap : ap < 4096) (hi : i < 12)
    (hsl : wH.env "slots" = slotsOf t) (htb : wH.env "treeAdrsBase" = ta) (hti : wH.env "treeIdx" = t)
    (hapH : wH.env "authPtr" = ap) (hTB : wH.env "TB" = 0x80) (hiH : wH.env "i" = i) :
    execList sha sig (forsBlk h) wH = (forsHeadLevelOut sha sig wH h t ta ap i, none) := by
  have hap16 : (ap + 16 * h) % W = ap + 16 * h := Nat.mod_eq_of_lt (lt_W_of_lt' (by omega))
  by_cases h10 : h < 10
  · unfold forsBlk
    rw [if_pos h10]
    rw [execList_cons_none sha sig _ _ _ (by simp only [execStmt]),
      execList_cons_none sha sig _ _ _ (by simp only [execStmt]), execList_single]
    simp only [execStmt, eval, hsl, htb, hti, hapH, hap16, byteAt_unfold]
    rw [(fors_slots_decode t ht h hh).1, show 2 * h + 3 = 2 * (h + 1) + 1 by omega,
      (fors_slots_decode t ht (h + 1) (by omega)).2, Nat.or_assoc]
    unfold forsHeadLevelOut nodeAt forsA
    rw [if_pos (by omega : h + 1 < 11)]
  · have h10' : h = 10 := by omega
    subst h10'
    unfold forsBlk
    rw [if_neg (by decide)]
    rw [execList_cons_none sha sig _ _ _ (by simp only [execStmt]),
      execList_cons_none sha sig _ _ _ (by simp only [execStmt]), execList_single]
    have hap160 : (ap + 160) % W = ap + 160 := Nat.mod_eq_of_lt (lt_W_of_lt' (by omega))
    have hout : ((128 + 64) % W + (i <<< 5) % W) % W = 0xC0 + 32 * i := by
      rw [shl5_small i (by omega), Nat.mod_eq_of_lt (lt_W_of_lt (show 128 + 64 < 4096 by omega)),
        Nat.mod_eq_of_lt (lt_W_of_lt (show 192 + 32 * i < 4096 by omega))]
    simp only [execStmt, eval, hsl, htb, hapH, hTB, hiH, byteAt_unfold, hap160, hout]
    rw [show (20 : Nat) = 2 * 10 from rfl, (fors_slots_decode t ht 10 (by decide)).1]
    have h11 : t >>> (10 + 1) = 0 := by
      rw [Nat.shiftRight_eq_div_pow]; exact Nat.div_eq_of_lt (Nat.lt_of_lt_of_le ht (by decide))
    unfold forsHeadLevelOut nodeAt forsA
    rw [if_neg (by decide)]
    simp only [h11, Nat.or_zero, show (10 : Nat) + 1 = 11 from rfl, show (16 : Nat) * 10 = 160 from rfl]

/-! ## 4. The climb of one tree -/

/-- The coupling between climb levels. `mR0` / `mH0` are the memories at climb entry. -/
def FInv (t ta ap i : Nat) (mR0 mH0 : ByteMemory) (h : Nat) (wR wH : VM) : Prop :=
  wR.env "pathIdx" = t >>> h ∧ wR.env "treeAdrsBase" = ta ∧ wR.env "authPtr" = ap
  ∧ wR.env "N_MASK" = NMASK ∧ wR.env "OUT" = 0x600
  ∧ wH.env "slots" = slotsOf t ∧ wH.env "treeAdrsBase" = ta ∧ wH.env "treeIdx" = t
  ∧ wH.env "authPtr" = ap ∧ wH.env "TB" = 0x80 ∧ wH.env "i" = i
  ∧ (∀ k, k < 32 → wH.mem k = wR.mem k)
  ∧ (∀ k, k < 32 → wH.mem (nodeAt t i h + k) = beByte (wR.env "node") k)
  ∧ (∀ k, 16 ≤ k → k < 32 → beByte (wR.env "node") k = 0)
  ∧ (∀ k, 16 ≤ k → k < 32 → wH.mem (64 + k) = 0 ∧ wH.mem (96 + k) = 0)
  ∧ (∀ a, 128 ≤ a → (a < 0x600 ∨ 0x620 ≤ a) → wR.mem a = mR0 a)
  ∧ (∀ a, 128 ≤ a → (a < 0xC0 + 32 * i ∨ 0xC0 + 32 * i + 16 ≤ a) → wH.mem a = mH0 a)
  ∧ (∀ k, k < 32 → wR.mem k = mR0 k)

set_option maxHeartbeats 8000000 in
/-- **One climb level, related.** Arbitrary hash oracle. The last level (`h = 10`) writes the
    optimized node into the tree's root slot `0xC0 + 32i`, whose low half must be zero at climb
    entry (`hz`). -/
theorem fors_step_rel {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n)
    (t ta ap i : Nat) (mR0 mH0 : ByteMemory) (h : Nat) (wR wH : VM)
    (hh : h < 11) (ht : t < 2048) (hap : ap < 4096) (hi : i < 12)
    (hz : ∀ k, 16 ≤ k → k < 32 → mH0 (0xC0 + 32 * i + k) = 0)
    (hI : FInv t ta ap i mR0 mH0 h wR wH) :
    (execList sha sig forsClimbBody { wR with env := setVar wR.env "h" h }).2 = none
    ∧ (execList sha sig (forsBlk h) wH).2 = none
    ∧ FInv t ta ap i mR0 mH0 (h + 1)
        (execList sha sig forsClimbBody { wR with env := setVar wR.env "h" h }).1
        (execList sha sig (forsBlk h) wH).1 := by
  obtain ⟨hm, hta, hapR, hN, hOUT, hsl, htb, hti, hapH, hTB, hiH, hseed, hnode, hnlo, hpad, hfR, hfH,
    hsR⟩ := hI
  rw [fors_ref_level_eq sha sig wR h t ta ap hh hap hm hta hapR hN hOUT,
    fors_head_level_eq sha sig wH h t ta ap i hh ht hap hi hsl htb hti hapH hTB hiH]
  refine ⟨rfl, rfl, ?_⟩
  have hb := bitOf_le t h
  have hb1 := bitOf_le t (h + 1)
  have hn0 : nodeAt t i h = 64 + 32 * bitOf t h := by unfold nodeAt; rw [if_pos hh]
  have hS := merkle_slice_eq sig wR.mem wH.mem (forsA ta t h) (wR.env "node") (bitOf t h) (ap + 16 * h) hb
    hseed (by rw [← hn0]; exact hnode) hpad
  unfold forsRefLevelOut forsHeadLevelOut
  simp only []
  rw [hS]
  -- where the new optimized node goes
  have hout : nodeAt t i (h + 1) = 64 + 32 * bitOf t (h + 1) ∨
      (h + 1 = 11 ∧ nodeAt t i (h + 1) = 0xC0 + 32 * i) := by
    unfold nodeAt
    by_cases h11 : h + 1 < 11
    · left; rw [if_pos h11]
    · right; exact ⟨by omega, by rw [if_neg h11]⟩
  have houtLo : nodeAt t i (h + 1) + 16 ≤ 128 ∨ 0xC0 + 32 * i = nodeAt t i (h + 1) := by
    rcases hout with e | ⟨_, e⟩
    · left; rw [e]; omega
    · right; exact e.symm
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · dsimp only; exact setVar_get_eq _ _ _
  · dsimp only; simp only [setVar, String.reduceEq, ite_false]; exact hta
  · dsimp only; simp only [setVar, String.reduceEq, ite_false]; exact hapR
  · dsimp only; simp only [setVar, String.reduceEq, ite_false]; exact hN
  · dsimp only; simp only [setVar, String.reduceEq, ite_false]; exact hOUT
  · exact hsl
  · exact htb
  · exact hti
  · exact hapH
  · exact hTB
  · exact hiH
  · intro k hk
    dsimp only
    rw [writeBytes_frame _ _ _ _ _ (by rcases hout with e | ⟨_, e⟩ <;> rw [e] <;> omega),
      mstore32_frame _ 32 _ k (by omega),
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
    · rw [if_neg hk16, writeBytes_frame _ _ _ _ _ (by omega)]
      rcases hout with e | ⟨h11, e⟩
      · rw [e, mstore32_frame _ 32 _ _ (by omega), writeBytes_frame _ _ _ _ _ (by omega)]
        have hp := hpad k (by omega) hk
        have : bitOf t (h + 1) = 0 ∨ bitOf t (h + 1) = 1 := by omega
        rcases this with e' | e' <;> rw [e']
        · simpa using hp.1
        · simpa using hp.2
      · rw [e, mstore32_frame _ 32 _ _ (by omega), writeBytes_frame _ _ _ _ _ (by omega),
          hfH _ (by omega) (Or.inr (by omega))]
        exact hz k (by omega) hk
  · intro k hk16 _
    dsimp only
    simp only [setVar, String.reduceEq, ite_false, ite_true]
    exact beByte_masked_low _ k hk16
  · intro k hk1 hk2
    dsimp only
    have hp := hpad k hk1 hk2
    constructor
    · rw [writeBytes_frame _ _ _ _ _ (by rcases hout with e | ⟨_, e⟩ <;> rw [e] <;> omega),
        mstore32_frame _ 32 _ _ (by omega), writeBytes_frame _ _ _ _ _ (by omega)]
      exact hp.1
    · rw [writeBytes_frame _ _ _ _ _ (by rcases hout with e | ⟨_, e⟩ <;> rw [e] <;> omega),
        mstore32_frame _ 32 _ _ (by omega), writeBytes_frame _ _ _ _ _ (by omega)]
      exact hp.2
  · intro a ha hout'
    dsimp only
    rw [writeRegion_frame _ _ _ _ (by omega), mstore32_frame _ _ _ a (by omega),
      mstore32_frame _ _ _ a (by omega), mstore32_frame _ 32 _ a (by omega)]
    exact hfR a ha hout'
  · intro a ha ha'
    dsimp only
    rw [writeBytes_frame _ _ _ _ _ (by rcases hout with e | ⟨_, e⟩ <;> rw [e] <;> omega),
      mstore32_frame _ 32 _ a (by omega), writeBytes_frame _ _ _ _ _ (by omega)]
    exact hfH a ha ha'
  · intro k hk
    dsimp only
    rw [writeRegion_frame _ _ _ _ (by omega), mstore32_frame _ _ _ k (by omega),
      mstore32_frame _ _ _ k (by omega), mstore32_frame _ 32 _ k (by omega)]
    exact hsR k hk

set_option maxHeartbeats 4000000 in
/-- **The climb of one FORS tree, related.** The reference's `forRange "h" 11 forsClimbBody` and
    the optimized `forsBlk 0 … forsBlk 10`, from states coupled at level 0, both fall through and
    leave the reference's final `node` with exactly the 32 bytes the optimized v1 leaves in the
    tree's root slot `0xC0 + 32i`. The full coupling at level 11 and the env frames are exported. -/
theorem fors_climb_rel {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n)
    (t ta ap i : Nat) (vR vH : VM) (ht : t < 2048) (hap : ap < 4096) (hi : i < 12)
    (hz : ∀ k, 16 ≤ k → k < 32 → vH.mem (0xC0 + 32 * i + k) = 0)
    (hI : FInv t ta ap i vR.mem vH.mem 0 vR vH) :
    (execStmt sha sig (.forRange "h" (.lit 11) forsClimbBody) vR).2 = none
    ∧ (execList sha sig ((List.range 11).flatMap forsBlk) vH).2 = none
    ∧ FInv t ta ap i vR.mem vH.mem 11 (execStmt sha sig (.forRange "h" (.lit 11) forsClimbBody) vR).1
        (execList sha sig ((List.range 11).flatMap forsBlk) vH).1
    ∧ (∀ x, x ≠ "h" → x ≠ "sibling" → x ≠ "parentIdx" → x ≠ "s" → x ≠ "node" → x ≠ "pathIdx" →
        (execStmt sha sig (.forRange "h" (.lit 11) forsClimbBody) vR).1.env x = vR.env x)
    ∧ (∀ x, (execList sha sig ((List.range 11).flatMap forsBlk) vH).1.env x = vH.env x) := by
  have henvR : ∀ x, x ≠ "h" → x ≠ "sibling" → x ≠ "parentIdx" → x ≠ "s" → x ≠ "node" → x ≠ "pathIdx" →
      (execStmt sha sig (.forRange "h" (.lit 11) forsClimbBody) vR).1.env x = vR.env x := by
    intro x a1 a2 a3 a4 a5 a6
    simp only [execStmt, eval]
    exact execFor_env_frame sha sig "h" forsClimbBody x (Ne.symm a1)
      (by unfold forsClimbBody; simp [assignsVarList, assignsVar]
          exact ⟨Ne.symm a2, Ne.symm a3, Ne.symm a4, Ne.symm a5, Ne.symm a6⟩) _ _ _
  have henvH : ∀ x, (execList sha sig ((List.range 11).flatMap forsBlk) vH).1.env x = vH.env x := by
    intro x
    exact execList_env_frame sha sig _ x vH
      (by simp [List.range_succ, forsBlk, assignsVarList, assignsVar])
  simp only [execStmt, eval]
  simp only [execStmt, eval] at henvR
  rw [List.range_eq_range'] at henvH ⊢
  have r := execFor_vs_blocks sha sig "h" forsClimbBody forsBlk 11 (FInv t ta ap i vR.mem vH.mem)
    (fun h w1 w2 hh hI' => fors_step_rel sha sig t ta ap i vR.mem vH.mem h w1 w2 hh ht hap hi hz hI')
    11 0 vR vH (by omega) hI
  obtain ⟨hnR, hnH, hfin⟩ := r
  exact ⟨hnR, hnH, hfin, henvR, henvH⟩

/-! ## 5. One tree's opening, executed -/

def tVal (e : VarEnv) : Nat := (e "dVal" >>> ((e "i" * 11) % W)) &&& 2047
def sVal {n : Nat} (sig : ByteVec n) (e : VarEnv) : Nat :=
  calldataload sig ((e "sigBase" + (16 + (e "i" <<< 4) % W) % W) % W) &&& e "N_MASK"
def lVal (e : VarEnv) : Nat :=
  (e "htIdx" <<< 160) % W ||| ((3 <<< 128) % W ||| ((e "i" <<< 96) % W ||| tVal e))
def taVal' (e : VarEnv) : Nat :=
  (e "htIdx" <<< 160) % W ||| ((3 <<< 128) % W ||| (e "i" <<< 96) % W)
def apVal (e : VarEnv) : Nat := (e "sigBase" + (224 + (e "i" * 176) % W) % W) % W

theorem treeOpen_eval {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (w : VM) :
    execList sha sig treeOpen w
      = ({ mem := mstore32 (mstore32 w.mem 32 (lVal w.env)) 64 (sVal sig w.env),
           env := setVar (setVar (setVar w.env "treeIdx" (tVal w.env)) "secretVal" (sVal sig w.env))
             "leafAdrs" (lVal w.env) }, none) := by
  unfold treeOpen treeIdxS secretS leafAdrsS
  repeat rw [execList_cons_none sha sig _ _ _ (by simp only [execStmt])]
  simp only [execList, execStmt, eval]
  simp (disch := decide) only [setVar_get_eq, setVar_get_ne]
  rfl

def refTreeMid : List Stmt :=
  [ .sha256 (.lit 0) (.lit 96) (.var "OUT"), .letv "node" (.bin .band (.mload (.var "OUT")) (.var "N_MASK"))
  , tabS, .letv "pathIdx" (.var "treeIdx"), authS ]

def headTreeMid : List Stmt := [ .sha256h (.lit 0) (.lit 96) (.bin .byte (.lit 1) (.var "slots")), tabS, authS ]

theorem refTreeBody_split : refTreeBody = treeOpen ++ (refTreeMid ++ [ .forRange "h" (.lit 11) forsClimbBody,
    .mstore (.bin .add (.lit 128) (.bin .shl (.lit 5) (.var "i"))) (.var "node") ]) := rfl

theorem headTreeBody_split : headTreeBody = treeOpen ++ (forsSlotsSetup ++ (headTreeMid
    ++ (List.range 11).flatMap forsBlk)) := rfl

set_option maxHeartbeats 8000000 in
/-- The reference tree opening through `authPtr`: the leaf hash of `M[0, 96)` (`M` after the two
    stores) into `node`, and the climb's bindings. -/
theorem ref_tree_pre {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (w : VM)
    (hOUT : w.env "OUT" = 0x600) :
    (execList sha sig (treeOpen ++ refTreeMid) w).2 = none
    ∧ (execList sha sig (treeOpen ++ refTreeMid) w).1.mem
        = writeRegion (mstore32 (mstore32 w.mem 32 (lVal w.env)) 64 (sVal sig w.env)) 0x600
            (fun j => (sha (slice (mstore32 (mstore32 w.mem 32 (lVal w.env)) 64 (sVal sig w.env)) 0 96)).data.getD j 0)
    ∧ (execList sha sig (treeOpen ++ refTreeMid) w).1.env "node"
        = wordOf (sha (slice (mstore32 (mstore32 w.mem 32 (lVal w.env)) 64 (sVal sig w.env)) 0 96)) &&& w.env "N_MASK"
    ∧ (execList sha sig (treeOpen ++ refTreeMid) w).1.env "pathIdx" = tVal w.env
    ∧ (execList sha sig (treeOpen ++ refTreeMid) w).1.env "treeAdrsBase" = taVal' w.env
    ∧ (execList sha sig (treeOpen ++ refTreeMid) w).1.env "authPtr" = apVal w.env
    ∧ (∀ x, x ≠ "treeIdx" → x ≠ "secretVal" → x ≠ "leafAdrs" → x ≠ "node" → x ≠ "treeAdrsBase" →
        x ≠ "pathIdx" → x ≠ "authPtr" → (execList sha sig (treeOpen ++ refTreeMid) w).1.env x = w.env x) := by
  rw [app_none _ _ _ _ _ (by rw [treeOpen_eval]), treeOpen_eval]
  unfold refTreeMid tabS authS
  repeat rw [execList_cons_none sha sig _ _ _ (by simp only [execStmt])]
  simp only [execList, execStmt, eval]
  simp (disch := decide) only [setVar_get_eq, setVar_get_ne, hOUT]
  refine ⟨trivial, by first | rfl | trivial, ?_, by first | rfl | trivial, by first | rfl | trivial,
    by first | rfl | trivial, ?_⟩
  · rw [mload32_digest]
  · intro x a1 a2 a3 a4 a5 a6 a7
    simp only [setVar_get_ne _ _ _ _ a7, setVar_get_ne _ _ _ _ a6, setVar_get_ne _ _ _ _ a5,
      setVar_get_ne _ _ _ _ a4, setVar_get_ne _ _ _ _ a3, setVar_get_ne _ _ _ _ a2, setVar_get_ne _ _ _ _ a1]

theorem forsSlotsSetup_eval {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (vm : VM) :
    (execList sha sig forsSlotsSetup vm).2 = none
    ∧ (execList sha sig forsSlotsSetup vm).1.env "slots" = slotsOf (vm.env "treeIdx")
    ∧ (execList sha sig forsSlotsSetup vm).1.mem = vm.mem := by
  unfold forsSlotsSetup
  rw [execList_cons_none sha sig _ _ _ (by simp only [execStmt]),
    execList_cons_none sha sig _ _ _ (by simp only [execStmt]), execList_single]
  refine ⟨by simp only [execStmt], ?_, by simp only [execStmt]⟩
  simp only [execStmt]
  rw [setVar_get_eq]
  simp only [eval]
  rw [setVar_get_eq, setVar_get_eq]
  rfl

theorem tVal_lt (e : VarEnv) : tVal e < 2048 := by
  unfold tVal; exact Nat.lt_of_le_of_lt Nat.and_le_right (by decide)

set_option maxHeartbeats 8000000 in
/-- The optimized tree opening through `authPtr`: the slot word, and the leaf hash of `M[0, 96)`
    written as 16 bytes into the leaf's node slot `0x40 + 32·bit_0`. -/
theorem head_tree_pre {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (w : VM) :
    (execList sha sig (treeOpen ++ (forsSlotsSetup ++ headTreeMid)) w).2 = none
    ∧ (execList sha sig (treeOpen ++ (forsSlotsSetup ++ headTreeMid)) w).1.mem
        = writeBytes (mstore32 (mstore32 w.mem 32 (lVal w.env)) 64 (sVal sig w.env))
            (64 + 32 * bitOf (tVal w.env) 0) 16
            (fun j => (sha (slice (mstore32 (mstore32 w.mem 32 (lVal w.env)) 64 (sVal sig w.env)) 0 96)).data.getD j 0)
    ∧ (execList sha sig (treeOpen ++ (forsSlotsSetup ++ headTreeMid)) w).1.env "slots" = slotsOf (tVal w.env)
    ∧ (execList sha sig (treeOpen ++ (forsSlotsSetup ++ headTreeMid)) w).1.env "treeIdx" = tVal w.env
    ∧ (execList sha sig (treeOpen ++ (forsSlotsSetup ++ headTreeMid)) w).1.env "treeAdrsBase" = taVal' w.env
    ∧ (execList sha sig (treeOpen ++ (forsSlotsSetup ++ headTreeMid)) w).1.env "authPtr" = apVal w.env
    ∧ (∀ x, x ≠ "treeIdx" → x ≠ "secretVal" → x ≠ "leafAdrs" → x ≠ "t" → x ≠ "sbit" → x ≠ "slots" →
        x ≠ "treeAdrsBase" → x ≠ "authPtr" →
        (execList sha sig (treeOpen ++ (forsSlotsSetup ++ headTreeMid)) w).1.env x = w.env x) := by
  rw [app_none _ _ _ _ _ (by rw [treeOpen_eval])]
  have hA := treeOpen_eval sha sig w
  generalize hvA : (execList sha sig treeOpen w).1 = vA
  have eA : ∀ x, x ≠ "treeIdx" → x ≠ "secretVal" → x ≠ "leafAdrs" → vA.env x = w.env x := by
    intro x a b c; rw [← hvA, hA]; simp only
    rw [setVar_get_ne _ _ _ _ c, setVar_get_ne _ _ _ _ b, setVar_get_ne _ _ _ _ a]
  have eT : vA.env "treeIdx" = tVal w.env := by
    rw [← hvA, hA]; simp (disch := decide) only [setVar_get_eq, setVar_get_ne]
  have mA : vA.mem = mstore32 (mstore32 w.mem 32 (lVal w.env)) 64 (sVal sig w.env) := by rw [← hvA, hA]
  obtain ⟨s0, sSl, sM⟩ := forsSlotsSetup_eval sha sig vA
  have fS : ∀ x, assignsVarList forsSlotsSetup x = false →
      (execList sha sig forsSlotsSetup vA).1.env x = vA.env x :=
    fun x hx => execList_env_frame _ _ _ _ _ hx
  rw [app_none _ _ _ _ _ s0]
  generalize hvB : (execList sha sig forsSlotsSetup vA).1 = vB at sSl sM fS
  have bL : ∀ x, x ≠ "treeIdx" → x ≠ "secretVal" → x ≠ "leafAdrs" → x ≠ "t" → x ≠ "sbit" → x ≠ "slots" →
      vB.env x = w.env x := by
    intro x a1 a2 a3 a4 a5 a6
    have hx : assignsVarList forsSlotsSetup x = false := by
      unfold forsSlotsSetup; simp [assignsVarList, assignsVar, Ne.symm a4, Ne.symm a5, Ne.symm a6]
    rw [fS _ hx, eA _ a1 a2 a3]
  have bT : vB.env "treeIdx" = tVal w.env := by rw [fS _ (by decide), eT]
  have bSl : vB.env "slots" = slotsOf (tVal w.env) := by rw [sSl, eT]
  have hout : byteAt 1 (slotsOf (tVal w.env)) = 64 + 32 * bitOf (tVal w.env) 0 :=
    (fors_slots_decode _ (tVal_lt _) 0 (by decide)).2
  unfold headTreeMid tabS authS
  repeat rw [execList_cons_none sha sig _ _ _ (by simp only [execStmt])]
  simp only [execList, execStmt, eval, bSl, byteAt_unfold, hout]
  have bH := bL "htIdx" (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
  have bI := bL "i" (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
  have bS := bL "sigBase" (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
  refine ⟨trivial, by rw [sM, mA], ?_, ?_, ?_, ?_, ?_⟩
  · simp (disch := decide) only [setVar_get_eq, setVar_get_ne, bSl]
  · simp (disch := decide) only [setVar_get_eq, setVar_get_ne, bT]
  · simp (disch := decide) only [setVar_get_eq, setVar_get_ne, bH, bI]; rfl
  · simp (disch := decide) only [setVar_get_eq, setVar_get_ne, bS, bI]; rfl
  · intro x a1 a2 a3 a4 a5 a6 a7 a8
    simp only [setVar_get_ne _ _ _ _ a8, setVar_get_ne _ _ _ _ a7]
    exact bL x a1 a2 a3 a4 a5 a6

/-! ## 6. One tree -/

/-- The coupling between FORS trees, after `j` trees: the roots so far equal (reference at
    `0x80 + 32t`, optimized at `0xC0 + 32t`), the optimized future root slots' low halves zero. -/
structure TreeInv (j : Nat) (vR vH : VM) : Prop where
  dv : vH.env "dVal" = vR.env "dVal"
  ht : vH.env "htIdx" = vR.env "htIdx"
  ht18 : vR.env "htIdx" < 2 ^ 18
  sbR : vR.env "sigBase" = 0
  sbH : vH.env "sigBase" = 0
  seed : vH.env "seed" = vR.env "seed"
  root : vH.env "root" = vR.env "root"
  rN : vR.env "N_MASK" = NMASK
  rOUT : vR.env "OUT" = 0x600
  hN : vH.env "N_MASK" = NMASK
  hTB : vH.env "TB" = 0x80
  hOUT : vH.env "OUT" = 0x620
  seedR : ∀ k, k < 32 → vR.mem k = beByte (vR.env "seed") k
  seedH : ∀ k, k < 32 → vH.mem k = beByte (vR.env "seed") k
  tb : ∀ k, k < 32 → vH.mem (0x80 + k) = beByte (vR.env "seed") k
  pad70 : ∀ k, 16 ≤ k → k < 32 → vH.mem (96 + k) = 0
  roots : ∀ t, t < j → ∀ k, k < 32 → vR.mem (0x80 + 32 * t + k) = vH.mem (0xC0 + 32 * t + k)
  lowFut : ∀ t, j ≤ t → t < 13 → ∀ k, 16 ≤ k → k < 32 → vH.mem (0xC0 + 32 * t + k) = 0

set_option maxHeartbeats 32000000 in
/-- **One FORS tree, related.** With the loop's `i := j` bound, both tree bodies fall through and
    add root `j` to the coupling. Arbitrary hash oracle. -/
theorem tree_step {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (j : Nat) (hj : j < 12)
    (vR vH : VM) (hI : TreeInv j vR vH) :
    (execList sha sig refTreeBody { vR with env := setVar vR.env "i" j }).2 = none
    ∧ (execList sha sig headTreeBody { vH with env := setVar vH.env "i" j }).2 = none
    ∧ TreeInv (j + 1) (execList sha sig refTreeBody { vR with env := setVar vR.env "i" j }).1
        (execList sha sig headTreeBody { vH with env := setVar vH.env "i" j }).1 := by
  generalize hwR : ({ vR with env := setVar vR.env "i" j } : VM) = wR
  generalize hwH : ({ vH with env := setVar vH.env "i" j } : VM) = wH
  have gR : ∀ x, x ≠ "i" → wR.env x = vR.env x := by intro x hx; rw [← hwR]; exact setVar_get_ne _ _ _ _ hx
  have gH : ∀ x, x ≠ "i" → wH.env x = vH.env x := by intro x hx; rw [← hwH]; exact setVar_get_ne _ _ _ _ hx
  have iR : wR.env "i" = j := by rw [← hwR]; exact setVar_get_eq vR.env "i" j
  have iH : wH.env "i" = j := by rw [← hwH]; exact setVar_get_eq vH.env "i" j
  have mR : wR.mem = vR.mem := by rw [← hwR]
  have mH : wH.mem = vH.mem := by rw [← hwH]
  -- the values both openings compute
  have eT : tVal wH.env = tVal wR.env := by unfold tVal; rw [iR, iH, gR _ (by decide), gH _ (by decide), hI.dv]
  have eS : sVal sig wH.env = sVal sig wR.env := by
    unfold sVal
    simp only [iR, iH, gR "sigBase" (by decide), gH "sigBase" (by decide), hI.sbR, hI.sbH,
      gR "N_MASK" (by decide), gH "N_MASK" (by decide), hI.rN, hI.hN]
  have eL : lVal wH.env = lVal wR.env := by
    unfold lVal; rw [eT, iR, iH, gR _ (by decide), gH _ (by decide), hI.ht]
  have eTA : taVal' wH.env = taVal' wR.env := by
    unfold taVal'; rw [iR, iH, gR _ (by decide), gH _ (by decide), hI.ht]
  have eAP : apVal wR.env = 224 + 176 * j := by
    unfold apVal; rw [iR, gR _ (by decide), hI.sbR, Nat.zero_add, Nat.mul_comm,
      Nat.mod_eq_of_lt (lt_W_of_lt (show 176 * j < 4096 by omega)),
      Nat.mod_eq_of_lt (lt_W_of_lt (show 224 + 176 * j < 4096 by omega)),
      Nat.mod_eq_of_lt (lt_W_of_lt (show 224 + 176 * j < 4096 by omega))]
  have eAPH : apVal wH.env = apVal wR.env := by
    unfold apVal; rw [iR, iH, gR _ (by decide), gH _ (by decide), hI.sbR, hI.sbH]
  have hSlow : ∀ k, 16 ≤ k → k < 32 → beByte (sVal sig wR.env) k = 0 := by
    intro k h1 _; unfold sVal; rw [gR "N_MASK" (by decide), hI.rN]; exact beByte_masked_low _ _ h1
  -- the two hash inputs of the leaf
  generalize hMR : mstore32 (mstore32 wR.mem 32 (lVal wR.env)) 64 (sVal sig wR.env) = MR
  generalize hMH : mstore32 (mstore32 wH.mem 32 (lVal wH.env)) 64 (sVal sig wH.env) = MH
  have hMRlo : ∀ a, 96 ≤ a → MR a = vR.mem a := by
    intro a ha; rw [← hMR, mstore32_frame _ 64 _ a (by omega), mstore32_frame _ 32 _ a (by omega), mR]
  have hMHlo : ∀ a, 96 ≤ a → MH a = vH.mem a := by
    intro a ha; rw [← hMH, mstore32_frame _ 64 _ a (by omega), mstore32_frame _ 32 _ a (by omega), mH]
  have hMseed : ∀ k, k < 32 → MH k = MR k := by
    intro k hk
    rw [← hMR, ← hMH, mstore32_frame _ 64 _ k (by omega), mstore32_frame _ 32 _ k (by omega),
      mstore32_frame _ 64 _ k (by omega), mstore32_frame _ 32 _ k (by omega), mR, mH, hI.seedR k hk,
      hI.seedH k hk]
  have hMRseed : ∀ k, k < 32 → MR k = beByte (vR.env "seed") k := by
    intro k hk; rw [← hMR, mstore32_frame _ 64 _ k (by omega), mstore32_frame _ 32 _ k (by omega), mR,
      hI.seedR k hk]
  have hMH64 : ∀ k, k < 32 → MH (64 + k) = beByte (sVal sig wR.env) k := by
    intro k hk; rw [← hMH, mstore32_get _ _ _ _ hk, eS]
  have hslice : slice MH 0 96 = slice MR 0 96 := by
    apply slice_congr
    intro i hi
    rw [Nat.zero_add]
    by_cases h32 : i < 32
    · exact hMseed i h32
    · rw [← hMR, ← hMH, eL, eS]
      by_cases h64 : i < 64
      · rw [mstore32_frame _ 64 _ i (by omega), mstore32_frame _ 64 _ i (by omega),
          show i = 32 + (i - 32) by omega, mstore32_get _ _ _ _ (by omega), mstore32_get _ _ _ _ (by omega)]
      · rw [show i = 64 + (i - 64) by omega, mstore32_get _ _ _ _ (by omega), mstore32_get _ _ _ _ (by omega)]
  -- the two openings
  obtain ⟨p0, pM, pN, pP, pTA, pAP, pF⟩ := ref_tree_pre sha sig wR (by rw [gR _ (by decide), hI.rOUT])
  obtain ⟨q0, qM, qSl, qT, qTA, qAP, qF⟩ := head_tree_pre sha sig wH
  rw [hMR] at pM pN
  rw [hMH] at qM
  rw [refTreeBody_split, ← List.append_assoc, app_none _ _ _ _ _ p0]
  rw [headTreeBody_split, show treeOpen ++ (forsSlotsSetup ++ (headTreeMid ++ (List.range 11).flatMap forsBlk))
    = (treeOpen ++ (forsSlotsSetup ++ headTreeMid)) ++ (List.range 11).flatMap forsBlk by
      simp only [List.append_assoc], app_none _ _ _ _ _ q0]
  generalize hr1 : (execList sha sig (treeOpen ++ refTreeMid) wR).1 = r1 at pM pN pP pTA pAP pF
  generalize hh1 : (execList sha sig (treeOpen ++ (forsSlotsSetup ++ headTreeMid)) wH).1 = h1
    at qM qSl qT qTA qAP qF
  -- the climb entry coupling
  have hb := bitOf_le (tVal wR.env) 0
  have hn0 : nodeAt (tVal wR.env) j 0 = 64 + 32 * bitOf (tVal wR.env) 0 := by unfold nodeAt; rw [if_pos (by decide)]
  have hI0 : FInv (tVal wR.env) (taVal' wR.env) (apVal wR.env) j r1.mem h1.mem 0 r1 h1 := by
    refine ⟨by rw [pP, Nat.shiftRight_zero], pTA, pAP, by rw [pF _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), gR _ (by decide), hI.rN],
      by rw [pF _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), gR _ (by decide), hI.rOUT], by rw [qSl, eT], by rw [qTA, eTA], by rw [qT, eT],
      by rw [qAP, eAPH], by rw [qF _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), gH _ (by decide), hI.hTB], by rw [qF _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), iH], ?_, ?_, ?_, ?_,
      fun _ _ _ => rfl, fun _ _ _ => rfl, fun _ _ => rfl⟩
    · intro k hk
      rw [qM, writeBytes_frame _ _ _ _ _ (by omega), pM, writeRegion_frame _ _ _ _ (by omega)]
      exact hMseed k hk
    · intro k hk
      rw [hn0, pN, gR _ (by decide), hI.rN, beByte_and_nmask]
      by_cases h16 : k < 16
      · rw [qM, eT, writeBytes_get _ _ _ _ _ (by omega), if_pos h16, beByte_wordOf_getD _ _ hk, hslice]
        congr 1; omega
      · rw [if_neg h16, qM, eT, writeBytes_frame _ _ _ _ _ (by omega)]
        rcases (by omega : bitOf (tVal wR.env) 0 = 0 ∨ bitOf (tVal wR.env) 0 = 1) with e | e
        · rw [e, show 64 + 32 * 0 + k = 64 + k by omega, hMH64 k hk]; exact hSlow k (by omega) hk
        · rw [e, show 64 + 32 * 1 + k = 96 + k by omega, hMHlo _ (by omega)]; exact hI.pad70 k (by omega) hk
    · intro k h1' h2'
      rw [pN, gR _ (by decide), hI.rN]; exact beByte_masked_low _ _ h1'
    · intro k h1' h2'
      constructor
      · rw [qM, eT, writeBytes_frame _ _ _ _ _ (by omega), hMH64 k h2']; exact hSlow k h1' h2'
      · rw [qM, eT, writeBytes_frame _ _ _ _ _ (by omega), hMHlo _ (by omega)]; exact hI.pad70 k h1' h2'
  have hz : ∀ k, 16 ≤ k → k < 32 → h1.mem (0xC0 + 32 * j + k) = 0 := by
    intro k h1' h2'
    rw [qM, writeBytes_frame _ _ _ _ _ (by omega), hMHlo _ (by omega)]
    exact hI.lowFut j (Nat.le_refl j) (by omega) k h1' h2'
  obtain ⟨c0, c0', cI, cR, cH⟩ := fors_climb_rel sha sig (tVal wR.env) (taVal' wR.env) (apVal wR.env) j r1 h1
    (tVal_lt _) (by rw [eAP]; omega) hj hz hI0
  rw [execList_cons_none _ _ _ _ _ c0]
  generalize hr2 : (execStmt sha sig (.forRange "h" (.lit 11) forsClimbBody) r1).1 = r2 at cI cR
  generalize hh2 : (execList sha sig ((List.range 11).flatMap forsBlk) h1).1 = h2 at cI cH
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, kSeed, kNode, kLow, kPad, kFR, kFH, kSR⟩ := cI
  have r2i : r2.env "i" = j := by rw [cR _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), pF _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), iR]
  refine ⟨?_, c0', ?_⟩
  · rw [execList_single]; simp only [execStmt]
  rw [execList_single]
  simp only [execStmt, eval, r2i, shl5_small j (by omega)]
  rw [Nat.mod_eq_of_lt (lt_W_of_lt (show 128 + 32 * j < 4096 by omega))]
  -- env carried through the tree
  have fR : ∀ x, x ≠ "i" → x ≠ "treeIdx" → x ≠ "secretVal" → x ≠ "leafAdrs" → x ≠ "node" →
      x ≠ "treeAdrsBase" → x ≠ "pathIdx" → x ≠ "authPtr" → x ≠ "h" → x ≠ "sibling" → x ≠ "parentIdx" →
      x ≠ "s" → r2.env x = vR.env x := by
    intro x a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 a10 a11
    rw [cR x a8 a9 a10 a11 a4 a6, pF x a1 a2 a3 a4 a5 a6 a7, gR x a0]
  have fH : ∀ x, x ≠ "i" → x ≠ "treeIdx" → x ≠ "secretVal" → x ≠ "leafAdrs" → x ≠ "t" → x ≠ "sbit" →
      x ≠ "slots" → x ≠ "treeAdrsBase" → x ≠ "authPtr" → h2.env x = vH.env x := by
    intro x a0 a1 a2 a3 a4 a5 a6 a7 a8
    rw [cH x, qF x a1 a2 a3 a4 a5 a6 a7 a8, gH x a0]
  have nodeAt11 : nodeAt (tVal wR.env) j 11 = 0xC0 + 32 * j := by unfold nodeAt; rw [if_neg (by decide)]
  have sR := fR "seed" (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
    (by decide) (by decide) (by decide) (by decide) (by decide)
  constructor
  · rw [fH _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
      (by decide), fR _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
      (by decide) (by decide) (by decide) (by decide) (by decide)]; exact hI.dv
  · rw [fH _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
      (by decide), fR _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
      (by decide) (by decide) (by decide) (by decide) (by decide)]; exact hI.ht
  · rw [fR _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
      (by decide) (by decide) (by decide) (by decide) (by decide)]; exact hI.ht18
  · rw [fR _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
      (by decide) (by decide) (by decide) (by decide) (by decide)]; exact hI.sbR
  · rw [fH _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
      (by decide)]; exact hI.sbH
  · rw [fH _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
      (by decide), sR]; exact hI.seed
  · rw [fH _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
      (by decide), fR _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
      (by decide) (by decide) (by decide) (by decide) (by decide)]; exact hI.root
  · rw [fR _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
      (by decide) (by decide) (by decide) (by decide) (by decide)]; exact hI.rN
  · rw [fR _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
      (by decide) (by decide) (by decide) (by decide) (by decide)]; exact hI.rOUT
  · rw [fH _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
      (by decide)]; exact hI.hN
  · rw [fH _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
      (by decide)]; exact hI.hTB
  · rw [fH _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)
      (by decide)]; exact hI.hOUT
  · intro k hk
    dsimp only
    rw [mstore32_frame _ _ _ k (by omega), kSR k hk, pM, writeRegion_frame _ _ _ _ (by omega), sR]
    exact hMRseed k hk
  · intro k hk
    dsimp only
    rw [kSeed k hk, kSR k hk, pM, writeRegion_frame _ _ _ _ (by omega), sR]
    exact hMRseed k hk
  · intro k hk
    dsimp only
    rw [kFH (0x80 + k) (by omega) (Or.inl (by omega)), qM, eT, writeBytes_frame _ _ _ _ _ (by omega),
      hMHlo _ (by omega), sR]
    exact hI.tb k hk
  · intro k h1' h2'
    exact (kPad k h1' h2').2
  · intro t ht k hk
    dsimp only
    by_cases htj : t < j
    · rw [mstore32_frame _ _ _ _ (by omega), kFR _ (by omega) (Or.inl (by omega)), pM,
        writeRegion_frame _ _ _ _ (by omega), hMRlo _ (by omega),
        kFH _ (by omega) (Or.inl (by omega)), qM, eT, writeBytes_frame _ _ _ _ _ (by omega),
        hMHlo _ (by omega)]
      exact hI.roots t htj k hk
    · have : t = j := by omega
      subst this
      rw [show 0x80 + 32 * t + k = 128 + 32 * t + k by omega, mstore32_get _ _ _ _ hk]
      have := kNode k hk
      rw [nodeAt11] at this
      exact this.symm
  · intro t ht1 ht2 k h1' h2'
    dsimp only
    rw [kFH _ (by omega) (Or.inr (by omega)), qM, eT, writeBytes_frame _ _ _ _ _ (by omega),
      hMHlo _ (by omega)]
    exact hI.lowFut t (by omega) ht2 k h1' h2'

/-! ## 7. The 12 trees -/

set_option maxHeartbeats 8000000 in
/-- The optimized prologue (`mstore(TB, seed)`, `mstore(0x60, 0)`) gives `TreeInv 0` from
    `HmsgExit`. -/
theorem fors_prologue {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (r h : VM)
    (hX : HmsgExit r h) :
    execList sha sig [ .mstore (.var "TB") (.var "seed"), .mstore (.lit 96) (.lit 0) ] h
      = ({ mem := mstore32 (mstore32 h.mem 0x80 (h.env "seed")) 96 0, env := h.env }, none)
    ∧ TreeInv 0 r { mem := mstore32 (mstore32 h.mem 0x80 (h.env "seed")) 96 0, env := h.env } := by
  refine ⟨?_, ?_⟩
  · rw [execList_cons_none _ _ _ _ _ (by simp only [execStmt]), execList_single]
    simp only [execStmt, eval, hX.hTB]
  · refine ⟨hX.dv, hX.ht, hX.ht18, hX.sbR, hX.sbH, hX.seed, hX.root, hX.rN, hX.rOUT, hX.hN, hX.hTB, hX.hOUT,
      hX.seedMemR, ?_, ?_, ?_, fun t ht => absurd ht (Nat.not_lt_zero t), ?_⟩
    · intro k hk; dsimp only
      rw [mstore32_frame _ 96 _ k (by omega), mstore32_frame _ 0x80 _ k (by omega)]; exact hX.seedMemH k hk
    · intro k hk; dsimp only
      rw [mstore32_frame _ 96 _ _ (by omega), mstore32_get _ _ _ _ hk, hX.seed]
    · intro k h1 h2; dsimp only
      rw [mstore32_get _ _ _ _ h2, beByte_small 0 k (by decide) h2]; split <;> rfl
    · intro t _ ht k h1 h2; dsimp only
      rw [mstore32_frame _ 96 _ _ (by omega), mstore32_frame _ 0x80 _ _ (by omega)]
      exact hX.zeroH _ (by omega) (by omega)

/-- **The 12 trees.** -/
theorem fors_trees {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (vR vH : VM)
    (hI : TreeInv 0 vR vH) :
    (execStmt sha sig (.forRange "i" (.lit 12) refTreeBody) vR).2 = none
    ∧ (execStmt sha sig (.forRange "i" (.lit 12) headTreeBody) vH).2 = none
    ∧ TreeInv 12 (execStmt sha sig (.forRange "i" (.lit 12) refTreeBody) vR).1
        (execStmt sha sig (.forRange "i" (.lit 12) headTreeBody) vH).1 := by
  simp only [execStmt, eval]
  have r := execFor_rel sha sig "i" refTreeBody "i" headTreeBody 0 12 TreeInv
    (fun c w1 w2 hc hw => by rw [Nat.zero_add]; exact tree_step sha sig c hc w1 w2 hw) 12 0 vR vH rfl hI
  simpa using r

/-! ## 8. The last tree, the root compression -/

def lsVal {n : Nat} (sig : ByteVec n) (e : VarEnv) : Nat :=
  calldataload sig ((e "sigBase" + (16 + (12 <<< 4) % W) % W) % W) &&& e "N_MASK"
def laVal (e : VarEnv) : Nat := (e "htIdx" <<< 160) % W ||| ((3 <<< 128) % W ||| (12 <<< 96) % W)
def raVal (e : VarEnv) : Nat := (e "htIdx" <<< 160) % W ||| (4 <<< 128) % W

theorem refLast_eval {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (w : VM)
    (hOUT : w.env "OUT" = 0x600) :
    execStmt sha sig (.block refLast) w
      = ({ mem := mstore32 (writeRegion (mstore32 (mstore32 w.mem 32 (laVal w.env)) 64 (lsVal sig w.env)) 0x600
              (fun j => (sha (slice (mstore32 (mstore32 w.mem 32 (laVal w.env)) 64 (lsVal sig w.env)) 0 96)).data.getD j 0))
            512 (wordOf (sha (slice (mstore32 (mstore32 w.mem 32 (laVal w.env)) 64 (lsVal sig w.env)) 0 96)) &&& w.env "N_MASK"),
           env := setVar w.env "lastSecret" (lsVal sig w.env) }, none) := by
  simp only [execStmt]
  unfold refLast lastSecretS lastAdrsE
  repeat rw [execList_cons_none sha sig _ _ _ (by simp only [execStmt])]
  simp only [execList, execStmt, eval]
  simp (disch := decide) only [setVar_get_eq, setVar_get_ne, hOUT]
  rw [mload32_digest]
  rfl

theorem headLast_eval {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (w : VM)
    (hTB : w.env "TB" = 0x80) :
    execStmt sha sig (.block headLast) w
      = ({ mem := writeBytes (mstore32 (mstore32 w.mem 32 (laVal w.env)) 64 (lsVal sig w.env)) 0x240 16
              (fun j => (sha (slice (mstore32 (mstore32 w.mem 32 (laVal w.env)) 64 (lsVal sig w.env)) 0 96)).data.getD j 0),
           env := setVar w.env "lastSecret" (lsVal sig w.env) }, none) := by
  simp only [execStmt]
  unfold headLast lastSecretS lastAdrsE
  repeat rw [execList_cons_none sha sig _ _ _ (by simp only [execStmt])]
  simp only [execList, execStmt, eval]
  simp (disch := decide) only [setVar_get_eq, setVar_get_ne, hTB]
  rfl

set_option maxHeartbeats 8000000 in
/-- The 13-record copy (the 43-record one restricted). -/
theorem copy_loop13 {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (vm : VM) :
    (execFor sha sig "i" forsCopyBody 13 0 vm).2 = none
    ∧ (∀ t, t < 13 → ∀ k, k < 32 →
        (execFor sha sig "i" forsCopyBody 13 0 vm).1.mem (0x40 + 32 * t + k) = vm.mem (0x80 + 32 * t + k))
    ∧ (∀ a, a < 0x40 → (execFor sha sig "i" forsCopyBody 13 0 vm).1.mem a = vm.mem a) := by
  let R : Nat → VM → Prop := fun cur w =>
    (∀ t, t < cur → ∀ k, k < 32 → w.mem (0x40 + 32 * t + k) = vm.mem (0x80 + 32 * t + k))
    ∧ (∀ a, 0x40 + 32 * cur ≤ a → w.mem a = vm.mem a)
    ∧ (∀ a, a < 0x40 → w.mem a = vm.mem a)
  have hstep : ∀ cur w, cur < 13 → R cur w →
      (execList sha sig forsCopyBody { w with env := setVar w.env "i" cur }).2 = none ∧
      R (cur + 1) (execList sha sig forsCopyBody { w with env := setVar w.env "i" cur }).1 := by
    intro cur w hcur hR
    obtain ⟨hcopied, hhigh, hlow⟩ := hR
    obtain ⟨hnone, hframe, hcopy⟩ := copy_step sha sig cur w (by omega)
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
  obtain ⟨h0, hc, _, hl⟩ := execFor_invariant_lt sha sig "i" forsCopyBody 13 R hstep vm hR0
  exact ⟨h0, hc, hl⟩

/-! ## 9. O2 discharged -/

theorem refFors_split' : refFors = .forRange "i" (.lit 12) refTreeBody :: .block refLast
    :: [ .mstore (.lit 32) rootAdrsE, .forRange "i" (.lit 13) forsCopyBody,
      .sha256 (.lit 0) (.lit 480) (.var "OUT"), .letv "forsPk" (.bin .band (.mload (.var "OUT")) (.var "N_MASK")) ] :=
  refFors_split

theorem headFors_split' : headFors = [ .mstore (.var "TB") (.var "seed"), .mstore (.lit 96) (.lit 0) ]
    ++ (.forRange "i" (.lit 12) headTreeBody :: .block headLast
      :: [ .mstore (.bin .add (.var "TB") (.lit 32)) rootAdrsE, .sha256h (.var "TB") (.lit 480) (.lit 64) ]) :=
  headFors_split

set_option maxHeartbeats 32000000 in
/-- **(O2) discharged: FORS.** From `HmsgExit`, both FORS fragments fall through and `ForsExit`
    holds: the reference's `forsPk` has exactly the bytes the optimized v1 leaves at `0x40`. -/
theorem fors_obl : ForsObl := by
  intro sig r h hX
  obtain ⟨pE, pI⟩ := fors_prologue c10Oracle sig r h hX
  rw [refFors_split', headFors_split', app_none _ _ _ _ _ (by rw [pE]), pE]
  generalize hh0 : ({ mem := mstore32 (mstore32 h.mem 0x80 (h.env "seed")) 96 0, env := h.env } : VM) = h0 at pI
  obtain ⟨t0, t0', tI⟩ := fors_trees c10Oracle sig r h0 pI
  rw [execList_cons_none _ _ _ _ _ t0, execList_cons_none _ _ _ _ _ t0']
  generalize hr1 : (execStmt c10Oracle sig (.forRange "i" (.lit 12) refTreeBody) r).1 = r1 at tI
  generalize hh1 : (execStmt c10Oracle sig (.forRange "i" (.lit 12) headTreeBody) h0).1 = h1 at tI
  rw [execList_cons_none c10Oracle sig (.block refLast) _ r1 (by rw [refLast_eval _ _ _ tI.rOUT]),
    refLast_eval _ _ _ tI.rOUT,
    execList_cons_none c10Oracle sig (.block headLast) _ h1 (by rw [headLast_eval _ _ _ tI.hTB]),
    headLast_eval _ _ _ tI.hTB]
  -- the last tree's leaf: the same 96 bytes on both sides
  have eLS : lsVal sig h1.env = lsVal sig r1.env := by
    unfold lsVal; rw [tI.sbR, tI.sbH, tI.rN, tI.hN]
  have eLA : laVal h1.env = laVal r1.env := by unfold laVal; rw [tI.ht]
  have eRA : raVal h1.env = raVal r1.env := by unfold raVal; rw [tI.ht]
  generalize hMR : mstore32 (mstore32 r1.mem 32 (laVal r1.env)) 64 (lsVal sig r1.env) = MR
  generalize hMH : mstore32 (mstore32 h1.mem 32 (laVal h1.env)) 64 (lsVal sig h1.env) = MH
  have hMRhi : ∀ a, 96 ≤ a → MR a = r1.mem a := by
    intro a ha; rw [← hMR, mstore32_frame _ 64 _ a (by omega), mstore32_frame _ 32 _ a (by omega)]
  have hMHhi : ∀ a, 96 ≤ a → MH a = h1.mem a := by
    intro a ha; rw [← hMH, mstore32_frame _ 64 _ a (by omega), mstore32_frame _ 32 _ a (by omega)]
  have hMRseed : ∀ k, k < 32 → MR k = beByte (r1.env "seed") k := by
    intro k hk; rw [← hMR, mstore32_frame _ 64 _ k (by omega), mstore32_frame _ 32 _ k (by omega)]
    exact tI.seedR k hk
  have hMHseed : ∀ k, k < 32 → MH k = beByte (r1.env "seed") k := by
    intro k hk; rw [← hMH, mstore32_frame _ 64 _ k (by omega), mstore32_frame _ 32 _ k (by omega)]
    exact tI.seedH k hk
  have hMH64 : ∀ k, k < 32 → MH (64 + k) = beByte (lsVal sig r1.env) k := by
    intro k hk; rw [← hMH, mstore32_get _ _ _ _ hk, eLS]
  have hLlow : ∀ k, 16 ≤ k → k < 32 → beByte (lsVal sig r1.env) k = 0 := by
    intro k h1' _; unfold lsVal; rw [tI.rN]; exact beByte_masked_low _ _ h1'
  have hsl1 : slice MH 0 96 = slice MR 0 96 := by
    apply slice_congr
    intro i hi
    rw [Nat.zero_add]
    by_cases h32 : i < 32
    · rw [hMHseed i h32, hMRseed i h32]
    · rw [← hMR, ← hMH, eLA, eLS]
      by_cases h64 : i < 64
      · rw [mstore32_frame _ 64 _ i (by omega), mstore32_frame _ 64 _ i (by omega),
          show i = 32 + (i - 32) by omega, mstore32_get _ _ _ _ (by omega), mstore32_get _ _ _ _ (by omega)]
      · rw [show i = 64 + (i - 64) by omega, mstore32_get _ _ _ _ (by omega), mstore32_get _ _ _ _ (by omega)]
  rw [hsl1]
  generalize hD1 : c10Oracle (slice MR 0 96) = D1
  -- the 13 roots, after the last tree
  have roots13 : ∀ t, t < 13 → ∀ k, k < 32 →
      mstore32 (writeRegion MR 0x600 (fun j => D1.data.getD j 0)) 512 (wordOf D1 &&& r1.env "N_MASK")
          (0x80 + 32 * t + k)
        = writeBytes MH 0x240 16 (fun j => D1.data.getD j 0) (0xC0 + 32 * t + k) := by
    intro t ht k hk
    by_cases h12 : t < 12
    · rw [mstore32_frame _ _ _ _ (by omega), writeRegion_frame _ _ _ _ (by omega), hMRhi _ (by omega),
        writeBytes_frame _ _ _ _ _ (by omega), hMHhi _ (by omega)]
      exact tI.roots t h12 k hk
    · have : t = 12 := by omega
      subst this
      rw [show 0x80 + 32 * 12 + k = 512 + k by omega, mstore32_get _ _ _ _ hk, tI.rN, beByte_and_nmask]
      by_cases h16 : k < 16
      · rw [if_pos h16, show 0xC0 + 32 * 12 + k = 0x240 + k by omega,
          writeBytes_get _ _ _ _ _ (by omega), beByte_wordOf_getD _ _ hk, Nat.add_sub_cancel_left]
      · rw [if_neg h16, writeBytes_frame _ _ _ _ _ (by omega), hMHhi _ (by omega)]
        exact (tI.lowFut 12 (Nat.le_refl 12) (by decide) k (by omega) hk).symm
  -- root ADRS, the reference copy, the compressions
  generalize hR2 : mstore32 (writeRegion MR 0x600 (fun j => D1.data.getD j 0)) 512 (wordOf D1 &&& r1.env "N_MASK") = R2
    at roots13
  generalize hH2 : writeBytes MH 0x240 16 (fun j => D1.data.getD j 0) = H2 at roots13
  have hR2lo : ∀ a, a < 64 → R2 a = MR a := by
    intro a ha; rw [← hR2, mstore32_frame _ _ _ _ (by omega), writeRegion_frame _ _ _ _ (by omega)]
  have hH2lo : ∀ a, a < 0x240 → H2 a = MH a := by
    intro a ha; rw [← hH2, writeBytes_frame _ _ _ _ _ (by omega)]
  -- root ADRS: both sides
  have mR : ∀ (w : VM), execStmt c10Oracle sig (.mstore (.lit 32) rootAdrsE) w
      = ({ w with mem := mstore32 w.mem 32 (raVal w.env) }, none) := by
    intro w; simp only [execStmt, eval, rootAdrsE]; rfl
  have mH : ∀ (w : VM), w.env "TB" = 0x80 →
      execStmt c10Oracle sig (.mstore (.bin .add (.var "TB") (.lit 32)) rootAdrsE) w
        = ({ w with mem := mstore32 w.mem 0xA0 (raVal w.env) }, none) := by
    intro w hw; simp only [execStmt, eval, rootAdrsE, hw]; rfl
  rw [execList_cons_none c10Oracle sig (.mstore (.lit 32) rootAdrsE) _ _ (by rw [mR]), mR,
    execList_cons_none c10Oracle sig (.mstore (.bin .add (.var "TB") (.lit 32)) rootAdrsE) _ _
      (by rw [mH _ (by simp only; rw [setVar_get_ne _ _ _ _ (by decide)]; exact tI.hTB)]),
    mH _ (by simp only; rw [setVar_get_ne _ _ _ _ (by decide)]; exact tI.hTB)]
  simp only []
  have rRA : raVal (setVar r1.env "lastSecret" (lsVal sig r1.env)) = raVal r1.env := by
    unfold raVal; rw [setVar_get_ne _ _ _ _ (by decide)]
  have hRA : raVal (setVar h1.env "lastSecret" (lsVal sig h1.env)) = raVal r1.env := by
    rw [← eRA]; unfold raVal; rw [setVar_get_ne _ _ _ _ (by decide)]
  rw [rRA, hRA]
  -- the reference copy
  generalize hV3 : ({ mem := mstore32 R2 32 (raVal r1.env), env := setVar r1.env "lastSecret" (lsVal sig r1.env) } : VM) = V3
  obtain ⟨c0, cM, cL⟩ := copy_loop13 c10Oracle sig V3
  have hS2 : execStmt c10Oracle sig (.forRange "i" (.lit 13) forsCopyBody) V3
      = execFor c10Oracle sig "i" forsCopyBody 13 0 V3 := by simp only [execStmt, eval]
  rw [execList_cons_none _ _ _ _ _ (by rw [hS2]; exact c0), hS2]
  have fB : ∀ x, x ≠ "i" → (execFor c10Oracle sig "i" forsCopyBody 13 0 V3).1.env x = V3.env x :=
    fun x hx => execFor_env_frame c10Oracle sig "i" forsCopyBody x (Ne.symm hx) (by
      unfold forsCopyBody; simp [assignsVarList, assignsVar]) _ _ _
  generalize hV4 : (execFor c10Oracle sig "i" forsCopyBody 13 0 V3).1 = V4 at cM cL fB
  have mV3 : V3.mem = mstore32 R2 32 (raVal r1.env) := by rw [← hV3]
  have eV3 : ∀ x, x ≠ "lastSecret" → V3.env x = r1.env x := by
    intro x hx; rw [← hV3]; exact setVar_get_ne _ _ _ _ hx
  have oV4 : V4.env "OUT" = 0x600 := by rw [fB _ (by decide), eV3 _ (by decide), tI.rOUT]
  have nV4 : V4.env "N_MASK" = NMASK := by rw [fB _ (by decide), eV3 _ (by decide), tI.rN]
  rw [execList_cons_none _ _ _ _ _ (by simp only [execStmt]), execList_single, execList_single]
  simp only [execStmt, eval, oV4]
  -- the two root compressions hash the same 480 bytes
  generalize hH3 : mstore32 H2 0xA0 (raVal r1.env) = H3
  have hsl2 : slice V4.mem 0 480 = slice H3 0x80 480 := by
    apply slice_congr'
    intro i hi
    rcases (by omega : i < 32 ∨ (32 ≤ i ∧ i < 64) ∨ 64 ≤ i) with h1' | h1' | h1'
    · rw [Nat.zero_add, cL i (by omega), mV3, mstore32_frame _ 32 _ i (by omega), hR2lo i (by omega),
        hMRseed i h1', ← hH3, mstore32_frame _ 0xA0 _ _ (by omega), hH2lo _ (by omega), hMHhi _ (by omega)]
      exact (tI.tb i h1').symm
    · rw [Nat.zero_add, cL i (by omega), mV3, show i = 32 + (i - 32) by omega, mstore32_get _ _ _ _ (by omega),
        ← hH3, show 0x80 + (32 + (i - 32)) = 0xA0 + (i - 32) by omega, mstore32_get _ _ _ _ (by omega)]
    · have ht : (i - 64) / 32 < 13 := by omega
      have hk : (i - 64) % 32 < 32 := Nat.mod_lt _ (by decide)
      have e1 : 0 + i = 0x40 + 32 * ((i - 64) / 32) + (i - 64) % 32 := by omega
      have e2 : 0x80 + i = 0xC0 + 32 * ((i - 64) / 32) + (i - 64) % 32 := by omega
      rw [e1, e2, cM _ ht _ hk, mV3, mstore32_frame _ 32 _ _ (by omega), roots13 _ ht _ hk, ← hH3,
        mstore32_frame _ 0xA0 _ _ (by omega)]
  rw [hsl2]
  refine ⟨by first | rfl | trivial, fun _ => ?_⟩
  simp (disch := decide) only [setVar_get_ne]
  rw [mload32_digest, nV4, tI.hTB]
  have eR : ∀ x, x ≠ "lastSecret" → x ≠ "i" → x ≠ "forsPk" →
      (setVar V4.env "forsPk" (wordOf (c10Oracle (slice H3 0x80 480)) &&& NMASK)) x = r1.env x := by
    intro x a b c; rw [setVar_get_ne _ _ _ _ c, fB _ b, eV3 _ a]
  have eH : ∀ x, x ≠ "lastSecret" → (setVar h1.env "lastSecret" (lsVal sig h1.env)) x = h1.env x :=
    fun x hx => setVar_get_ne _ _ _ _ hx
  refine ⟨?_, ?_, Nat.lt_of_le_of_lt Nat.and_le_left (wordOf_lt _), ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    ?_, ?_⟩
  · intro k hk
    dsimp only
    simp only [setVar_get_eq]
    rw [beByte_and_nmask]
    by_cases h16 : k < 16
    · rw [writeBytes_get _ _ _ _ _ (by omega), if_pos h16, beByte_wordOf_getD _ _ hk,
        Nat.add_sub_cancel_left]
    · rw [if_neg h16, writeBytes_frame _ _ _ _ _ (by omega), ← hH3, mstore32_frame _ 0xA0 _ _ (by omega),
        hH2lo _ (by omega), hMH64 k hk]
      exact hLlow k (by omega) hk
  · intro k h1' _; dsimp only; simp only [setVar_get_eq]; exact beByte_masked_low _ _ h1'
  · intro k hk
    dsimp only
    rw [eR "seed" (by decide) (by decide) (by decide), writeBytes_frame _ _ _ _ _ (by omega), ← hH3,
      mstore32_frame _ 0xA0 _ _ (by omega), hH2lo _ (by omega), hMHhi _ (by omega)]
    exact tI.tb k hk
  · dsimp only; rw [eH _ (by decide), eR _ (by decide) (by decide) (by decide)]; exact tI.seed
  · dsimp only; rw [eH _ (by decide), eR _ (by decide) (by decide) (by decide)]; exact tI.root
  · dsimp only; rw [eH _ (by decide), eR _ (by decide) (by decide) (by decide)]; exact tI.ht
  · dsimp only; rw [eR _ (by decide) (by decide) (by decide)]; exact tI.ht18
  · dsimp only; rw [eR _ (by decide) (by decide) (by decide)]; exact tI.sbR
  · dsimp only; rw [eH _ (by decide)]; exact tI.sbH
  · dsimp only; rw [eR _ (by decide) (by decide) (by decide)]; exact tI.rN
  · dsimp only; rw [eR _ (by decide) (by decide) (by decide)]; exact tI.rOUT
  · dsimp only; rw [eH _ (by decide)]; exact tI.hN
  · dsimp only; rw [eH _ (by decide)]; exact tI.hTB
  · dsimp only; rw [eH _ (by decide)]; exact tI.hOUT

/-! ## 10. The end theorem, with every obligation discharged -/

/-- **The optimized v1 returns the reference's verdict, for every key, message and signature**
    (under the real SHA-256 oracle, in `execC10Asm`'s setting). No phase obligation is assumed:
    O1-O5 are all proven. -/
theorem head_verdict_eq_full (pkSeed pkRoot message : ByteVec 32) (sig : ByteVec Spec.SignatureLen) :
    execC10HeadAsm pkSeed pkRoot message sig = execC10Asm pkSeed pkRoot message sig :=
  RelHmsg.head_verdict_eq_of_fors fors_obl pkSeed pkRoot message sig

/-- **Composed with the reference's own refinement** (`C10Refine.execC10Asm_eq`): the optimized v1
    computes the declarative spec, modulo the same two leading N-mask guards. -/
theorem execC10HeadAsm_eq (pkSeed pkRoot message : ByteVec 32) (sig : ByteVec Spec.SignatureLen) :
    execC10HeadAsm pkSeed pkRoot message sig
      = (nMaskedB pkSeed && nMaskedB pkRoot && SphincsCVerify.Bridge.verifyYulModel pkSeed pkRoot message sig) := by
  rw [head_verdict_eq_full, execC10Asm_eq]

end SphincsCVerify.Interpreter.C10.RelFors

/-
SphincsCVerify.Interpreter.RelChain — RESEARCH (#1155 gas track, batch 7): the relational pilot
for ONE WOTS chain, the first memory-coupled step of the `c10HeadProgram ≡ c10Program` route.

Reference (`c10Program`, `wotsChainBody` with loop var `i = c`): the chain value lives in the
variable `val` (a 32-byte word, low half zero); each step writes the whole ADRS word to `0x20`
and `val` to `0x40`, hashes `[0, 0x60)` into the scratch word at `0x600`, and masks it back into
`val`; the endpoint is stored at `0x80 + 32c`.

Optimized (`c10HeadProgram`, `chainBlock c`): the chain value lives IN MEMORY at `0x40`; the
ADRS word at `0x20` is written once per layer and patched byte-wise (`mstore8` of the chain
index at `0x37`, of the chain position at `0x3B`); each step hashes `[0, 0x60)` and writes the
first 16 digest bytes back to `0x40` in place; the endpoint is stored at `TB + 64 + 32c =
0xC0 + 32c`.

The theorems here are SPEC-FREE: no `Spec.*` term, no reference spec lemma, and an ARBITRARY
hash oracle `sha`. They relate the two executions directly through a memory/environment coupling
(`StepRel`): same seed bytes, HEAD's ADRS bytes = the reference's ADRS word bytes, HEAD's bytes at
`0x40` = the bytes of the reference's `val`. `chain_block_rel` is the per-chain result: both fall
through and store the SAME 32 bytes (the reference at `0x80 + 32c`, the optimized v1 at
`0xC0 + 32c`), with frames; `head_chainBlocks_pin` ties `chainBlock 0 … chainBlock 42` to the
optimized layer loop by `rfl`.

Mathlib-free; no `sorry`/`admit`/`axiom`/`native_decide`/`bv_decide`.
-/

import SphincsCVerify.Interpreter.RelE1

namespace SphincsCVerify.Interpreter.C10.RelChain

open SphincsCVerify.Interpreter
open SphincsCVerify.Interpreter.C10
open SphincsCVerify.Interpreter.C10.RelE1 (loopBody execList_single)
open SphincsCVerify.Spec (ByteVec)

/-! ## 1. Byte-granular memory lemmas (one-time infrastructure) -/

theorem writeBytes_get (mem : ByteMemory) (off len : Nat) (f : Nat → UInt8) (a : Nat)
    (h : off ≤ a ∧ a < off + len) : writeBytes mem off len f a = f (a - off) := by
  unfold writeBytes; rw [if_pos h]

theorem writeBytes_frame (mem : ByteMemory) (off len : Nat) (f : Nat → UInt8) (a : Nat)
    (h : a < off ∨ off + len ≤ a) : writeBytes mem off len f a = mem a := by
  unfold writeBytes
  split
  · omega
  · rfl

theorem mstore8Mem_get (mem : ByteMemory) (off val : Nat) :
    mstore8Mem mem off val off = UInt8.ofNat (val % 256) := by
  unfold mstore8Mem; simp

theorem mstore8Mem_frame (mem : ByteMemory) (off val a : Nat) (h : a ≠ off) :
    mstore8Mem mem off val a = mem a := by
  unfold mstore8Mem; simp [h]

theorem slice_congr (m1 m2 : ByteMemory) (off n : Nat)
    (h : ∀ i, i < n → m1 (off + i) = m2 (off + i)) : slice m1 off n = slice m2 off n := by
  unfold slice
  apply List.map_congr_left
  intro i hi
  exact h i (List.mem_range.mp hi)

/-- A value below 256 has one non-zero big-endian byte, the last. -/
theorem beByte_small (x k : Nat) (hx : x < 256) (hk : k < 32) :
    beByte x k = if k = 31 then UInt8.ofNat x else 0 := by
  unfold beByte
  by_cases h : k = 31
  · subst h; simp [Nat.mod_eq_of_lt hx]
  · rw [if_neg h, Nat.shiftRight_eq_div_pow,
      Nat.div_eq_of_lt (Nat.lt_of_lt_of_le hx (by
        have : 8 ≤ 8 * (31 - k) := by omega
        exact Nat.le_trans (by decide : 256 ≤ 2 ^ 8) (Nat.pow_le_pow_right (by decide) this)))]
    rfl

/-! ## 2. The ADRS word, byte by byte -/

/-- The reference's per-chain ADRS base: `and(or(wotsAdrs, shl(64, i)), CHAINBASE_MASK)`. -/
def cbOf (wa c : Nat) : Nat := (wa ||| (c <<< 64) % W) &&& CHAINBASE_MASK

/-- The reference's per-step ADRS word: `or(chainBase, shl(32, pos))`. -/
def adrsOf (wa c pos : Nat) : Nat := cbOf wa c ||| (pos <<< 32) % W

theorem uint8_or_zero (x : UInt8) : x ||| 0 = x := by
  apply UInt8.toBitVec_inj.mp; simp

theorem uint8_zero_or (x : UInt8) : 0 ||| x = x := by
  apply UInt8.toBitVec_inj.mp; simp

theorem uint8_and_ff (x : UInt8) : x &&& 0xFF = x := by
  have : (0xFF : UInt8) = (-1 : UInt8) := by decide
  rw [this, UInt8.and_neg_one]

theorem uint8_and_zero (x : UInt8) : x &&& 0 = 0 := by
  apply UInt8.toBitVec_inj.mp; simp

/-- **The ADRS coupling.** If `wotsAdrs` has zero bytes 23..26 (its chain-index low byte and
    the chain-position high bytes), the reference's per-step ADRS word has the bytes of
    `wotsAdrs` with byte 23 = the chain index and byte 27 = the chain position: exactly what the
    optimized v1's two `mstore8`s produce over the stored `wotsAdrs`. -/
theorem adrsOf_byte (wa c pos k : Nat) (hc : c < 256) (hpos : pos < 256) (hk : k < 32)
    (hz : ∀ j, 23 ≤ j → j ≤ 26 → beByte wa j = 0) :
    beByte (adrsOf wa c pos) k
      = if k = 23 then UInt8.ofNat c else if k = 27 then UInt8.ofNat pos else beByte wa k := by
  have hc64 : (c <<< 64) % W = c <<< (8 * 8) := Nat.mod_eq_of_lt (by
    rw [Nat.shiftLeft_eq]; show c * 2 ^ 64 < 2 ^ 256
    have : c * 2 ^ 64 < 256 * 2 ^ 64 := Nat.mul_lt_mul_of_pos_right hc (by decide)
    exact Nat.lt_of_lt_of_le this (by decide))
  have hp32 : (pos <<< 32) % W = pos <<< (8 * 4) := Nat.mod_eq_of_lt (by
    rw [Nat.shiftLeft_eq]; show pos * 2 ^ 32 < 2 ^ 256
    have : pos * 2 ^ 32 < 256 * 2 ^ 32 := Nat.mul_lt_mul_of_pos_right hpos (by decide)
    exact Nat.lt_of_lt_of_le this (by decide))
  unfold adrsOf cbOf
  rw [hc64, hp32, beByte_lor, beByte_band, beByte_lor, chainbase_byte,
    beByte_shiftLeft_byte c 8 k hk, beByte_shiftLeft_byte pos 4 k hk]
  by_cases h23 : k = 23
  · subst h23
    simp only [show (23 : Nat) + 8 ≤ 31 from by decide, if_true, show (23 : Nat) + 4 ≤ 31 from by decide,
      show ¬ (24 ≤ 23 ∧ 23 < 28) from by decide, if_false, show (23 : Nat) + 8 = 31 from rfl,
      show (23 : Nat) + 4 = 27 from rfl]
    rw [hz 23 (by decide) (by decide), beByte_small c 31 hc (by decide), beByte_small pos 27 hpos (by decide)]
    simp [uint8_and_ff]
  · by_cases h27 : k = 27
    · subst h27
      rw [if_neg (by decide : ¬ ((27 : Nat) + 8 ≤ 31)), if_pos (by decide : (27 : Nat) + 4 ≤ 31),
        if_pos (by decide : 24 ≤ (27 : Nat) ∧ (27 : Nat) < 28), if_neg (by decide : ¬ ((27 : Nat) = 23)),
        if_pos rfl, show (27 : Nat) + 4 = 31 from rfl, beByte_small pos 31 hpos (by decide), if_pos rfl,
        uint8_and_zero, uint8_zero_or]
    · rw [if_neg h23, if_neg h27]
      by_cases hmid : 24 ≤ k ∧ k < 28
      · rw [if_pos hmid, uint8_and_zero, uint8_zero_or]
        have hk26 : k ≤ 26 := by omega
        rw [hz k (by omega) hk26]
        by_cases h4 : k + 4 ≤ 31
        · rw [if_pos h4, beByte_small pos (k + 4) hpos (by omega), if_neg (by omega)]
        · rw [if_neg h4]
      · rw [if_neg hmid, uint8_and_ff]
        have hcz : (if k + 8 ≤ 31 then beByte c (k + 8) else 0) = 0 := by
          by_cases h8 : k + 8 ≤ 31
          · rw [if_pos h8, beByte_small c (k + 8) hc (by omega), if_neg (by omega)]
          · rw [if_neg h8]
        have hpz : (if k + 4 ≤ 31 then beByte pos (k + 4) else 0) = 0 := by
          by_cases h4 : k + 4 ≤ 31
          · rw [if_pos h4, beByte_small pos (k + 4) hpos (by omega), if_neg (by omega)]
          · rw [if_neg h4]
        rw [hcz, hpz, uint8_or_zero, uint8_or_zero]

/-! ## 3. One chain step -/

/-- The optimized v1's inner chain-step body (`mstore8(0x3B, p)`, then the in-place hash). -/
def headStepBody : List Stmt :=
  [ .mstore8 (.lit 59) (.var "p"), .sha256h (.lit 0) (.lit 96) (.lit 64) ]

/-- The reference-to-optimized coupling inside one chain (chain index `c`, ADRS base `wa`),
    with `mR0` / `mH0` the two memories at chain entry (for the frames). -/
def StepRel (digit c wa : Nat) (mR0 mH0 : ByteMemory) (wR wH : VM) : Prop :=
  wR.env "chainBase" = cbOf wa c ∧ wR.env "digit" = digit ∧ wR.env "N_MASK" = NMASK
  ∧ wR.env "OUT" = 0x600
  ∧ (∀ k, k < 32 → wH.mem k = wR.mem k)
  ∧ (∀ k, k < 32 → k ≠ 23 → k ≠ 27 → wH.mem (32 + k) = beByte wa k)
  ∧ wH.mem 55 = UInt8.ofNat c
  ∧ (∀ k, k < 32 → wH.mem (64 + k) = beByte (wR.env "val") k)
  ∧ (∀ k, 16 ≤ k → k < 32 → beByte (wR.env "val") k = 0)
  ∧ (∀ a, 96 ≤ a → (a < 0x600 ∨ 0x620 ≤ a) → wR.mem a = mR0 a)
  ∧ (∀ a, 96 ≤ a → wH.mem a = mH0 a)
  ∧ (∀ k, k < 32 → wR.mem k = mR0 k)

theorem beByte_masked_low (x k : Nat) (hk : 16 ≤ k) : beByte (x &&& NMASK) k = 0 := by
  rw [beByte_and_nmask, if_neg (by omega)]

set_option maxHeartbeats 4000000 in
/-- **One step, related.** From coupled states, one reference step (`step := cur`) and one
    optimized step (`p := digit + cur`) both fall through, hash the SAME 96 bytes, and leave
    coupled states. Arbitrary hash oracle `sha`. -/
theorem chain_step_rel {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n)
    (digit c wa cur : Nat) (mR0 mH0 : ByteMemory) (wR wH : VM)
    (hc : c < 256) (hpos : digit + cur < 256)
    (hz : ∀ j, 23 ≤ j → j ≤ 26 → beByte wa j = 0)
    (h : StepRel digit c wa mR0 mH0 wR wH) :
    (execList sha sig wotsChainStepBody { wR with env := setVar wR.env "step" cur }).2 = none
    ∧ (execList sha sig headStepBody { wH with env := setVar wH.env "p" (digit + cur) }).2 = none
    ∧ StepRel digit c wa mR0 mH0
        (execList sha sig wotsChainStepBody { wR with env := setVar wR.env "step" cur }).1
        (execList sha sig headStepBody { wH with env := setVar wH.env "p" (digit + cur) }).1 := by
  obtain ⟨hcb, hdig, hN, hOUT, hseed, hadrs, h55, hval, hvlo, hfR, hfH, hsR⟩ := h
  -- the reference step, statement by statement
  unfold wotsChainStepBody headStepBody
  rw [execList_cons_none sha sig _ _ _ (by simp only [execStmt]),
    execList_cons_none sha sig _ _ _ (by simp only [execStmt]),
    execList_cons_none sha sig _ _ _ (by simp only [execStmt]), execList_single,
    execList_cons_none sha sig _ _ _ (by simp only [execStmt]), execList_single]
  have hsum : (digit + cur) % W = digit + cur := Nat.mod_eq_of_lt (lt_W_of_lt (by omega))
  -- name the pieces
  generalize hval0 : wR.env "val" = val at *
  have hA : (wR.env "chainBase" ||| ((digit + cur) % W) <<< 32 % W) = adrsOf wa c (digit + cur) := by
    rw [hcb, hsum]; rfl
  have hslice : slice (mstore32 (mstore32 wR.mem 32 (adrsOf wa c (digit + cur))) 64 val) 0 96
      = slice (mstore8Mem wH.mem 59 (digit + cur)) 0 96 := by
    apply slice_congr
    intro i hi
    simp only [Nat.zero_add]
    by_cases hi32 : i < 32
    · rw [mstore32_frame _ 64 val i (by omega), mstore32_frame _ 32 _ i (by omega),
        mstore8Mem_frame _ _ _ _ (by omega), hseed i hi32]
    · by_cases hi64 : i < 64
      · rw [mstore32_frame _ 64 val i (by omega)]
        have e1 := mstore32_get wR.mem 32 (adrsOf wa c (digit + cur)) (i - 32) (by omega)
        rw [show 32 + (i - 32) = i by omega] at e1
        rw [e1, adrsOf_byte wa c (digit + cur) (i - 32) hc hpos (by omega) hz]
        by_cases h59 : i = 59
        · subst h59
          rw [mstore8Mem_get, Nat.mod_eq_of_lt hpos]
          simp
        · rw [mstore8Mem_frame _ _ _ _ h59]
          by_cases h55' : i = 55
          · subst h55'; rw [h55]; simp
          · rw [if_neg (by omega), if_neg (by omega)]
            have := hadrs (i - 32) (by omega) (by omega) (by omega)
            rw [show 32 + (i - 32) = i by omega] at this
            exact this.symm
      · have e2 := mstore32_get (mstore32 wR.mem 32 (adrsOf wa c (digit + cur))) 64 val (i - 64) (by omega)
        rw [show 64 + (i - 64) = i by omega] at e2
        rw [e2, mstore8Mem_frame _ _ _ _ (by omega)]
        have := hval (i - 64) (by omega)
        rw [show 64 + (i - 64) = i by omega] at this
        exact this.symm
  refine ⟨?_, ?_, ?_⟩
  · simp only [execStmt]
  · simp only [execStmt]
  · simp only [execStmt, eval, setVar, ite_true, ite_false, String.reduceEq, hN, hOUT, hdig]
    rw [hA, hval0, hslice]
    generalize hD : sha (slice (mstore8Mem wH.mem 59 (digit + cur)) 0 96) = D
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · exact hcb
    · exact hdig
    · exact hN
    · exact hOUT
    · intro k hk
      dsimp only
      rw [writeBytes_frame _ _ _ _ _ (by omega), writeRegion_frame _ _ _ _ (by omega),
        mstore8Mem_frame _ _ _ _ (by omega), mstore32_frame _ 64 _ k (by omega),
        mstore32_frame _ 32 _ k (by omega), hseed k hk]
    · intro k hk h23 h27
      dsimp only
      rw [writeBytes_frame _ _ _ _ _ (by omega), mstore8Mem_frame _ _ _ _ (by omega), hadrs k hk h23 h27]
    · dsimp only
      rw [writeBytes_frame _ _ _ _ _ (by omega), mstore8Mem_frame _ _ _ _ (by omega), h55]
    · intro k hk
      dsimp only
      simp only [setVar, ite_true]
      rw [beByte_and_nmask]
      by_cases hk16 : k < 16
      · rw [if_pos hk16, writeBytes_get _ _ _ _ _ (by omega), beByte_mload32 _ _ _ hk,
          writeRegion_get _ _ _ _ (by omega)]
        simp only [Nat.add_sub_cancel_left]
      · rw [if_neg hk16, writeBytes_frame _ _ _ _ _ (by omega), mstore8Mem_frame _ _ _ _ (by omega),
          hval k hk, hvlo k (by omega) hk]
    · intro k hk16 _
      dsimp only
      simp only [setVar, ite_true]
      exact beByte_masked_low _ k hk16
    · intro a ha hout
      dsimp only
      rw [writeRegion_frame _ _ _ _ (by omega), mstore32_frame _ 64 _ a (by omega),
        mstore32_frame _ 32 _ a (by omega)]
      exact hfR a ha hout
    · intro a ha
      dsimp only
      rw [writeBytes_frame _ _ _ _ _ (by omega), mstore8Mem_frame _ _ _ _ (by omega)]
      exact hfH a ha
    · intro k hk
      dsimp only
      rw [writeRegion_frame _ _ _ _ (by omega), mstore32_frame _ 64 _ k (by omega),
        mstore32_frame _ 32 _ k (by omega)]
      exact hsR k hk

/-! ## 4. Two loops in lock-step (one-time infrastructure) -/

/-- **Two-program loop simulation.** If each pair of iterations (the first loop at index `c`,
    the second at `off + c`) falls through and preserves `R`, then so do the whole loops. -/
theorem execFor_rel {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n)
    (v1 : String) (b1 : List Stmt) (v2 : String) (b2 : List Stmt) (off N : Nat)
    (R : Nat → VM → VM → Prop)
    (hstep : ∀ c w1 w2, c < N → R c w1 w2 →
      (execList sha sig b1 { w1 with env := setVar w1.env v1 c }).2 = none
      ∧ (execList sha sig b2 { w2 with env := setVar w2.env v2 (off + c) }).2 = none
      ∧ R (c + 1) (execList sha sig b1 { w1 with env := setVar w1.env v1 c }).1
          (execList sha sig b2 { w2 with env := setVar w2.env v2 (off + c) }).1) :
    ∀ rem c w1 w2, c + rem = N → R c w1 w2 →
      (execFor sha sig v1 b1 rem c w1).2 = none
      ∧ (execFor sha sig v2 b2 rem (off + c) w2).2 = none
      ∧ R N (execFor sha sig v1 b1 rem c w1).1 (execFor sha sig v2 b2 rem (off + c) w2).1
  | 0, c, w1, w2, hN, hR => by
      rw [execFor, execFor]
      rw [Nat.add_zero] at hN
      subst hN
      exact ⟨rfl, rfl, hR⟩
  | rem + 1, c, w1, w2, hN, hR => by
      obtain ⟨h1, h2, h3⟩ := hstep c w1 w2 (by omega) hR
      rw [execFor, execFor]
      cases e1 : execList sha sig b1 { w1 with env := setVar w1.env v1 c } with
      | mk a1 o1 =>
        cases e2 : execList sha sig b2 { w2 with env := setVar w2.env v2 (off + c) } with
        | mk a2 o2 =>
          rw [e1] at h1 h3
          rw [e2] at h2 h3
          simp only at h1 h2 h3
          subst h1
          subst h2
          simp only
          have ih := execFor_rel sha sig v1 b1 v2 b2 off N R hstep rem (c + 1) a1 a2 (by omega) h3
          rw [show off + c + 1 = off + (c + 1) by omega]
          exact ih

/-! ## 5. One chain block -/

theorem lt_W_of_lt' {x : Nat} (h : x < 2 ^ 200) : x < W := by
  unfold W; exact Nat.lt_trans h (by decide)

/-- The optimized v1's chain block for chain `j` (four statements; the layer loop holds
    `chainBlock 0 … chainBlock 42`, `head_chainBlocks_pin`). -/
def chainBlock (j : Nat) : List Stmt :=
  [ .mstore (.lit 64) (.bin .band (.calldataload (.bin .add (.var "wotsPtr") (.lit (16 * j)))) (.var "N_MASK"))
  , .mstore8 (.lit 55) (.lit j)
  , .forFrom "p" (.bin .band (.bin .shr (.lit (3 * j)) (.var "d")) (.lit 7)) (.lit 7) headStepBody
  , .mstore (.bin .add (.var "TB") (.lit (64 + 32 * j))) (.mload (.lit 64)) ]

/-- The reference's state after the chain body's four `let`s (digit, steps, value, ADRS base). -/
def refEntry (vR : VM) (dg v0 wa c : Nat) : VM :=
  { mem := vR.mem, env := setVar (setVar (setVar (setVar vR.env "digit" dg) "steps" ((7 + (W - dg % W)) % W)) "val" v0) "chainBase" (cbOf wa c) }

/-- The optimized state after the block's first two statements (value, chain-index byte). -/
def headEntry (vH : VM) (v0 c : Nat) : VM :=
  { mem := mstore8Mem (mstore32 vH.mem 64 v0) 55 c, env := vH.env }

theorem refEntry_env_ne (vR : VM) (dg v0 wa c : Nat) (x : String) (h1 : x ≠ "digit")
    (h2 : x ≠ "steps") (h3 : x ≠ "val") (h4 : x ≠ "chainBase") :
    (refEntry vR dg v0 wa c).env x = vR.env x := by
  unfold refEntry; dsimp only
  rw [setVar_get_ne _ _ _ _ h4, setVar_get_ne _ _ _ _ h3, setVar_get_ne _ _ _ _ h2,
    setVar_get_ne _ _ _ _ h1]

theorem refEntry_digit (vR : VM) (dg v0 wa c : Nat) : (refEntry vR dg v0 wa c).env "digit" = dg := by
  unfold refEntry; dsimp only
  rw [setVar_get_ne _ _ _ _ (by decide), setVar_get_ne _ _ _ _ (by decide),
    setVar_get_ne _ _ _ _ (by decide), setVar_get_eq]

theorem refEntry_steps (vR : VM) (dg v0 wa c : Nat) :
    (refEntry vR dg v0 wa c).env "steps" = (7 + (W - dg % W)) % W := by
  unfold refEntry; dsimp only
  rw [setVar_get_ne _ _ _ _ (by decide), setVar_get_ne _ _ _ _ (by decide), setVar_get_eq]

theorem refEntry_val (vR : VM) (dg v0 wa c : Nat) : (refEntry vR dg v0 wa c).env "val" = v0 := by
  unfold refEntry; dsimp only
  rw [setVar_get_ne _ _ _ _ (by decide), setVar_get_eq]

theorem refEntry_cb (vR : VM) (dg v0 wa c : Nat) :
    (refEntry vR dg v0 wa c).env "chainBase" = cbOf wa c := by
  unfold refEntry; dsimp only; rw [setVar_get_eq]

theorem refEntry_mem (vR : VM) (dg v0 wa c : Nat) : (refEntry vR dg v0 wa c).mem = vR.mem := rfl
theorem headEntry_env (vH : VM) (v0 c : Nat) : (headEntry vH v0 c).env = vH.env := rfl
theorem headEntry_mem (vH : VM) (v0 c : Nat) :
    (headEntry vH v0 c).mem = mstore8Mem (mstore32 vH.mem 64 v0) 55 c := rfl

/-- The reference chain body after its four `let`s. -/
theorem ref_chain_prefix {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (vR : VM)
    (c d wp wa : Nat) (hc : c < 43) (hwp : wp < 4096)
    (hRd : vR.env "d" = d) (hRwp : vR.env "wotsPtr" = wp) (hRwa : vR.env "wotsAdrs" = wa)
    (hRN : vR.env "N_MASK" = NMASK) (hRi : vR.env "i" = c) :
    execList sha sig wotsChainBody vR
      = execList sha sig
          [ .forRange "step" (.var "steps") wotsChainStepBody
          , .mstore (.bin .add (.lit 128) (.bin .shl (.lit 5) (.var "i"))) (.var "val") ]
          (refEntry vR ((d >>> (3 * c)) &&& 7) (calldataload sig (wp + 16 * c) &&& NMASK) wa c) := by
  have h3c : c * 3 % W = 3 * c := by
    rw [Nat.mul_comm]; exact Nat.mod_eq_of_lt (lt_W_of_lt (by omega))
  have h4c : c <<< 4 % W = 16 * c := by
    rw [Nat.shiftLeft_eq, show (2 : Nat) ^ 4 = 16 from rfl, Nat.mul_comm]
    exact Nat.mod_eq_of_lt (lt_W_of_lt (by omega))
  have hwpc : (wp + 16 * c) % W = wp + 16 * c := Nat.mod_eq_of_lt (lt_W_of_lt' (by omega))
  unfold wotsChainBody
  rw [execList_cons_none sha sig _ _ _ (by simp only [execStmt]),
    execList_cons_none sha sig _ _ _ (by simp only [execStmt]),
    execList_cons_none sha sig _ _ _ (by simp only [execStmt]),
    execList_cons_none sha sig _ _ _ (by simp only [execStmt])]
  simp only [execStmt, eval, setVar, ite_true, ite_false, String.reduceEq, hRd, hRi, hRwp, hRN, hRwa,
    h3c, h4c, hwpc]
  rfl

/-- The optimized chain block after its first two statements (`mstore(0x40, value)` and the
    chain-index byte). -/
theorem head_chain_prefix {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (vH : VM)
    (c wp : Nat) (hc : c < 43) (hwp : wp < 4096)
    (hHwp : vH.env "wotsPtr" = wp) (hHN : vH.env "N_MASK" = NMASK) :
    execList sha sig (chainBlock c) vH
      = execList sha sig
          [ .forFrom "p" (.bin .band (.bin .shr (.lit (3 * c)) (.var "d")) (.lit 7)) (.lit 7) headStepBody
          , .mstore (.bin .add (.var "TB") (.lit (64 + 32 * c))) (.mload (.lit 64)) ]
          (headEntry vH (calldataload sig (wp + 16 * c) &&& NMASK) c) := by
  have hwpc : (wp + 16 * c) % W = wp + 16 * c := Nat.mod_eq_of_lt (lt_W_of_lt' (by omega))
  unfold chainBlock
  rw [execList_cons_none sha sig _ _ _ (by simp only [execStmt]),
    execList_cons_none sha sig _ _ _ (by simp only [execStmt])]
  simp only [execStmt, eval, hHwp, hHN, hwpc]
  rfl

/-- The reference's step count: `sub(7, digit)` for a digit `≤ 7`. -/
theorem steps_eq (dg : Nat) (h : dg ≤ 7) : (7 + (W - dg % W)) % W = 7 - dg := by
  have hW : W = 2 ^ 256 := rfl
  rw [Nat.mod_eq_of_lt (show dg < W by rw [hW]; omega)]
  rw [show 7 + (W - dg) = W + (7 - dg) by rw [hW]; omega, Nat.add_mod_left,
    Nat.mod_eq_of_lt (show 7 - dg < W by rw [hW]; omega)]

set_option maxHeartbeats 8000000 in
/-- **One WOTS chain, related.** The reference's chain body (loop var `i = c`) and the optimized
    v1's `chainBlock c`, from states that agree on `d` / `wotsPtr` / `N_MASK` and whose
    memories are coupled (same seed bytes; the optimized ADRS bytes at `0x20` are `wotsAdrs`'s
    except the patched ci / cp bytes), both fall through and store the SAME 32 bytes: the
    reference at `0x80 + 32c`, the optimized v1 at `0xC0 + 32c`. The coupling of the low memory
    is re-established, the reference's seed bytes are unchanged, the optimized v1's zero padding
    at `0x50..0x60` holds, everything at or above `0x60` outside the two stores (and the reference's
    hash scratch) is framed, and every variable other than the chain's own
    scratch (`digit`/`steps`/`val`/`chainBase`/`step`; `p`) keeps its value: the hypotheses for
    chain `c + 1` are re-established (the 43-fold COMPOSITION is a separate, not yet proven
    lemma). Spec-free, arbitrary hash oracle. -/
theorem chain_block_rel {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n)
    (c d wp wa : Nat) (vR vH : VM) (hc : c < 43) (hwp : wp < 4096)
    (hz : ∀ j, 23 ≤ j → j ≤ 26 → beByte wa j = 0)
    (hRd : vR.env "d" = d) (hRwp : vR.env "wotsPtr" = wp) (hRwa : vR.env "wotsAdrs" = wa)
    (hRN : vR.env "N_MASK" = NMASK) (hROUT : vR.env "OUT" = 0x600) (hRi : vR.env "i" = c)
    (hHd : vH.env "d" = d) (hHwp : vH.env "wotsPtr" = wp) (hHN : vH.env "N_MASK" = NMASK)
    (hHTB : vH.env "TB" = 0x80)
    (hseed : ∀ k, k < 32 → vH.mem k = vR.mem k)
    (hadrs : ∀ k, k < 32 → k ≠ 23 → k ≠ 27 → vH.mem (32 + k) = beByte wa k) :
    (execList sha sig wotsChainBody vR).2 = none
    ∧ (execList sha sig (chainBlock c) vH).2 = none
    ∧ (∀ k, k < 32 → (execList sha sig wotsChainBody vR).1.mem (0x80 + 32 * c + k)
        = (execList sha sig (chainBlock c) vH).1.mem (0xC0 + 32 * c + k))
    ∧ (∀ k, k < 32 →
        (execList sha sig (chainBlock c) vH).1.mem k = (execList sha sig wotsChainBody vR).1.mem k)
    ∧ (∀ k, k < 32 → k ≠ 23 → k ≠ 27 → (execList sha sig (chainBlock c) vH).1.mem (32 + k) = beByte wa k)
    ∧ (∀ a, 96 ≤ a → (a < 0x600 ∨ 0x620 ≤ a) → (a < 0x80 + 32 * c ∨ 0x80 + 32 * c + 32 ≤ a) →
        (execList sha sig wotsChainBody vR).1.mem a = vR.mem a)
    ∧ (∀ a, 96 ≤ a → (a < 0xC0 + 32 * c ∨ 0xC0 + 32 * c + 32 ≤ a) →
        (execList sha sig (chainBlock c) vH).1.mem a = vH.mem a)
    ∧ (∀ x, x ≠ "digit" → x ≠ "steps" → x ≠ "val" → x ≠ "chainBase" → x ≠ "step" →
        (execList sha sig wotsChainBody vR).1.env x = vR.env x)
    ∧ (∀ x, x ≠ "p" → (execList sha sig (chainBlock c) vH).1.env x = vH.env x)
    ∧ (∀ k, k < 32 → (execList sha sig wotsChainBody vR).1.mem k = vR.mem k)
    ∧ (∀ k, 16 ≤ k → k < 32 → (execList sha sig (chainBlock c) vH).1.mem (64 + k) = 0) := by
  rw [ref_chain_prefix sha sig vR c d wp wa hc hwp hRd hRwp hRwa hRN hRi,
    head_chain_prefix sha sig vH c wp hc hwp hHwp hHN]
  have hdg7 : (d >>> (3 * c)) &&& 7 ≤ 7 := Nat.and_le_right
  generalize hdg : (d >>> (3 * c)) &&& 7 = dg at hdg7 ⊢
  generalize hv0 : calldataload sig (wp + 16 * c) &&& NMASK = v0
  have hv0lo : ∀ k, 16 ≤ k → k < 32 → beByte v0 k = 0 := by
    intro k hk _; rw [← hv0]; exact beByte_masked_low _ k hk
  -- the two loop-entry states
  generalize hvR4 : refEntry vR dg v0 wa c = vR4
  generalize hvH2 : headEntry vH v0 c = vH2
  have e4 : ∀ x, x ≠ "digit" → x ≠ "steps" → x ≠ "val" → x ≠ "chainBase" → vR4.env x = vR.env x := by
    intro x h1 h2 h3 h4; rw [← hvR4]; exact refEntry_env_ne vR dg v0 wa c x h1 h2 h3 h4
  have hR4mem : vR4.mem = vR.mem := by rw [← hvR4]; rfl
  have hH2env : vH2.env = vH.env := by rw [← hvH2]; rfl
  have hH2mem : vH2.mem = mstore8Mem (mstore32 vH.mem 64 v0) 55 c := by rw [← hvH2]; rfl
  have hval4 : vR4.env "val" = v0 := by rw [← hvR4]; exact refEntry_val vR dg v0 wa c
  -- the loops
  have hloopR : execStmt sha sig (.forRange "step" (.var "steps") wotsChainStepBody) vR4
      = execFor sha sig "step" wotsChainStepBody (7 - dg) 0 vR4 := by
    have hst : vR4.env "steps" = 7 - dg := by
      rw [← hvR4, refEntry_steps, steps_eq dg hdg7]
    simp only [execStmt, eval, hst]
  have hloopH : execStmt sha sig (.forFrom "p" (.bin .band (.bin .shr (.lit (3 * c)) (.var "d")) (.lit 7))
      (.lit 7) headStepBody) vH2 = execFor sha sig "p" headStepBody (7 - dg) dg vH2 := by
    simp only [execStmt, eval, hH2env, hHd, hdg]
  have hR0 : StepRel dg c wa vR4.mem vH2.mem vR4 vH2 := by
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · rw [← hvR4]; exact refEntry_cb vR dg v0 wa c
    · rw [← hvR4]; exact refEntry_digit vR dg v0 wa c
    · rw [e4 _ (by decide) (by decide) (by decide) (by decide), hRN]
    · rw [e4 _ (by decide) (by decide) (by decide) (by decide), hROUT]
    · intro k hk
      rw [hH2mem, hR4mem, mstore8Mem_frame _ _ _ _ (by omega), mstore32_frame _ 64 _ k (by omega), hseed k hk]
    · intro k hk h23 h27
      rw [hH2mem, mstore8Mem_frame _ _ _ _ (by omega), mstore32_frame _ 64 _ _ (by omega), hadrs k hk h23 h27]
    · rw [hH2mem, mstore8Mem_get, Nat.mod_eq_of_lt (by omega : c < 256)]
    · intro k hk
      rw [hH2mem, mstore8Mem_frame _ _ _ _ (by omega), mstore32_get _ 64 v0 k hk, hval4]
    · intro k hk1 hk2
      rw [hval4]; exact hv0lo k hk1 hk2
    · intro a _ _; rfl
    · intro a _; rfl
    · intro k _; rfl
  have hrel := execFor_rel sha sig "step" wotsChainStepBody "p" headStepBody dg (7 - dg)
    (fun _ wR wH => StepRel dg c wa vR4.mem vH2.mem wR wH)
    (fun cur wR wH hcur h => chain_step_rel sha sig dg c wa cur vR4.mem vH2.mem wR wH
      (by omega) (by omega) hz h)
    (7 - dg) 0 vR4 vH2 (by omega) hR0
  rw [Nat.add_zero] at hrel
  obtain ⟨hnR, hnH, hfin⟩ := hrel
  rw [← hloopR] at hnR hfin
  rw [← hloopH] at hnH hfin
  generalize hfR : execStmt sha sig (.forRange "step" (.var "steps") wotsChainStepBody) vR4 = oR at hnR hfin
  generalize hfH : execStmt sha sig (.forFrom "p" (.bin .band (.bin .shr (.lit (3 * c)) (.var "d")) (.lit 7))
      (.lit 7) headStepBody) vH2 = oH at hnH hfin
  have hlistR : execList sha sig
      [ .forRange "step" (.var "steps") wotsChainStepBody
      , .mstore (.bin .add (.lit 128) (.bin .shl (.lit 5) (.var "i"))) (.var "val") ] vR4
      = execStmt sha sig (.mstore (.bin .add (.lit 128) (.bin .shl (.lit 5) (.var "i"))) (.var "val")) oR.1 := by
    rw [execList_cons_none sha sig _ _ _ (by rw [hfR]; exact hnR), execList_single, hfR]
  have hlistH : execList sha sig
      [ .forFrom "p" (.bin .band (.bin .shr (.lit (3 * c)) (.var "d")) (.lit 7)) (.lit 7) headStepBody
      , .mstore (.bin .add (.var "TB") (.lit (64 + 32 * c))) (.mload (.lit 64)) ] vH2
      = execStmt sha sig (.mstore (.bin .add (.var "TB") (.lit (64 + 32 * c))) (.mload (.lit 64))) oH.1 := by
    rw [execList_cons_none sha sig _ _ _ (by rw [hfH]; exact hnH), execList_single, hfH]
  rw [hlistR, hlistH]
  have hiR : oR.1.env "i" = c := by
    rw [← hfR, hloopR, execFor_env_frame sha sig "step" wotsChainStepBody "i" (by decide)
      (by unfold wotsChainStepBody; simp [assignsVarList, assignsVar]) _ _ _,
      e4 _ (by decide) (by decide) (by decide) (by decide)]
    exact hRi
  have henvR : ∀ x, x ≠ "digit" → x ≠ "steps" → x ≠ "val" → x ≠ "chainBase" → x ≠ "step" →
      oR.1.env x = vR.env x := by
    intro x h1 h2 h3 h4 h5
    rw [← hfR, hloopR, execFor_env_frame sha sig "step" wotsChainStepBody x (Ne.symm h5)
      (by unfold wotsChainStepBody; simp [assignsVarList, assignsVar]; exact Ne.symm h3) _ _ _,
      e4 x h1 h2 h3 h4]
  have henvH : ∀ x, x ≠ "p" → oH.1.env x = vH.env x := by
    intro x h1
    rw [← hfH, hloopH, execFor_env_frame sha sig "p" headStepBody x (Ne.symm h1)
      (by unfold headStepBody; simp [assignsVarList, assignsVar]) _ _ _, hH2env]
  have hTB : oH.1.env "TB" = 0x80 := by
    rw [← hfH, hloopH, execFor_env_frame sha sig "p" headStepBody "TB" (by decide)
      (by unfold headStepBody; simp [assignsVarList, assignsVar]) _ _ _, hH2env]
    exact hHTB
  obtain ⟨-, -, -, -, hseedF, hadrsF, -, hvalF, hvloF, hfRF, hfHF, hsRF⟩ := hfin
  have h5 : (128 + c <<< 5 % W) % W = 128 + 32 * c := by
    have : c <<< 5 % W = 32 * c := by
      rw [Nat.shiftLeft_eq, show (2 : Nat) ^ 5 = 32 from rfl, Nat.mul_comm]
      exact Nat.mod_eq_of_lt (lt_W_of_lt (by omega))
    rw [this]; exact Nat.mod_eq_of_lt (lt_W_of_lt (by omega))
  have h6 : (128 + (64 + 32 * c)) % W = 192 + 32 * c := by
    rw [show 128 + (64 + 32 * c) = 192 + 32 * c by omega]
    exact Nat.mod_eq_of_lt (lt_W_of_lt (by omega))
  simp only [execStmt, eval, hiR, hTB, h5, h6]
  refine ⟨trivial, trivial, ?_, ?_, ?_, ?_, ?_, henvR, henvH, ?_, ?_⟩
  · intro k hk
    rw [mstore32_get _ _ _ k hk, mstore32_get _ _ _ k hk, beByte_mload32 _ _ _ hk, hvalF k hk]
  · intro k hk
    rw [mstore32_frame _ _ _ k (by omega), mstore32_frame _ _ _ k (by omega)]
    exact hseedF k hk
  · intro k hk h23 h27
    rw [mstore32_frame _ _ _ (32 + k) (by omega)]
    exact hadrsF k hk h23 h27
  · intro a ha hout hpk
    rw [mstore32_frame _ _ _ a hpk, hfRF a ha hout, hR4mem]
  · intro a ha hpk
    rw [mstore32_frame _ _ _ a (by omega), hfHF a ha, hH2mem, mstore8Mem_frame _ _ _ _ (by omega),
      mstore32_frame _ 64 _ a (by omega)]
  · intro k hk
    rw [mstore32_frame _ _ _ k (by omega), hsRF k hk, hR4mem]
  · intro k hk1 hk2
    rw [mstore32_frame _ _ _ (64 + k) (by omega), hvalF k hk2, hvloF k hk1 hk2]

/-! ## 6. Side conditions and pins -/

/-- The zero-field hypothesis of `chain_block_rel` holds for the ADRS base both programs build,
    `or(shl(224, layer), or(shl(160, idxTree), shl(96, idxLeaf)))`, for field values in range:
    its bytes 23..26 lie below every shifted field. -/
theorem wotsAdrs_zero_field (layer tree leaf : Nat) (hl : layer < 2 ^ 32) (ht : tree < 2 ^ 64)
    (hf : leaf < 2 ^ 32) :
    ∀ j, 23 ≤ j → j ≤ 26 →
      beByte ((layer <<< 224) % W ||| ((tree <<< 160) % W ||| (leaf <<< 96) % W)) j = 0 := by
  intro j hj1 hj2
  have hW : W = 2 ^ 256 := rfl
  have e1 : (layer <<< 224) % W = layer <<< (8 * 28) := by
    rw [hW]; apply Nat.mod_eq_of_lt; rw [Nat.shiftLeft_eq]
    calc layer * 2 ^ 224 < 2 ^ 32 * 2 ^ 224 := Nat.mul_lt_mul_of_pos_right hl (Nat.two_pow_pos _)
      _ = 2 ^ 256 := by rw [← Nat.pow_add]
  have e2 : (tree <<< 160) % W = tree <<< (8 * 20) := by
    rw [hW]; apply Nat.mod_eq_of_lt; rw [Nat.shiftLeft_eq]
    calc tree * 2 ^ 160 < 2 ^ 64 * 2 ^ 160 := Nat.mul_lt_mul_of_pos_right ht (Nat.two_pow_pos _)
      _ ≤ 2 ^ 256 := by rw [← Nat.pow_add]; exact Nat.pow_le_pow_right (by decide) (by decide)
  have e3 : (leaf <<< 96) % W = leaf <<< (8 * 12) := by
    rw [hW]; apply Nat.mod_eq_of_lt; rw [Nat.shiftLeft_eq]
    calc leaf * 2 ^ 96 < 2 ^ 32 * 2 ^ 96 := Nat.mul_lt_mul_of_pos_right hf (Nat.two_pow_pos _)
      _ ≤ 2 ^ 256 := by rw [← Nat.pow_add]; exact Nat.pow_le_pow_right (by decide) (by decide)
  rw [e1, e2, e3, beByte_lor, beByte_lor, beByte_shiftLeft_byte _ _ _ (by omega),
    beByte_shiftLeft_byte _ _ _ (by omega), beByte_shiftLeft_byte _ _ _ (by omega),
    if_neg (by omega), if_neg (by omega), if_neg (by omega), uint8_or_zero, uint8_or_zero]

set_option maxRecDepth 100000 in
set_option maxHeartbeats 4000000 in
/-- The reference's per-chain loop is `forRange "i" 43 wotsChainBody` (statement 15 of its
    layer loop). -/
theorem ref_chainLoop_pin :
    (loopBody c10Program[28]?)[15]? = some (.forRange "i" (.lit 43) wotsChainBody) := rfl

set_option maxRecDepth 100000 in
set_option maxHeartbeats 4000000 in
/-- The optimized layer loop's statements 16..187 are exactly `chainBlock 0 … chainBlock 42`
    (one template, all 43 chains). -/
theorem head_chainBlocks_pin :
    ((loopBody c10HeadProgram[28]?).drop 16).take 172 = (List.range 43).flatMap chainBlock := rfl

end SphincsCVerify.Interpreter.C10.RelChain

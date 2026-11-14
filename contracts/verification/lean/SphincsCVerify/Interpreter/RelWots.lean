/-
SphincsCVerify.Interpreter.RelWots — RESEARCH (#1155 gas track, batch 8): the whole WOTS chain
phase of one hypertree layer, related. The reference runs `forRange "i" 43 wotsChainBody`; the
optimized v1 runs `mstore(0x20, wotsAdrs)` followed by the 43 unrolled `chainBlock c`.
`wots_layer_rel` composes `chain_block_rel` (RelChain.lean) over all 43 chains with a generic
loop-vs-unrolled lemma (`execFor_vs_blocks`): both fall through and the 43 chain endpoints the
reference stores at `0x80 + 32i` equal, byte for byte, the ones the optimized v1 stores at
`0xC0 + 32i`. `head_wotsLayer_pin` ties the 173 statements to the optimized layer loop by `rfl`.

Spec-free (no spec function or lemma; arbitrary hash oracle). Mathlib-free; no
`sorry`/`admit`/`axiom`/`native_decide`/`bv_decide`.
-/

import SphincsCVerify.Interpreter.RelChain

namespace SphincsCVerify.Interpreter.C10.RelWots

open SphincsCVerify.Interpreter
open SphincsCVerify.Interpreter.C10
open SphincsCVerify.Interpreter.C10.RelE1 (loopBody execList_single)
open SphincsCVerify.Interpreter.C10.RelChain
open SphincsCVerify.Spec (ByteVec)

/-! ## 1. A loop against its unrolled blocks (one-time infrastructure) -/

/-- **Loop vs unrolled blocks.** If iteration `c` of a loop and block `c` of an unrolled
    sequence fall through and preserve `Inv`, then the loop and the concatenated blocks
    (`(List.range' c rem).flatMap blk`) do. -/
theorem execFor_vs_blocks {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n)
    (v : String) (body : List Stmt) (blk : Nat → List Stmt) (N : Nat)
    (Inv : Nat → VM → VM → Prop)
    (hstep : ∀ c w1 w2, c < N → Inv c w1 w2 →
      (execList sha sig body { w1 with env := setVar w1.env v c }).2 = none
      ∧ (execList sha sig (blk c) w2).2 = none
      ∧ Inv (c + 1) (execList sha sig body { w1 with env := setVar w1.env v c }).1
          (execList sha sig (blk c) w2).1) :
    ∀ rem c w1 w2, c + rem = N → Inv c w1 w2 →
      (execFor sha sig v body rem c w1).2 = none
      ∧ (execList sha sig ((List.range' c rem).flatMap blk) w2).2 = none
      ∧ Inv N (execFor sha sig v body rem c w1).1
          (execList sha sig ((List.range' c rem).flatMap blk) w2).1
  | 0, c, w1, w2, hN, hR => by
      rw [execFor, List.range'_zero, List.flatMap_nil, execList]
      rw [Nat.add_zero] at hN
      subst hN
      exact ⟨rfl, rfl, hR⟩
  | rem + 1, c, w1, w2, hN, hR => by
      obtain ⟨h1, h2, h3⟩ := hstep c w1 w2 (by omega) hR
      rw [execFor, List.range'_succ, List.flatMap_cons, execList_append]
      cases e1 : execList sha sig body { w1 with env := setVar w1.env v c } with
      | mk a1 o1 =>
        cases e2 : execList sha sig (blk c) w2 with
        | mk a2 o2 =>
          rw [e1] at h1 h3
          rw [e2] at h2 h3
          simp only at h1 h2 h3
          subst h1
          subst h2
          simp only
          exact execFor_vs_blocks sha sig v body blk N Inv hstep rem (c + 1) a1 a2 (by omega) h3

/-! ## 2. The invariant between chains, and the composition -/

/-- What holds before chain `c`: the variables both chain bodies read, the low-memory coupling,
    and the endpoints of chains `0 … c-1` already equal. -/
def WotsInv (d wp wa : Nat) (mR0 mH0 : ByteMemory) (eR0 eH0 : VarEnv) (c : Nat) (w1 w2 : VM) : Prop :=
  w1.env "d" = d ∧ w1.env "wotsPtr" = wp ∧ w1.env "wotsAdrs" = wa ∧ w1.env "N_MASK" = NMASK
  ∧ w1.env "OUT" = 0x600
  ∧ w2.env "d" = d ∧ w2.env "wotsPtr" = wp ∧ w2.env "N_MASK" = NMASK ∧ w2.env "TB" = 0x80
  ∧ (∀ k, k < 32 → w2.mem k = w1.mem k)
  ∧ (∀ k, k < 32 → k ≠ 23 → k ≠ 27 → w2.mem (32 + k) = beByte wa k)
  ∧ (∀ i, i < c → ∀ k, k < 32 → w1.mem (0x80 + 32 * i + k) = w2.mem (0xC0 + 32 * i + k))
  ∧ (∀ k, k < 32 → w1.mem k = mR0 k)
  ∧ (0 < c → ∀ k, 16 ≤ k → k < 32 → w2.mem (64 + k) = 0)
  ∧ (∀ a, 96 ≤ a → (a < 0x600 ∨ 0x620 ≤ a) → (a < 0x80 ∨ 0x80 + 32 * c ≤ a) → w1.mem a = mR0 a)
  ∧ (∀ a, 96 ≤ a → (a < 0xC0 ∨ 0xC0 + 32 * c ≤ a) → w2.mem a = mH0 a)
  ∧ (∀ x, x ≠ "digit" → x ≠ "steps" → x ≠ "val" → x ≠ "chainBase" → x ≠ "step" → x ≠ "i" →
      w1.env x = eR0 x)
  ∧ (∀ x, x ≠ "p" → w2.env x = eH0 x)

set_option maxHeartbeats 4000000 in
/-- One chain preserves the invariant (and adds its own endpoint). -/
theorem wots_inv_step {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n)
    (d wp wa : Nat) (hwp : wp < 4096) (hz : ∀ j, 23 ≤ j → j ≤ 26 → beByte wa j = 0)
    (mR0 mH0 : ByteMemory) (eR0 eH0 : VarEnv) (c : Nat) (w1 w2 : VM) (hc : c < 43)
    (h : WotsInv d wp wa mR0 mH0 eR0 eH0 c w1 w2) :
    (execList sha sig wotsChainBody { w1 with env := setVar w1.env "i" c }).2 = none
    ∧ (execList sha sig (chainBlock c) w2).2 = none
    ∧ WotsInv d wp wa mR0 mH0 eR0 eH0 (c + 1)
        (execList sha sig wotsChainBody { w1 with env := setVar w1.env "i" c }).1
        (execList sha sig (chainBlock c) w2).1 := by
  obtain ⟨h1d, h1wp, h1wa, h1N, h1OUT, h2d, h2wp, h2N, h2TB, hseed, hadrs, hend, hsR, -, hfR0, hfH0,
    heR0, heH0⟩ := h
  have r := chain_block_rel sha sig c d wp wa { w1 with env := setVar w1.env "i" c } w2 hc hwp hz
    (by show setVar w1.env "i" c "d" = d; rw [setVar_get_ne _ _ _ _ (by decide)]; exact h1d)
    (by show setVar w1.env "i" c "wotsPtr" = wp; rw [setVar_get_ne _ _ _ _ (by decide)]; exact h1wp)
    (by show setVar w1.env "i" c "wotsAdrs" = wa; rw [setVar_get_ne _ _ _ _ (by decide)]; exact h1wa)
    (by show setVar w1.env "i" c "N_MASK" = NMASK; rw [setVar_get_ne _ _ _ _ (by decide)]; exact h1N)
    (by show setVar w1.env "i" c "OUT" = 0x600; rw [setVar_get_ne _ _ _ _ (by decide)]; exact h1OUT)
    (by show setVar w1.env "i" c "i" = c; exact setVar_get_eq _ _ _)
    h2d h2wp h2N h2TB hseed hadrs
  obtain ⟨hnR, hnH, hstore, hseed', hadrs', hfrR, hfrH, henvR, henvH, hsR', hpad'⟩ := r
  refine ⟨hnR, hnH, ?_⟩
  have eR : ∀ x, x ≠ "digit" → x ≠ "steps" → x ≠ "val" → x ≠ "chainBase" → x ≠ "step" → x ≠ "i" →
      (execList sha sig wotsChainBody { w1 with env := setVar w1.env "i" c }).1.env x = w1.env x := by
    intro x a1 a2 a3 a4 a5 a6
    rw [henvR x a1 a2 a3 a4 a5]
    show setVar w1.env "i" c x = _
    exact setVar_get_ne _ _ _ _ a6
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, hseed', hadrs', ?_, ?_, fun _ => hpad', ?_, ?_, ?_, ?_⟩
  · rw [eR _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)]; exact h1d
  · rw [eR _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)]; exact h1wp
  · rw [eR _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)]; exact h1wa
  · rw [eR _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)]; exact h1N
  · rw [eR _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide)]; exact h1OUT
  · rw [henvH _ (by decide)]; exact h2d
  · rw [henvH _ (by decide)]; exact h2wp
  · rw [henvH _ (by decide)]; exact h2N
  · rw [henvH _ (by decide)]; exact h2TB
  · intro i hi k hk
    by_cases hic : i = c
    · subst hic; exact hstore k hk
    · have hlt : i < c := by omega
      rw [hfrR _ (by omega) (by omega) (by omega), hfrH _ (by omega) (by omega)]
      show w1.mem _ = _
      exact hend i hlt k hk
  · intro k hk
    rw [hsR' k hk]
    exact hsR k hk
  · intro a ha hout hpk
    rw [hfrR a ha hout (by omega)]
    exact hfR0 a ha hout (by omega)
  · intro a ha hpk
    rw [hfrH a ha (by omega)]
    exact hfH0 a ha (by omega)
  · intro x a1 a2 a3 a4 a5 a6
    rw [eR x a1 a2 a3 a4 a5 a6]
    exact heR0 x a1 a2 a3 a4 a5 a6
  · intro x a1
    rw [henvH x a1]
    exact heH0 x a1

set_option maxHeartbeats 4000000 in
/-- **The WOTS chain phase of one layer, related.** The reference's `forRange "i" 43 wotsChainBody`
    and the optimized `mstore(0x20, wotsAdrs)` + `chainBlock 0 … chainBlock 42`, from states that
    agree on `d` / `wotsPtr` / `wotsAdrs` / `N_MASK` and have the same seed bytes, with
    `wotsPtr < 4096`, `wotsAdrs` bytes 23..26 zero, the reference's `OUT = 0x600` and the
    optimized `TB = 0x80` (`RelWotsEntry.wots_entry_rel` derives all of these from the layer
    entry), both fall
    through and store the same 43 chain endpoints (reference at `0x80 + 32i`, optimized at
    `0xC0 + 32i`); the seed bytes stay coupled, the reference's are unchanged, the optimized v1's
    zero padding at `0x50..0x60` holds, all memory at or above `0x60` outside the endpoint stores
    (and the reference's hash scratch) is unchanged, and so is every variable outside the chain
    bodies' scratch. Arbitrary hash oracle. -/
theorem wots_layer_rel {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n)
    (d wp wa : Nat) (vR vH : VM) (hwp : wp < 4096) (hz : ∀ j, 23 ≤ j → j ≤ 26 → beByte wa j = 0)
    (hRd : vR.env "d" = d) (hRwp : vR.env "wotsPtr" = wp) (hRwa : vR.env "wotsAdrs" = wa)
    (hRN : vR.env "N_MASK" = NMASK) (hROUT : vR.env "OUT" = 0x600)
    (hHd : vH.env "d" = d) (hHwp : vH.env "wotsPtr" = wp) (hHwa : vH.env "wotsAdrs" = wa)
    (hHN : vH.env "N_MASK" = NMASK) (hHTB : vH.env "TB" = 0x80)
    (hseed : ∀ k, k < 32 → vH.mem k = vR.mem k) :
    (execStmt sha sig (.forRange "i" (.lit 43) wotsChainBody) vR).2 = none
    ∧ (execList sha sig (.mstore (.lit 32) (.var "wotsAdrs") :: (List.range 43).flatMap chainBlock) vH).2
        = none
    ∧ (∀ i, i < 43 → ∀ k, k < 32 →
        (execStmt sha sig (.forRange "i" (.lit 43) wotsChainBody) vR).1.mem (0x80 + 32 * i + k)
          = (execList sha sig (.mstore (.lit 32) (.var "wotsAdrs") :: (List.range 43).flatMap chainBlock)
              vH).1.mem (0xC0 + 32 * i + k))
    ∧ (∀ k, k < 32 →
        (execList sha sig (.mstore (.lit 32) (.var "wotsAdrs") :: (List.range 43).flatMap chainBlock)
          vH).1.mem k
          = (execStmt sha sig (.forRange "i" (.lit 43) wotsChainBody) vR).1.mem k)
    ∧ (∀ k, k < 32 → (execStmt sha sig (.forRange "i" (.lit 43) wotsChainBody) vR).1.mem k = vR.mem k)
    ∧ (∀ k, 16 ≤ k → k < 32 →
        (execList sha sig (.mstore (.lit 32) (.var "wotsAdrs") :: (List.range 43).flatMap chainBlock)
          vH).1.mem (64 + k) = 0)
    ∧ (∀ a, 96 ≤ a → (a < 0x600 ∨ 0x620 ≤ a) → (a < 0x80 ∨ 0x80 + 32 * 43 ≤ a) →
        (execStmt sha sig (.forRange "i" (.lit 43) wotsChainBody) vR).1.mem a = vR.mem a)
    ∧ (∀ a, 96 ≤ a → (a < 0xC0 ∨ 0xC0 + 32 * 43 ≤ a) →
        (execList sha sig (.mstore (.lit 32) (.var "wotsAdrs") :: (List.range 43).flatMap chainBlock)
          vH).1.mem a = vH.mem a)
    ∧ (∀ x, x ≠ "digit" → x ≠ "steps" → x ≠ "val" → x ≠ "chainBase" → x ≠ "step" → x ≠ "i" →
        (execStmt sha sig (.forRange "i" (.lit 43) wotsChainBody) vR).1.env x = vR.env x)
    ∧ (∀ x, x ≠ "p" →
        (execList sha sig (.mstore (.lit 32) (.var "wotsAdrs") :: (List.range 43).flatMap chainBlock)
          vH).1.env x = vH.env x) := by
  rw [execList_cons_none sha sig _ _ _ (by simp only [execStmt])]
  simp only [execStmt, eval, hHwa]
  rw [List.range_eq_range']
  have h0 : WotsInv d wp wa vR.mem vH.mem vR.env vH.env 0 vR { vH with mem := mstore32 vH.mem 32 wa } := by
    refine ⟨hRd, hRwp, hRwa, hRN, hROUT, hHd, hHwp, hHN, hHTB, ?_, ?_, ?_, fun _ _ => rfl,
      fun h => absurd h (by omega), fun _ _ _ _ => rfl, ?_, fun _ _ _ _ _ _ _ => rfl, fun _ _ => rfl⟩
    · intro k hk
      show mstore32 vH.mem 32 wa k = _
      rw [mstore32_frame _ _ _ _ (by omega)]; exact hseed k hk
    · intro k hk _ _
      show mstore32 vH.mem 32 wa (32 + k) = _
      exact mstore32_get _ _ _ _ hk
    · intro i hi; omega
    · intro a ha _
      show mstore32 vH.mem 32 wa a = _
      exact mstore32_frame _ _ _ _ (by omega)
  have r := execFor_vs_blocks sha sig "i" wotsChainBody chainBlock 43
    (WotsInv d wp wa vR.mem vH.mem vR.env vH.env)
    (fun c w1 w2 hc h => wots_inv_step sha sig d wp wa hwp hz vR.mem vH.mem vR.env vH.env c w1 w2 hc h)
    43 0 vR { vH with mem := mstore32 vH.mem 32 wa } (by omega) h0
  obtain ⟨hnR, hnH, hinv⟩ := r
  obtain ⟨-, -, -, -, -, -, -, -, -, hseedF, -, hendF, hsRF, hpadF, hfRF, hfHF, heRF, heHF⟩ := hinv
  exact ⟨hnR, hnH, fun i hi k hk => hendF i hi k hk, hseedF, hsRF, hpadF (by omega), hfRF, hfHF, heRF,
    heHF⟩

/-! ## 3. The pin -/

set_option maxRecDepth 100000 in
set_option maxHeartbeats 4000000 in
/-- The optimized layer loop's statements 15..187 are `mstore(0x20, wotsAdrs)` followed by the 43
    chain blocks; with `ref_chainLoop_pin` this fixes both sides of `wots_layer_rel` in the two
    programs. -/
theorem head_wotsLayer_pin :
    ((loopBody c10HeadProgram[28]?).drop 15).take 173
      = .mstore (.lit 32) (.var "wotsAdrs") :: (List.range 43).flatMap chainBlock := rfl

end SphincsCVerify.Interpreter.C10.RelWots

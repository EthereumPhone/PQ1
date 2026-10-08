/- Actual private FORS tree recovery: leaf hash followed by eleven siblings. -/
import Extracted.ForsRecovery.Funs
import Extracted.MerkleVerifySpec

open Aeneas Aeneas.Std Result
namespace Extracted.Equiv
open sphincs_c10

def forsRecoveryAdrs (ht tree : Std.U32) (height idx : Nat) : Std.Array Std.U8 32#usize :=
  ⟨(specMakeAdrs 0 ht.val 3 tree.val 0 height idx).map
      (fun n => (⟨BitVec.ofNat 8 n⟩ : Std.U8)), by simp [specMakeAdrs, u32be, u64be]⟩

noncomputable def forsRecoveryFold (seed : Std.Array Std.U8 32#usize) (ht tree : Std.U32) :
    List (Std.Array Std.U8 16#usize) → Std.Array Std.U8 16#usize → Nat → Nat →
    Std.Array Std.U8 16#usize
  | [], node, _, _ => node
  | sibling :: rest, node, idx, h =>
      let a := forsRecoveryAdrs ht tree (h+1) (idx/2)
      let next := if idx % 2 = 0 then th_pair_pure seed a (pad16p node) (pad16p sibling)
          else th_pair_pure seed a (pad16p sibling) (pad16p node)
      forsRecoveryFold seed ht tree rest next (idx/2) (h+1)

theorem forsRecoveryAdrs_eq_of_map_val (a : Std.Array Std.U8 32#usize)
    (ht tree : Std.U32) (h idx : Nat)
    (hm : a.val.map (·.val) = specMakeAdrs 0 ht.val 3 tree.val 0 h idx) :
    forsRecoveryAdrs ht tree h idx = a := by
  apply Subtype.ext
  change (specMakeAdrs 0 ht.val 3 tree.val 0 h idx).map
    (fun n => (⟨BitVec.ofNat 8 n⟩ : Std.U8)) = a.val
  rw [← hm, List.map_map]
  conv_rhs => rw [← List.map_id a.val]
  apply List.map_congr_left
  intro x _
  exact U8.mk_ofNat_val x

set_option maxHeartbeats 16000000 in
set_option maxRecDepth 100000 in
/-- Loop lemma (continuation form): folding the remaining siblings from the
    current state yields the total fold. -/
theorem fors_recovery_loop_value
    (iter : core.ops.range.Range Std.Usize) (seed : Std.Array Std.U8 32#usize)
    (ht : Std.U32) (tree : Std.U32)
    (auth_path : Std.Array (Std.Array Std.U8 16#usize) 11#usize)
    (node : Std.Array Std.U8 16#usize) (idx : Std.U32)
    (total : Std.Array Std.U8 16#usize)
    (hend : iter.«end».val = 11) (hle : iter.start.val ≤ 11)
    (hcont : forsRecoveryFold seed ht tree (auth_path.val.drop iter.start.val) node idx.val
               iter.start.val = total) :
    hypertree.reconstruct_fors_root_loop iter seed ht tree auth_path node idx
      ⦃ r => r = total ⦄ := by
  unfold hypertree.reconstruct_fors_root_loop
  apply Aeneas.Std.loop.spec_decr_nat
    (measure := fun (s : core.ops.range.Range Std.Usize ×
                      Std.Array Std.U8 16#usize × Std.U32) =>
       s.1.«end».val - s.1.start.val)
    (inv := fun (s : core.ops.range.Range Std.Usize ×
                     Std.Array Std.U8 16#usize × Std.U32) =>
       s.1.«end».val = 11 ∧ s.1.start.val ≤ 11 ∧
       forsRecoveryFold seed ht tree (auth_path.val.drop s.1.start.val) s.2.1 s.2.2.val
         s.1.start.val = total)
  · rintro ⟨it, nd, ix⟩ ⟨hbnd, hsle, hfold⟩
    simp only at hbnd hsle hfold
    unfold hypertree.reconstruct_fors_root_loop.body
    simp only [lift, core.convert.num.FromU64U32.from]
    let* ⟨ob, iter1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨h, it', heq, hh, hlt, hend', hstart'⟩
    · subst ho
      simp only [WP.spec_ok]
      have h9 : it.start.val = 11 := by omega
      have hlen9 : auth_path.val.length = 11 := by
        have := auth_path.property; simpa using this
      rw [h9, List.drop_of_length_le (by rw [hlen9])] at hfold
      simpa [forsRecoveryFold] using hfold
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      have hhv : h.val = it.start.val := by rw [hh]
      have hh8 : h.val ≤ 10 := by omega
      have hlen9 : auth_path.val.length = 11 := by
        have := auth_path.property; simpa using this
      step* <;> first | scalar_tac | skip
      let* ⟨adrs, hadrs⟩ ← make_adrs_spec 0#u32 (⟨BitVec.setWidth 64 ht.bv⟩ : Std.U64) params.ADRS_FORS_TREE tree 0#u32
            (UScalar.cast UScalarTy.U32 i1) parent_idx
      let* ⟨sibling, hsib⟩ ← Array.index_usize_spec auth_path h (by scalar_tac)
      -- shared value facts
      have hpv : parent_idx.val = ix.val / 2 := by
        rw [parent_idx_post1, Nat.shiftRight_eq_div_pow, pow_one]
      have hcastv : (UScalar.cast UScalarTy.U32 i1).val = h.val + 1 := by
        rw [UScalar.cast_val_eq, i1_post]
        exact Nat.mod_eq_of_lt (by
          calc h.val + 1 ≤ 11 := by omega
            _ < 2 ^ UScalarTy.U32.numBits := by norm_num)
      have hatype : ((params.ADRS_FORS_TREE : Std.U32)).val = 3 := by
        simp [params.ADRS_FORS_TREE]
      have hht : (⟨BitVec.setWidth 64 ht.bv⟩ : Std.U64).val = ht.val := by
        exact BitVec.toNat_setWidth_of_le (by decide)
      rw [hatype, hcastv, hpv, hht] at hadrs
      have hadrs_eq : forsRecoveryAdrs ht tree (h.val+1) (ix.val / 2) = adrs :=
        forsRecoveryAdrs_eq_of_map_val adrs ht tree (h.val+1) (ix.val / 2) hadrs
      have hsib2 : sibling = auth_path.val[h.val]! := by
        rw [hsib]
        exact (getElem!_pos _ _ (by rw [hlen9]; omega)).symm
      -- massage hfold into one-step-unfolded form
      rw [show (↑it.start : Nat) = ↑h from hhv.symm] at hfold
      rw [← List.cons_getElem_drop_succ (n := h.val) (h := by rw [hlen9]; omega)] at hfold
      simp only [forsRecoveryFold] at hfold
      split
      · -- even: node left, sibling right
        rename_i hcond
        have hmod : ix.val % 2 = 0 := by
          have hv := congrArg UScalar.val hcond
          rw [UScalar.val_and, show ((1#u32) : Std.U32).val = 1 from rfl,
              show ((0#u32) : Std.U32).val = 0 from rfl,
              show (1:Nat) = 2 ^ 1 - 1 from rfl, Nat.and_two_pow_sub_one_eq_mod] at hv
          simpa using hv
        rw [if_pos hmod] at hfold
        let* ⟨a, ha⟩ ← pad16_spec nd
        let* ⟨a1, ha1⟩ ← pad16_spec sibling
        step* <;> first | scalar_tac | skip
      · -- odd: sibling left, node right
        rename_i hcond
        have hmod : ¬ ix.val % 2 = 0 := by
          intro h0
          apply hcond
          apply UScalar.eq_of_val_eq
          rw [UScalar.val_and, show ((1#u32) : Std.U32).val = 1 from rfl,
              show ((0#u32) : Std.U32).val = 0 from rfl,
              show (1:Nat) = 2 ^ 1 - 1 from rfl, Nat.and_two_pow_sub_one_eq_mod]
          simpa using h0
        rw [if_neg hmod] at hfold
        let* ⟨a, ha⟩ ← pad16_spec sibling
        let* ⟨a1, ha1⟩ ← pad16_spec nd
        step* <;> first | scalar_tac | skip
  · exact ⟨hend, hle, hcont⟩


/-- The actual Rust helper hashes the secret once, then folds all eleven siblings. -/
theorem fors_recovery_spec (seed : Std.Array Std.U8 32#usize)
    (ht tree idx : Std.U32) (secret : Std.Array Std.U8 16#usize)
    (auth : Std.Array (Std.Array Std.U8 16#usize) 11#usize) :
    hypertree.reconstruct_fors_root seed ht tree idx secret auth ⦃ r =>
      r = forsRecoveryFold seed ht tree auth.val
        (th_pure seed (forsRecoveryAdrs ht tree 0 idx.val) (pad16p secret)) idx.val 0 ⦄ := by
  unfold hypertree.reconstruct_fors_root
  simp only [lift, core.convert.num.FromU64U32.from]
  let* ⟨adrs, hadrs⟩ ← make_adrs_spec 0#u32
    (⟨BitVec.setWidth 64 ht.bv⟩ : Std.U64) params.ADRS_FORS_TREE tree 0#u32 0#u32 idx
  have hht : (⟨BitVec.setWidth 64 ht.bv⟩ : Std.U64).val = ht.val :=
    BitVec.toNat_setWidth_of_le (by decide)
  have ha : forsRecoveryAdrs ht tree 0 idx.val = adrs := by
    apply forsRecoveryAdrs_eq_of_map_val
    simpa only [params.ADRS_FORS_TREE, hht] using hadrs
  let* ⟨p, hp⟩ ← pad16_spec secret
  let* ⟨node, hn⟩ ← hash.th_spec seed adrs p
  apply fors_recovery_loop_value _ _ _ _ _ _ _ _ (by simp [params.A]) (by simp)
  simpa only [show (0#usize).val = 0 from rfl, List.drop_zero, hn, hp, ha]

end Extracted.Equiv

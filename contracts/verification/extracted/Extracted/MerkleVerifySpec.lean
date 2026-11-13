/- §33 rank 6 — merkle::verify_auth_path: FUNCTIONAL spec (statement only).

   The XMSS auth-path walk: from a leaf and its index, fold the 9 siblings
   upward — parent ADRS at height h+1 and index idx>>1, left/right operand
   order selected by idx&1, node = th_pair(seed, adrs, l, r). The index walk
   and operand order ARE the security-relevant content (a swapped operand or
   a wrong parent index verifies a different tree); th_pair itself is the
   uninterpreted boundary (th_pair_pure, Merkle/FunsExternal.lean).

   The ADRS bytes are pinned via specMakeAdrs (AdrsEquiv.lean), which is
   already proven equal to BOTH the extracted make_adrs (make_adrs_spec) and
   the vendored on-chain spec (firmware_make_adrs_matches_vendored) — so this
   statement composes into the SpecBridge chain.

   Proof plan: loop.spec_decr_nat with invariant
     state after k steps = (authFold (auth.take k) leaf idx 0 unrolled k times,
                            idx >>> k)
   i.e. node_k = authFold seed layer tree (auth.val.take k) leaf_node idx.val 0
   and idx_k.val = leaf_idx.val >>> k; each step: make_adrs_spec gives the
   adrs bytes = specMakeAdrs (lift to adrsBytes via map_val_mk-style argument:
   entries < 256 so BitVec.ofNat is injective on them), pad16 step* gives the
   pure pad, the &&&1 / >>>1 selections match %2 / /2 by scalar_tac. -/
import Extracted.Merkle.Funs
import Extracted.HashSpecs
import Extracted.AdrsEquiv
import Extracted.SetSliceLemmas
import Extracted.ForsLoop

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

open sphincs_c10

/-- Pure `pad16`: the 16-byte node left-justified in a zero 32-byte block. -/
def pad16p (v : Std.Array Std.U8 16#usize) : Std.Array Std.U8 32#usize :=
  ⟨v.val ++ List.replicate 16 0#u8, by have := v.property; simp_all⟩

/-- Pure tree-ADRS at height `h+1`, parent index `pidx` — the exact
    `specMakeAdrs` bytes (ADRS_TREE = 2, kp = ci = 0), lifted to `U8`s.
    Entries are < 256 by construction so `BitVec.ofNat` loses nothing. -/
def treeAdrs (layer : Std.U32) (tree : Std.U64) (h : Nat) (pidx : Nat) :
    Std.Array Std.U8 32#usize :=
  ⟨(specMakeAdrs layer.val tree.val 2 0 0 (h + 1) pidx).map
      (fun n => (⟨BitVec.ofNat 8 n⟩ : Std.U8)), by
    simp [specMakeAdrs, u32be, u64be]⟩

/-- The pure auth-path fold mirroring the Rust loop step-for-step. -/
noncomputable def authFold (seed : Std.Array Std.U8 32#usize) (layer : Std.U32) (tree : Std.U64) :
    List (Std.Array Std.U8 16#usize) → Std.Array Std.U8 16#usize → Nat → Nat →
    Std.Array Std.U8 16#usize
  | [], node, _, _ => node
  | sib :: rest, node, idx, h =>
      let adrs := treeAdrs layer tree h (idx / 2)
      let next :=
        if idx % 2 = 0 then th_pair_pure seed adrs (pad16p node) (pad16p sib)
        else th_pair_pure seed adrs (pad16p sib) (pad16p node)
      authFold seed layer tree rest next (idx / 2) (h + 1)

/-- Lifting the byte value back through `BitVec.ofNat` is the identity. -/
theorem U8.mk_ofNat_val (x : Std.U8) : (⟨BitVec.ofNat 8 x.val⟩ : Std.U8) = x := by
  have h : BitVec.ofNat 8 x.val = x.bv := by
    rw [show x.val = x.bv.toNat from rfl, BitVec.ofNat_toNat, BitVec.setWidth_eq]
  rw [h]

/-- An array whose byte values match `specMakeAdrs …` IS the corresponding
    `treeAdrs` (the `BitVec.ofNat` lift loses nothing below 256). -/
theorem treeAdrs_eq_of_map_val (a : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (h pidx : Nat)
    (hmap : a.val.map (·.val) = specMakeAdrs layer.val tree.val 2 0 0 (h + 1) pidx) :
    treeAdrs layer tree h pidx = a := by
  apply Subtype.ext
  show (specMakeAdrs layer.val tree.val 2 0 0 (h + 1) pidx).map
      (fun n => (⟨BitVec.ofNat 8 n⟩ : Std.U8)) = a.val
  rw [← hmap, List.map_map]
  conv_rhs => rw [← List.map_id a.val]
  apply List.map_congr_left
  intro x _
  exact U8.mk_ofNat_val x

set_option maxHeartbeats 4000000 in
/-- `hash.pad16` computes the pure left-justified pad. -/
theorem pad16_spec (v : Std.Array Std.U8 16#usize) :
    hash.pad16 v ⦃ r => r = pad16p v ⦄ := by
  have hv : v.val.length = 16 := by have := v.property; simpa using this
  unfold hash.pad16
  simp only [params.N]
  step* <;> first | scalar_tac | skip
  apply Subtype.ext
  simp only [s2_post, s1_post, s_post3, Array.val_to_slice, Array.repeat_val]
  norm_num
  have hkey := Extracted.SetSlice.setSlice!_append_replicate
      ([] : List Std.U8) 32 v.val 0#u8 (by rw [hv]; omega)
  simp only [List.nil_append, List.length_nil] at hkey
  rw [hkey]
  simp [pad16p, hv]

set_option maxHeartbeats 16000000 in
set_option maxRecDepth 100000 in
/-- Loop lemma (continuation form): folding the remaining siblings from the
    current state yields the total fold. -/
theorem verify_auth_path_loop_value
    (iter : core.ops.range.Range Std.Usize) (seed : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64)
    (auth_path : Std.Array (Std.Array Std.U8 16#usize) 9#usize)
    (node : Std.Array Std.U8 16#usize) (idx : Std.U32)
    (total : Std.Array Std.U8 16#usize)
    (hend : iter.«end».val = 9) (hle : iter.start.val ≤ 9)
    (hcont : authFold seed layer tree (auth_path.val.drop iter.start.val) node idx.val
               iter.start.val = total) :
    merkle.verify_auth_path_loop iter seed layer tree auth_path node idx
      ⦃ r => r = total ⦄ := by
  unfold merkle.verify_auth_path_loop
  apply Aeneas.Std.loop.spec_decr_nat
    (measure := fun (s : core.ops.range.Range Std.Usize ×
                      Std.Array Std.U8 16#usize × Std.U32) =>
       s.1.«end».val - s.1.start.val)
    (inv := fun (s : core.ops.range.Range Std.Usize ×
                     Std.Array Std.U8 16#usize × Std.U32) =>
       s.1.«end».val = 9 ∧ s.1.start.val ≤ 9 ∧
       authFold seed layer tree (auth_path.val.drop s.1.start.val) s.2.1 s.2.2.val
         s.1.start.val = total)
  · rintro ⟨it, nd, ix⟩ ⟨hbnd, hsle, hfold⟩
    simp only at hbnd hsle hfold
    unfold merkle.verify_auth_path_loop.body
    simp only [lift]
    let* ⟨ob, iter1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨h, it', heq, hh, hlt, hend', hstart'⟩
    · subst ho
      simp only [WP.spec_ok]
      have h9 : it.start.val = 9 := by omega
      have hlen9 : auth_path.val.length = 9 := by
        have := auth_path.property; simpa using this
      rw [h9, List.drop_of_length_le (by rw [hlen9])] at hfold
      simpa [authFold] using hfold
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      have hhv : h.val = it.start.val := by rw [hh]
      have hh8 : h.val ≤ 8 := by omega
      have hlen9 : auth_path.val.length = 9 := by
        have := auth_path.property; simpa using this
      step* <;> first | scalar_tac | skip
      let* ⟨adrs, hadrs⟩ ← make_adrs_spec layer tree params.ADRS_TREE 0#u32 0#u32
            (UScalar.cast UScalarTy.U32 i) parent_idx
      let* ⟨sibling, hsib⟩ ← Array.index_usize_spec auth_path h (by scalar_tac)
      -- shared value facts
      have hpv : parent_idx.val = ix.val / 2 := by
        rw [parent_idx_post1, Nat.shiftRight_eq_div_pow, pow_one]
      have hcastv : (UScalar.cast UScalarTy.U32 i).val = h.val + 1 := by
        rw [UScalar.cast_val_eq, i_post]
        exact Nat.mod_eq_of_lt (by
          calc h.val + 1 ≤ 9 := by omega
            _ < 2 ^ UScalarTy.U32.numBits := by norm_num)
      have hatype : ((params.ADRS_TREE : Std.U32)).val = 2 := by
        simp [params.ADRS_TREE]
      rw [hatype, hcastv, hpv] at hadrs
      have hadrs_eq : treeAdrs layer tree h.val (ix.val / 2) = adrs :=
        treeAdrs_eq_of_map_val adrs layer tree h.val (ix.val / 2) hadrs
      have hsib2 : sibling = auth_path.val[h.val]! := by
        rw [hsib]
        exact (getElem!_pos _ _ (by rw [hlen9]; omega)).symm
      -- massage hfold into one-step-unfolded form
      rw [show (↑it.start : Nat) = ↑h from hhv.symm] at hfold
      rw [← List.cons_getElem_drop_succ (n := h.val) (h := by rw [hlen9]; omega)] at hfold
      simp only [authFold] at hfold
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

/-- **Functional spec**: `verify_auth_path` computes exactly the 9-step fold —
    every parent index, height tweak, and left/right operand order pinned. -/
theorem verify_auth_path_spec (seed : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (leaf_node : Std.Array Std.U8 16#usize)
    (leaf_idx : Std.U32) (auth_path : Std.Array (Std.Array Std.U8 16#usize) 9#usize) :
    merkle.verify_auth_path seed layer tree leaf_node leaf_idx auth_path
      ⦃ r => r = authFold seed layer tree auth_path.val leaf_node leaf_idx.val 0 ⦄ := by
  unfold merkle.verify_auth_path
  simp only [params.layer_h, params.SUBTREE_H, params.H, params.D]
  step* <;> first | scalar_tac | skip
  apply verify_auth_path_loop_value _ _ _ _ _ _ _ _ (by rw [i_post]) (by simp)
  show authFold seed layer tree (List.drop 0 auth_path.val) leaf_node leaf_idx.val 0
      = authFold seed layer tree auth_path.val leaf_node leaf_idx.val 0
  rw [List.drop_zero]

end Extracted.Equiv

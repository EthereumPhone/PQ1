/- Actual iterative FORS tree construction, related to recursive tree nodes. -/
import Extracted.ForsRoot.Funs
import Extracted.ForsRootSchedule
import Extracted.ForsSecretSpec
import Extracted.ForsRecoverySpec

open Aeneas Aeneas.Std Result
set_option maxHeartbeats 2000000
set_option maxRecDepth 8192
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.Equiv
open sphincs_c10

def forsRootNode (seed sk : Std.Array Std.U8 32#usize) (ht tree : Std.U32) :
    Nat → Nat → Std.Array Std.U8 16#usize
  | 0, idx => th_pure seed (forsRecoveryAdrs ht tree 0 idx)
      (pad16p (forsSecretPure sk ht tree ⟨BitVec.ofNat 32 idx⟩))
  | h+1, idx => th_pair_pure seed (forsRecoveryAdrs ht tree (h+1) idx)
      (pad16p (forsRootNode seed sk ht tree h (2*idx)))
      (pad16p (forsRootNode seed sk ht tree h (2*idx+1)))

attribute [local irreducible] forsRootNode forsRootSlots

def forsRootStack (seed sk : Std.Array Std.U8 32#usize) (ht tree : Std.U32)
    (j : Nat) (stack : Std.Array (Std.Array Std.U8 16#usize) 12#usize)
    (heights : Std.Array Std.U32 12#usize) : Prop :=
  ∀ p, p < (forsRootSlots j).length →
    heights.val[p]!.val = (forsRootSlots j)[p]!.1 ∧
    stack.val[p]! = forsRootNode seed sk ht tree
      (forsRootSlots j)[p]!.1 (forsRootSlots j)[p]!.2

theorem forsRootSlots_length (j : Nat) : (forsRootSlots j).length ≤ 12 := by
  simp only [forsRootSlots, List.length_map]
  calc
    _ ≤ ((List.range 12).reverse).length := List.length_filter_le _ _
    _ = 12 := by simp

/-- The carry loop leaves the stack untouched and produces the next canonical
    frontier node. The schedule only determines positions; these equalities
    additionally preserve every actual hash and its ordered children. -/
theorem fors_root_carry_spec (seed sk : Std.Array Std.U8 32#usize)
    (ht tree : Std.U32) (stack : Std.Array (Std.Array Std.U8 16#usize) 12#usize)
    (heights : Std.Array Std.U32 12#usize) (j sp : Std.Usize)
    (node : Std.Array Std.U8 16#usize) (height : Std.U32)
    (hj : j.val < 2048) (hheight : height.val < 12)
    (hdiv : (j.val+1) % 2^height.val = 0)
    (hsp : sp.val = (forsRootSlots j.val).length - height.val)
    (hn : node = forsRootNode seed sk ht tree height.val (j.val / 2^height.val))
    (hstack : forsRootStack seed sk ht tree j.val stack heights) :
    fors.compute_fors_root_loop0_loop0 seed ht tree stack heights sp j node height
      ⦃ r => r.1.val < 12 ∧ r.1.val ≤ (forsRootSlots j.val).length ∧ r.2.2.val < 12 ∧
        r.2.1 = forsRootNode seed sk ht tree r.2.2.val (j.val / 2^r.2.2.val) ∧
        forsRootSlots (j.val+1) = (forsRootSlots j.val).take r.1.val ++
          [(r.2.2.val, j.val / 2^r.2.2.val)] ⦄ := by
  unfold fors.compute_fors_root_loop0_loop0
  apply loop.spec_decr_nat
    (measure := fun (s : Std.Usize × Std.Array Std.U8 16#usize × Std.U32) => s.1.val)
    (inv := fun (s : Std.Usize × Std.Array Std.U8 16#usize × Std.U32) =>
      s.2.2.val < 12 ∧ (j.val+1) % 2^s.2.2.val = 0 ∧
      s.1.val = (forsRootSlots j.val).length - s.2.2.val ∧
      s.2.1 = forsRootNode seed sk ht tree s.2.2.val (j.val / 2^s.2.2.val))
  · rintro ⟨sp0, nd, h⟩ ⟨hh, hd, hs, hnd⟩
    simp only at hh hd hs hnd
    have hsch := fors_root_schedule ⟨j.val, hj⟩ ⟨h.val, hh⟩
    simp only [forsRootScheduleAt, Fin.val_mk] at hsch
    obtain ⟨hhlen, hsch⟩ := hsch hd
    have hlen := forsRootSlots_length j.val
    have hsp0 : sp0.val ≤ 12 := by omega
    unfold fors.compute_fors_root_loop0_loop0.body
    simp only [lift, core.convert.num.FromU64U32.from]
    split
    · rename_i hp
      have hpv : sp0.val > 0 := by scalar_tac
      let* ⟨i, hi, hile⟩ ← Std.Usize.sub_spec (x := sp0) (y := 1#usize) (by scalar_tac)
      let* ⟨top, htop⟩ ← Array.index_usize_spec heights i (by scalar_tac)
      have hiv : i.val = sp0.val - 1 := by scalar_tac
      have hib : i.val < (forsRootSlots j.val).length := by omega
      have htopv : top.val = (forsRootSlots j.val)[i.val]!.1 := by
        have hsz : heights.val.length = 12 := by simpa using heights.property
        rw [htop, ← getElem!_pos heights.val i.val (by omega)]
        exact (hstack i.val hib).1
      split
      · rename_i heq
        have heqv : (forsRootSlots j.val)[i.val]!.1 = h.val := by rw [← htopv, heq]
        have hc : (forsRootSlots j.val).length - h.val > 0 ∧
            (forsRootSlots j.val)[(forsRootSlots j.val).length - h.val - 1]!.1 = h.val := by
          exact ⟨by omega, by simpa [hiv, hs] using heqv⟩
        rw [if_pos hc] at hsch
        obtain ⟨hh11, hleft, hright, hdivnext⟩ := hsch
        step* <;> first | scalar_tac | (have := System.Platform.numBits_eq; omega) | skip
        have hip : i3.val = j.val / 2^(h.val+1) := by
          rw [i3_post1, Nat.shiftRight_eq_div_pow, i2_post]
        have hipb : i3.val < 2048 := by rw [hip]; exact lt_of_le_of_lt (Nat.div_le_self _ _) hj
        have hcast : (UScalar.cast .U32 i3).val = i3.val := by
          rw [UScalar.cast_val_eq]
          exact Nat.mod_eq_of_lt (by scalar_tac)
        let* ⟨adrs, hadrs⟩ ← make_adrs_spec 0#u32
          (⟨BitVec.setWidth 64 ht.bv⟩ : Std.U64) params.ADRS_FORS_TREE tree 0#u32 i2
          (UScalar.cast .U32 i3)
        have hht : (⟨BitVec.setWidth 64 ht.bv⟩ : Std.U64).val = ht.val :=
          BitVec.toNat_setWidth_of_le (by decide)
        simp only [show (0#u32 : Std.U32).val = 0 from rfl,
          show params.ADRS_FORS_TREE.val = 3 by simp [params.ADRS_FORS_TREE], hht, i2_post, hcast, hip] at hadrs
        have hadeq := forsRecoveryAdrs_eq_of_map_val adrs ht tree (h.val+1)
          (j.val / 2^(h.val+1)) hadrs
        let* ⟨left, hleftpad⟩ ← pad16_spec sibling
        let* ⟨right, hrightpad⟩ ← pad16_spec nd
        let* ⟨parent, hparent⟩ ← hash.th_pair_spec seed adrs left right
        refine ⟨by omega, by simpa [i2_post] using hdivnext, by omega, ?_, by omega⟩
        have hsib : sibling = forsRootNode seed sk ht tree h.val
            (2 * (j.val / 2^(h.val+1))) := by
          have hsz : stack.val.length = 12 := by simpa using stack.property
          rw [sibling_post, ← getElem!_pos stack.val i.val (by omega), (hstack i.val hib).2, heqv]
          rw [show (forsRootSlots j.val)[i.val]!.2 = 2 * (j.val / 2^(h.val+1)) from
            (by simpa [hiv, hs] using hleft)]
        rw [hparent, hleftpad, hrightpad, ← hadeq, hsib, hnd, hright, i2_post]
        rw [forsRootNode]
      · rename_i hne
        have hnev : (forsRootSlots j.val)[i.val]!.1 ≠ h.val := by
          intro heqv
          apply hne
          apply UScalar.eq_of_val_eq
          rw [htopv, heqv]
        have hc : ¬ ((forsRootSlots j.val).length - h.val > 0 ∧
            (forsRootSlots j.val)[(forsRootSlots j.val).length - h.val - 1]!.1 = h.val) := by
          simpa [hiv, hs] using fun hx : (forsRootSlots j.val).length - h.val > 0 ∧
              (forsRootSlots j.val)[i.val]!.1 = h.val => hnev hx.2
        rw [if_neg hc] at hsch
        simp only [WP.spec_ok]
        exact ⟨by omega, by omega, hh, hnd, by simpa [← hs] using hsch.2⟩
    · rename_i hp
      have hpv : sp0.val = 0 := by scalar_tac
      have hncond : ¬ ((forsRootSlots j.val).length - h.val > 0 ∧
          (forsRootSlots j.val)[(forsRootSlots j.val).length - h.val - 1]!.1 = h.val) := by
        omega
      rw [if_neg hncond] at hsch
      simp only [WP.spec_ok]
      exact ⟨by omega, by omega, hh, hnd, by simpa [← hs] using hsch.2⟩
  · exact ⟨hheight, hdiv, hsp, hn⟩

/-- Inserting the completed carry node restores the full frontier invariant. -/
theorem fors_root_stack_update (seed sk : Std.Array Std.U8 32#usize) (ht tree : Std.U32)
    (j : Nat) (stack : Std.Array (Std.Array Std.U8 16#usize) 12#usize)
    (heights : Std.Array Std.U32 12#usize) (sp : Std.Usize)
    (node : Std.Array Std.U8 16#usize) (h : Std.U32)
    (hsp : sp.val < 12) (hsplen : sp.val ≤ (forsRootSlots j).length)
    (hn : node = forsRootNode seed sk ht tree h.val (j / 2^h.val))
    (hslots : forsRootSlots (j+1) = (forsRootSlots j).take sp.val ++ [(h.val, j / 2^h.val)])
    (hstack : forsRootStack seed sk ht tree j stack heights) :
    (forsRootSlots (j+1)).length = sp.val+1 ∧
    forsRootStack seed sk ht tree (j+1) (stack.set sp node) (heights.set sp h) := by
  have htake : ((forsRootSlots j).take sp.val).length = sp.val := by simp [List.length_take, Nat.min_eq_left hsplen]
  constructor
  · rw [hslots, List.length_append, htake]; simp
  intro p hp
  rw [hslots, List.length_append, htake] at hp
  simp only [List.length_singleton] at hp
  simp only [Array.set_val_eq]
  by_cases heq : p = sp.val
  · subst p
    rw [List.set_getElem!_eq _ _ _ _ ⟨by simpa using hsp, rfl⟩,
      List.set_getElem!_eq _ _ _ _ ⟨by simpa using hsp, rfl⟩]
    have hslot : (forsRootSlots (j+1))[sp.val]! = (h.val, j / 2^h.val) := by
      rw [hslots]
      simp [List.getElem!_eq_getElem?_getD, List.getElem?_append, htake]
    rw [hslot]
    exact ⟨rfl, hn⟩
  · have hlt : p < sp.val := by omega
    rw [List.set_getElem!_ne _ _ _ _ (by omega), List.set_getElem!_ne _ _ _ _ (by omega)]
    have hslot : (forsRootSlots (j+1))[p]! = (forsRootSlots j)[p]! := by
      rw [hslots]
      simp [List.getElem!_eq_getElem?_getD, List.getElem?_append, htake, hlt,
        List.getElem?_take, List.getElem?_eq_getElem (show p < (forsRootSlots j).length by omega)]
    rw [hslot]
    exact hstack p (by omega)

/-- All 2048 leaves are processed. The final frontier consists of the height-11
    root alone, so both extracted debug assertions and the final access hold. -/
theorem fors_root_loop_spec (seed sk : Std.Array Std.U8 32#usize) (ht tree : Std.U32)
    (iter : core.ops.range.Range Std.Usize)
    (stack : Std.Array (Std.Array Std.U8 16#usize) 12#usize)
    (heights : Std.Array Std.U32 12#usize) (sp : Std.Usize)
    (hend : iter.«end».val = 2048) (hle : iter.start.val ≤ 2048)
    (hsp : sp.val = (forsRootSlots iter.start.val).length)
    (hstack : forsRootStack seed sk ht tree iter.start.val stack heights) :
    fors.compute_fors_root_loop0 iter seed sk ht tree stack heights sp
      ⦃ r => r.2.2.val = 1 ∧ r.2.1.val[0]!.val = 11 ∧
        r.1.val[0]! = forsRootNode seed sk ht tree 11 0 ⦄ := by
  unfold fors.compute_fors_root_loop0
  apply loop.spec_decr_nat
    (measure := fun (s : core.ops.range.Range Std.Usize ×
      Std.Array (Std.Array Std.U8 16#usize) 12#usize × Std.Array Std.U32 12#usize × Std.Usize) =>
        2048 - s.1.start.val)
    (inv := fun (s : core.ops.range.Range Std.Usize ×
      Std.Array (Std.Array Std.U8 16#usize) 12#usize × Std.Array Std.U32 12#usize × Std.Usize) =>
        s.1.«end».val = 2048 ∧ s.1.start.val ≤ 2048 ∧
        s.2.2.2.val = (forsRootSlots s.1.start.val).length ∧
        forsRootStack seed sk ht tree s.1.start.val s.2.1 s.2.2.1)
  · rintro ⟨it, st, hs, sp0⟩ ⟨he, hl, hsp0, hst⟩
    simp only at he hl hsp0 hst
    unfold fors.compute_fors_root_loop0.body
    simp only [lift, core.convert.num.FromU64U32.from]
    let* ⟨ob, it1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨j, it', heq, hj, hlt, hend', hstart'⟩
    · subst ho
      have hit : it.start.val = 2048 := by omega
      have hx := hst 0 (by simp [hit])
      simp only [hit, forsRootSlots_final, List.length_singleton, List.getElem!_cons_zero] at hx hsp0
      simp only [WP.spec_ok]
      exact ⟨hsp0, hx⟩
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      have hjv : j.val = it.start.val := by rw [hj]
      have hjb : j.val < 2048 := by omega
      have hcastv : (UScalar.cast .U32 j).val = j.val := by
        rw [UScalar.cast_val_eq]
        exact Nat.mod_eq_of_lt (by scalar_tac)
      have hcast : UScalar.cast .U32 j = (⟨BitVec.ofNat 32 j.val⟩ : Std.U32) := by
        apply UScalar.eq_of_val_eq
        rw [hcastv]
        exact (Nat.mod_eq_of_lt (show j.val < 2^32 by omega)).symm
      let* ⟨secret, hsecret⟩ ← fors_secret_spec sk ht tree (UScalar.cast .U32 j)
      let* ⟨adrs, hadrs⟩ ← make_adrs_spec 0#u32
        (⟨BitVec.setWidth 64 ht.bv⟩ : Std.U64) params.ADRS_FORS_TREE tree 0#u32 0#u32
        (UScalar.cast .U32 j)
      have hht : (⟨BitVec.setWidth 64 ht.bv⟩ : Std.U64).val = ht.val :=
        BitVec.toNat_setWidth_of_le (by decide)
      simp only [show (0#u32 : Std.U32).val = 0 from rfl,
        show params.ADRS_FORS_TREE.val = 3 by simp [params.ADRS_FORS_TREE], hht, hcastv] at hadrs
      have hadeq := forsRecoveryAdrs_eq_of_map_val adrs ht tree 0 j.val hadrs
      let* ⟨padded, hpadded⟩ ← pad16_spec secret
      let* ⟨leaf, hleaf⟩ ← hash.th_spec seed adrs padded
      have hleafnode : leaf = forsRootNode seed sk ht tree 0 j.val := by
        rw [hleaf, hpadded, ← hadeq, hsecret, hcast]
        rw [forsRootNode]
      let* ⟨sp1, node, h, hs1, hsplen, hh, hn, hslots⟩ ←
        fors_root_carry_spec seed sk ht tree st hs j sp0 leaf 0#u32 hjb (by decide)
          (by simp [Nat.mod_one]) (by simpa [hjv] using hsp0) (by simpa using hleafnode) (by simpa [hjv] using hst)
      let* ⟨st1, hst1⟩ ← Array.update_spec st sp1 node (by simpa using hs1)
      let* ⟨hs2, hhs2⟩ ← Array.update_spec hs sp1 h (by simpa using hs1)
      let* ⟨sp2, hsp2⟩ ← Std.Usize.add_spec (x := sp1) (y := 1#usize) (by scalar_tac)
      have hup := fors_root_stack_update seed sk ht tree j.val st hs sp1 node h hs1 hsplen hn hslots
        (by simpa [hjv] using hst)
      refine ⟨by rw [hend']; exact he, by omega, ?_, ?_, by omega⟩
      · rw [hsp2, hstart', ← hjv]
        exact hup.1.symm
      · rw [hst1, hhs2, hstart', ← hjv]
        exact hup.2
  · exact ⟨hend, hle, hsp, hstack⟩

/-- Totality and exact root for the actual Rust stack algorithm, for every seed
    and every full-width hypertree/tree index. -/
@[step] theorem fors_compute_root_spec (seed sk : Std.Array Std.U8 32#usize)
    (ht tree : Std.U32) :
    fors.compute_fors_root seed sk ht tree ⦃ r => r = forsRootNode seed sk ht tree 11 0 ⦄ := by
  unfold fors.compute_fors_root
  simp only [params.FORS_LEAVES, params.A]
  step* <;> first | scalar_tac | skip
  · change 11 < System.Platform.numBits
    have := System.Platform.numBits_eq
    omega
  have hn : n_leaves.val = 2048 := by
    rw [n_leaves_post1]
    simp only [Usize.size, Usize.numBits]
    rcases System.Platform.numBits_eq with hb | hb <;>
      norm_num [Nat.shiftLeft_eq, UScalarTy.numBits, hb]
  let* ⟨stack, heights, sp, hsp, hh, hroot⟩ ← fors_root_loop_spec seed sk ht tree
    { start := 0#usize, «end» := n_leaves }
    (Array.repeat 12#usize (Array.repeat 16#usize 0#u8))
    (Array.repeat 12#usize 0#u32) 0#usize hn (by simp) (by simp)
    (by intro p hp; simpa using hp)
  have hsp1 : sp = 1#usize := by apply UScalar.eq_of_val_eq; exact hsp
  step* <;> first | scalar_tac | skip
  · apply UScalar.eq_of_val_eq
    rw [left_val_post, ← getElem!_pos heights.val 0 (by simpa using heights.property)]
    simpa [right_val_post, UScalar.cast_val_eq] using hh
  · rw [r_post, ← getElem!_pos stack.val 0 (by simpa using stack.property)]
    exact hroot

end Extracted.Equiv

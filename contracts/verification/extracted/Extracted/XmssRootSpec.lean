/- Actual iterative XMSS tree construction, related to recursive tree nodes. -/
import Extracted.XmssRoot.Funs
import Extracted.XmssRootSchedule
import Extracted.WotsKeygenSpec
import Extracted.MerkleVerifySpec

open Aeneas Aeneas.Std Result
set_option maxHeartbeats 2000000
set_option maxRecDepth 8192
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.Equiv
open sphincs_c10

def xmssRootNode (seed sk : Std.Array Std.U8 32#usize) (layer : Std.U32) (tree : Std.U64) :
    Nat → Nat → Std.Array Std.U8 16#usize
  | 0, idx => wotsKeygenPure seed sk layer tree ⟨BitVec.ofNat 32 idx⟩
  | h+1, idx => th_pair_pure seed (treeAdrs layer tree h idx)
      (pad16p (xmssRootNode seed sk layer tree h (2*idx)))
      (pad16p (xmssRootNode seed sk layer tree h (2*idx+1)))

attribute [local irreducible] xmssRootNode xmssRootSlots

def xmssRootStack (seed sk : Std.Array Std.U8 32#usize) (layer : Std.U32) (tree : Std.U64)
    (j : Nat) (stack : Std.Array (Std.Array Std.U8 16#usize) 10#usize)
    (heights : Std.Array Std.U32 10#usize) : Prop :=
  ∀ p, p < (xmssRootSlots j).length →
    heights.val[p]!.val = (xmssRootSlots j)[p]!.1 ∧
    stack.val[p]! = xmssRootNode seed sk layer tree
      (xmssRootSlots j)[p]!.1 (xmssRootSlots j)[p]!.2

theorem xmssRootSlots_length (j : Nat) : (xmssRootSlots j).length ≤ 10 := by
  simp only [xmssRootSlots, List.length_map]
  calc
    _ ≤ ((List.range 10).reverse).length := List.length_filter_le _ _
    _ = 10 := by simp

/-- The carry loop leaves the stack untouched and produces the next canonical
    frontier node. The schedule only determines positions; these equalities
    additionally preserve every actual hash and its ordered children. -/
theorem xmss_root_carry_spec (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (stack : Std.Array (Std.Array Std.U8 16#usize) 10#usize)
    (heights : Std.Array Std.U32 10#usize) (j sp : Std.Usize)
    (node : Std.Array Std.U8 16#usize) (height : Std.U32)
    (hj : j.val < 512) (hheight : height.val < 10)
    (hdiv : (j.val+1) % 2^height.val = 0)
    (hsp : sp.val = (xmssRootSlots j.val).length - height.val)
    (hn : node = xmssRootNode seed sk layer tree height.val (j.val / 2^height.val))
    (hstack : xmssRootStack seed sk layer tree j.val stack heights) :
    merkle.compute_subtree_root_loop0_loop0 seed layer tree stack heights sp j node height
      ⦃ r => r.1.val < 10 ∧ r.1.val ≤ (xmssRootSlots j.val).length ∧ r.2.2.val < 10 ∧
        r.2.1 = xmssRootNode seed sk layer tree r.2.2.val (j.val / 2^r.2.2.val) ∧
        xmssRootSlots (j.val+1) = (xmssRootSlots j.val).take r.1.val ++
          [(r.2.2.val, j.val / 2^r.2.2.val)] ⦄ := by
  unfold merkle.compute_subtree_root_loop0_loop0
  apply loop.spec_decr_nat
    (measure := fun (s : Std.Usize × Std.Array Std.U8 16#usize × Std.U32) => s.1.val)
    (inv := fun (s : Std.Usize × Std.Array Std.U8 16#usize × Std.U32) =>
      s.2.2.val < 10 ∧ (j.val+1) % 2^s.2.2.val = 0 ∧
      s.1.val = (xmssRootSlots j.val).length - s.2.2.val ∧
      s.2.1 = xmssRootNode seed sk layer tree s.2.2.val (j.val / 2^s.2.2.val))
  · rintro ⟨sp0, nd, h⟩ ⟨hh, hd, hs, hnd⟩
    simp only at hh hd hs hnd
    have hsch := xmss_root_schedule ⟨j.val, hj⟩ ⟨h.val, hh⟩
    simp only [xmssRootScheduleAt, Fin.val_mk] at hsch
    obtain ⟨hhlen, hsch⟩ := hsch hd
    have hlen := xmssRootSlots_length j.val
    have hsp0 : sp0.val ≤ 10 := by omega
    unfold merkle.compute_subtree_root_loop0_loop0.body
    simp only [lift, core.convert.num.FromU64U32.from]
    split
    · rename_i hp
      have hpv : sp0.val > 0 := by scalar_tac
      let* ⟨i, hi, hile⟩ ← Std.Usize.sub_spec (x := sp0) (y := 1#usize) (by scalar_tac)
      let* ⟨top, htop⟩ ← Array.index_usize_spec heights i (by scalar_tac)
      have hiv : i.val = sp0.val - 1 := by scalar_tac
      have hib : i.val < (xmssRootSlots j.val).length := by omega
      have htopv : top.val = (xmssRootSlots j.val)[i.val]!.1 := by
        have hsz : heights.val.length = 10 := by simpa using heights.property
        rw [htop, ← getElem!_pos heights.val i.val (by omega)]
        exact (hstack i.val hib).1
      split
      · rename_i heq
        have heqv : (xmssRootSlots j.val)[i.val]!.1 = h.val := by rw [← htopv, heq]
        have hc : (xmssRootSlots j.val).length - h.val > 0 ∧
            (xmssRootSlots j.val)[(xmssRootSlots j.val).length - h.val - 1]!.1 = h.val := by
          exact ⟨by omega, by simpa [hiv, hs] using heqv⟩
        rw [if_pos hc] at hsch
        obtain ⟨hh11, hleft, hright, hdivnext⟩ := hsch
        step* <;> first | scalar_tac | (have := System.Platform.numBits_eq; omega) | skip
        have hip : i3.val = j.val / 2^(h.val+1) := by
          rw [i3_post1, Nat.shiftRight_eq_div_pow, i2_post]
        have hipb : i3.val < 512 := by rw [hip]; exact lt_of_le_of_lt (Nat.div_le_self _ _) hj
        have hcast : (UScalar.cast .U32 i3).val = i3.val := by
          rw [UScalar.cast_val_eq]
          exact Nat.mod_eq_of_lt (by scalar_tac)
        let* ⟨adrs, hadrs⟩ ← make_adrs_spec layer tree params.ADRS_TREE 0#u32 0#u32 i2
          (UScalar.cast .U32 i3)
        simp only [show params.ADRS_TREE.val = 2 by simp [params.ADRS_TREE], i2_post, hcast, hip] at hadrs
        have hadeq := treeAdrs_eq_of_map_val adrs layer tree h.val
          (j.val / 2^(h.val+1)) hadrs
        let* ⟨left, hleftpad⟩ ← pad16_spec sibling
        let* ⟨right, hrightpad⟩ ← pad16_spec nd
        let* ⟨parent, hparent⟩ ← hash.th_pair_spec seed adrs left right
        refine ⟨by omega, by simpa [i2_post] using hdivnext, by omega, ?_, by omega⟩
        have hsib : sibling = xmssRootNode seed sk layer tree h.val
            (2 * (j.val / 2^(h.val+1))) := by
          have hsz : stack.val.length = 10 := by simpa using stack.property
          rw [sibling_post, ← getElem!_pos stack.val i.val (by omega), (hstack i.val hib).2, heqv]
          rw [show (xmssRootSlots j.val)[i.val]!.2 = 2 * (j.val / 2^(h.val+1)) from
            (by simpa [hiv, hs] using hleft)]
        rw [hparent, hleftpad, hrightpad, ← hadeq, hsib, hnd, hright, i2_post]
        rw [xmssRootNode]
      · rename_i hne
        have hnev : (xmssRootSlots j.val)[i.val]!.1 ≠ h.val := by
          intro heqv
          apply hne
          apply UScalar.eq_of_val_eq
          rw [htopv, heqv]
        have hc : ¬ ((xmssRootSlots j.val).length - h.val > 0 ∧
            (xmssRootSlots j.val)[(xmssRootSlots j.val).length - h.val - 1]!.1 = h.val) := by
          simpa [hiv, hs] using fun hx : (xmssRootSlots j.val).length - h.val > 0 ∧
              (xmssRootSlots j.val)[i.val]!.1 = h.val => hnev hx.2
        rw [if_neg hc] at hsch
        simp only [WP.spec_ok]
        exact ⟨by omega, by omega, hh, hnd, by simpa [← hs] using hsch.2⟩
    · rename_i hp
      have hpv : sp0.val = 0 := by scalar_tac
      have hncond : ¬ ((xmssRootSlots j.val).length - h.val > 0 ∧
          (xmssRootSlots j.val)[(xmssRootSlots j.val).length - h.val - 1]!.1 = h.val) := by
        omega
      rw [if_neg hncond] at hsch
      simp only [WP.spec_ok]
      exact ⟨by omega, by omega, hh, hnd, by simpa [← hs] using hsch.2⟩
  · exact ⟨hheight, hdiv, hsp, hn⟩

/-- Inserting the completed carry node restores the full frontier invariant. -/
theorem xmss_root_stack_update (seed sk : Std.Array Std.U8 32#usize) (layer : Std.U32) (tree : Std.U64)
    (j : Nat) (stack : Std.Array (Std.Array Std.U8 16#usize) 10#usize)
    (heights : Std.Array Std.U32 10#usize) (sp : Std.Usize)
    (node : Std.Array Std.U8 16#usize) (h : Std.U32)
    (hsp : sp.val < 10) (hsplen : sp.val ≤ (xmssRootSlots j).length)
    (hn : node = xmssRootNode seed sk layer tree h.val (j / 2^h.val))
    (hslots : xmssRootSlots (j+1) = (xmssRootSlots j).take sp.val ++ [(h.val, j / 2^h.val)])
    (hstack : xmssRootStack seed sk layer tree j stack heights) :
    (xmssRootSlots (j+1)).length = sp.val+1 ∧
    xmssRootStack seed sk layer tree (j+1) (stack.set sp node) (heights.set sp h) := by
  have htake : ((xmssRootSlots j).take sp.val).length = sp.val := by simp [List.length_take, Nat.min_eq_left hsplen]
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
    have hslot : (xmssRootSlots (j+1))[sp.val]! = (h.val, j / 2^h.val) := by
      rw [hslots]
      simp [List.getElem!_eq_getElem?_getD, List.getElem?_append, htake]
    rw [hslot]
    exact ⟨rfl, hn⟩
  · have hlt : p < sp.val := by omega
    rw [List.set_getElem!_ne _ _ _ _ (by omega), List.set_getElem!_ne _ _ _ _ (by omega)]
    have hslot : (xmssRootSlots (j+1))[p]! = (xmssRootSlots j)[p]! := by
      rw [hslots]
      simp [List.getElem!_eq_getElem?_getD, List.getElem?_append, htake, hlt,
        List.getElem?_take, List.getElem?_eq_getElem (show p < (xmssRootSlots j).length by omega)]
    rw [hslot]
    exact hstack p (by omega)

/-- All 512 leaves are processed. The final frontier consists of the height-9
    root alone, so both extracted debug assertions and the final access hold. -/
theorem xmss_root_loop_spec (seed sk : Std.Array Std.U8 32#usize) (layer : Std.U32) (tree : Std.U64)
    (progress : hypertree.ProgressSink) (pct_lo pct_hi : Std.U8) (n_leaves : Std.Usize)
    (iter : core.ops.range.Range Std.Usize)
    (stack : Std.Array (Std.Array Std.U8 16#usize) 10#usize)
    (heights : Std.Array Std.U32 10#usize) (sp : Std.Usize)
    (hnleaves : n_leaves.val = 512) (hend : iter.«end».val = 512) (hle : iter.start.val ≤ 512)
    (hsp : sp.val = (xmssRootSlots iter.start.val).length)
    (hstack : xmssRootStack seed sk layer tree iter.start.val stack heights) :
    merkle.compute_subtree_root_loop0 iter seed sk layer tree progress pct_lo pct_hi n_leaves stack heights sp
      ⦃ r => r.2.2.val = 1 ∧ r.2.1.val[0]!.val = 9 ∧
        r.1.val[0]! = xmssRootNode seed sk layer tree 9 0 ⦄ := by
  unfold merkle.compute_subtree_root_loop0
  apply loop.spec_decr_nat
    (measure := fun (s : core.ops.range.Range Std.Usize ×
      Std.Array (Std.Array Std.U8 16#usize) 10#usize × Std.Array Std.U32 10#usize × Std.Usize) =>
        512 - s.1.start.val)
    (inv := fun (s : core.ops.range.Range Std.Usize ×
      Std.Array (Std.Array Std.U8 16#usize) 10#usize × Std.Array Std.U32 10#usize × Std.Usize) =>
        s.1.«end».val = 512 ∧ s.1.start.val ≤ 512 ∧
        s.2.2.2.val = (xmssRootSlots s.1.start.val).length ∧
        xmssRootStack seed sk layer tree s.1.start.val s.2.1 s.2.2.1)
  · rintro ⟨it, st, hs, sp0⟩ ⟨he, hl, hsp0, hst⟩
    simp only at he hl hsp0 hst
    unfold merkle.compute_subtree_root_loop0.body
    simp only [lift, core.convert.num.FromU64U32.from]
    let* ⟨ob, it1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨j, it', heq, hj, hlt, hend', hstart'⟩
    · subst ho
      have hit : it.start.val = 512 := by omega
      have hx := hst 0 (by simp [hit])
      simp only [hit, xmssRootSlots_final, List.length_singleton, List.getElem!_cons_zero] at hx hsp0
      simp only [WP.spec_ok]
      exact ⟨hsp0, hx⟩
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      have hjv : j.val = it.start.val := by rw [hj]
      have hjb : j.val < 512 := by omega
      have hcastv : (UScalar.cast .U32 j).val = j.val := by
        rw [UScalar.cast_val_eq]
        exact Nat.mod_eq_of_lt (by scalar_tac)
      have hcast : UScalar.cast .U32 j = (⟨BitVec.ofNat 32 j.val⟩ : Std.U32) := by
        apply UScalar.eq_of_val_eq
        rw [hcastv]
        exact (Nat.mod_eq_of_lt (show j.val < 2^32 by omega)).symm
      let* ⟨leaf, hleaf⟩ ← wots_keygen_pk_spec seed sk layer tree (UScalar.cast .U32 j)
      have hleafnode : leaf = xmssRootNode seed sk layer tree 0 j.val := by
        rw [hleaf, hcast, xmssRootNode]
      let* ⟨sp1, node, h, hs1, hsplen, hh, hn, hslots⟩ ←
        xmss_root_carry_spec seed sk layer tree st hs j sp0 leaf 0#u32 hjb (by decide)
          (by simp [Nat.mod_one]) (by simpa [hjv] using hsp0) (by simpa using hleafnode) (by simpa [hjv] using hst)
      let* ⟨stold, stback, hstold, hst1⟩ ← Array.index_mut_usize_spec st sp1 (by simpa using hs1)
      let* ⟨hsold, hsback, hhsold, hhs2⟩ ← Array.index_mut_usize_spec hs sp1 (by simpa using hs1)
      let* ⟨sp2, hsp2⟩ ← Std.Usize.add_spec (x := sp1) (y := 1#usize) (by scalar_tac)
      have hup := xmss_root_stack_update seed sk layer tree j.val st hs sp1 node h hs1 hsplen hn hslots
        (by simpa [hjv] using hst)
      have hcastn : (UScalar.cast .U32 n_leaves).val = 512 := by
        simp only [UScalar.cast_val_eq, hnleaves]; norm_num
      have hspan : (core.convert.num.FromU32U8.from (core.num.U8.saturating_sub pct_hi pct_lo)).val ≤ 255 := by
        rw [core.convert.num.FromU32U8.from_val_eq]
        have hb : (core.num.U8.saturating_sub pct_hi pct_lo).val < 256 := by
          simpa [UScalarTy.numBits] using (core.num.U8.saturating_sub pct_hi pct_lo).hBounds
        omega
      have hlo : (core.convert.num.FromU32U8.from pct_lo).val ≤ 255 := by
        rw [core.convert.num.FromU32U8.from_val_eq]
        have hb : pct_lo.val < 256 := by simpa [UScalarTy.numBits] using pct_lo.hBounds
        omega
      simp only [merkle.REPORT_EVERY]
      step* <;> first | scalar_tac | skip
      all_goals try simp only [lift, hypertree.report]
      all_goals step* <;> first | scalar_tac | skip
      all_goals
        refine ⟨by rw [hend']; exact he, by omega, ?_, ?_, by omega⟩
        · rw [hsp2, hstart', ← hjv]
          exact hup.1.symm
        · rw [hst1, hhs2, hstart', ← hjv]
          exact hup.2
  · exact ⟨hend, hle, hsp, hstack⟩

/-- Totality and exact root for the actual Rust stack algorithm, for every seed
    and every full-width hypertree/tree index. -/
@[step] theorem xmss_compute_root_spec (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64)
    (progress : hypertree.ProgressSink) (pct_lo pct_hi : Std.U8) :
    merkle.compute_subtree_root seed sk layer tree progress pct_lo pct_hi ⦃ r => r = xmssRootNode seed sk layer tree 9 0 ⦄ := by
  unfold merkle.compute_subtree_root
  simp only [params.SUBTREE_LEAVES, params.SUBTREE_H, params.H, params.D]
  step* <;> first | scalar_tac | skip
  · have hx9 : x.val = 9 := by omega
    have := System.Platform.numBits_eq
    omega
  have hn : n_leaves.val = 512 := by
    rw [n_leaves_post1]
    simp only [Usize.size, Usize.numBits]
    rcases System.Platform.numBits_eq with hb | hb <;>
      norm_num [Nat.shiftLeft_eq, UScalarTy.numBits, hb, x_post]
  let* ⟨stack, heights, sp, hsp, hh, hroot⟩ ← xmss_root_loop_spec seed sk layer tree progress pct_lo pct_hi n_leaves
    { start := 0#usize, «end» := n_leaves }
    (Array.repeat 10#usize (Array.repeat 16#usize 0#u8))
    (Array.repeat 10#usize 0#u32) 0#usize hn hn (by simp) (by simp)
    (by intro p hp; simpa using hp)
  have hsp1 : sp = 1#usize := by apply UScalar.eq_of_val_eq; exact hsp
  step* <;> first | scalar_tac | skip
  · apply UScalar.eq_of_val_eq
    rw [left_val_post, ← getElem!_pos heights.val 0 (by simpa using heights.property)]
    simpa [right_val_post, UScalar.cast_val_eq, i_post] using hh
  · rw [r_post, ← getElem!_pos stack.val 0 (by simpa using stack.property)]
    exact hroot

/-- The public key uses the top layer/tree and pads the public seed exactly. -/
@[step] theorem xmss_compute_pk_root_spec (sk : Std.Array Std.U8 32#usize)
    (seed : Std.Array Std.U8 16#usize) :
    hypertree.compute_pk_root sk seed ⦃ r =>
      r = xmssRootNode (pad16p seed) sk 1#u32 0#u64 9 0 ⦄ := by
  unfold hypertree.compute_pk_root hypertree.progress_none hypertree.compute_pk_root_inner
  simp only [WP.spec_ok, bind_tc_ok]
  let* ⟨padded, hpadded⟩ ← pad16_spec seed
  let* ⟨root, hroot⟩ ← xmss_compute_root_spec padded sk 1#u32 0#u64 () 0#u8 0#u8
  rw [hroot, hpadded]

end Extracted.Equiv

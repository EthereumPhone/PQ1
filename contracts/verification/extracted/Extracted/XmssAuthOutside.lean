/- Out-of-tree XMSS targets in the callback-free release extraction.
   The actual builder returns its root and leaves every authentication slot zero. -/
import Extracted.XmssAuthSpec
import Extracted.C10FunctionalBuildValues

open Aeneas Aeneas.Std Result
set_option maxHeartbeats 2000000
set_option maxRecDepth 8192
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes
namespace Extracted.Equiv
open sphincs_c10
attribute [local irreducible] xmssRootNode xmssRootSlots xmssAuthEnd xmssAuthSibling

theorem xmss_auth_capture_outside (leaf height : Std.U32) (j : Std.Usize)
    (keep : Std.Array (Std.Array Std.U8 16#usize) 9#usize)
    (flags : Std.Array Bool 9#usize) (left right : Std.Array Std.U8 16#usize) (b : Bool)
    (hleaf : 512 ≤ leaf.val) (hh : height.val < 9) (hj : j.val < 512)
    (halign : j.val+1 = (j.val / 2^(height.val+1)+1)*2^(height.val+1))
 :
    (do
      let h ← lift (UScalar.cast .Usize height)
      if b then ok (keep, flags) else do
        let target ← leaf >>> height
        let sibling ← lift (target ^^^ 1#u32)
        let h1 ← height + 1#u32
        let q ← j >>> h1
        let pairStart ← q <<< h1
        let l ← pairStart >>> height
        let leftIdx ← lift (UScalar.cast .U32 l)
        let rightIdx ← leftIdx + 1#u32
        if leftIdx = sibling then do
          let out ← Array.update keep h left
          let set ← Array.update flags h true
          ok (out, set)
        else if rightIdx = sibling then do
          let out ← Array.update keep h right
          let set ← Array.update flags h true
          ok (out, set)
        else ok (keep, flags)) ⦃ r =>
      r = (keep, flags) ⦄ := by
  simp only [lift, bind_tc_ok]
  split
  · simp only [WP.spec_ok]
  ·
    let* ⟨target, htarg, htbv⟩ ← Std.U32.ShiftRight_spec leaf height (by scalar_tac)
    try simp only [lift, bind_tc_ok]
    have hs : (target ^^^ 1#u32).val = xmssAuthSibling leaf.val height.val := by
      rw [UScalar.val_xor, htarg, Nat.shiftRight_eq_div_pow, xmssAuthSibling]
      rfl
    let* ⟨h1, hh1⟩ ← Std.U32.add_spec (x := height) (y := 1#u32) (by scalar_tac)
    let* ⟨q, hq, hqbv⟩ ← Std.Usize.ShiftRight_spec j h1
      (by have := System.Platform.numBits_eq; scalar_tac)
    have hqv : q.val = j.val/2^(height.val+1) := by
      rw [hq, Nat.shiftRight_eq_div_pow, hh1]
    let* ⟨pairStart, hstart, hstartbv⟩ ← Std.Usize.ShiftLeft_spec q h1
      (by have := System.Platform.numBits_eq; scalar_tac)
    have hpw : 0 < 2^height.val := by positivity
    have hstartb : (j.val/2^(height.val+1))*2^(height.val+1) < 512 := by
      nlinarith [pow_pos (by decide : 0 < (2:Nat)) (height.val+1)]
    have hstartv : pairStart.val = (j.val/2^(height.val+1))*2^(height.val+1) := by
      rw [hstart, Nat.shiftLeft_eq, hqv, hh1]
      exact Nat.mod_eq_of_lt (by scalar_tac)
    let* ⟨l, hl, hlbv⟩ ← Std.Usize.ShiftRight_spec pairStart height
      (by have := System.Platform.numBits_eq; scalar_tac)
    have hlv : l.val = 2*(j.val/2^(height.val+1)) := by
      rw [hl, Nat.shiftRight_eq_div_pow, hstartv]
      rw [show (j.val/2^(height.val+1))*2^(height.val+1) =
        (2*(j.val/2^(height.val+1)))*2^height.val by rw [pow_succ]; ring]
      exact Nat.mul_div_cancel _ hpw
    have hleftb : 2*(j.val/2^(height.val+1)) < 512 := by
      have hpow : 2 ≤ 2^(height.val+1) := by
        calc 2 = 2^1 := by norm_num
             _ ≤ 2^(height.val+1) := Nat.pow_le_pow_right (by decide) (by omega)
      nlinarith
    have hcast : (UScalar.cast .U32 l).val = 2*(j.val/2^(height.val+1)) := by
      rw [UScalar.cast_val_eq, hlv, Nat.mod_eq_of_lt (by scalar_tac)]
    try simp only [lift, bind_tc_ok]
    let* ⟨rightIdx, hrightIdx⟩ ← Std.U32.add_spec (x := UScalar.cast .U32 l) (y := 1#u32)
      (by scalar_tac)
    have hrv : rightIdx.val = 2*(j.val/2^(height.val+1))+1 := by
      rw [hrightIdx, hcast]
    have hb := C10FunctionalBuildValues.sibling_shift_outside leaf.val height.val 9 32
      hh (by decide) hleaf (by scalar_tac)
    have hsb : 512 ≤ xmssAuthSibling leaf.val height.val * 2^height.val := by
      simpa only [xmssAuthSibling, show (2:Nat)^9 = 512 by decide] using hb.1
    have hpow : 2^(height.val+1) = 2^height.val*2 := by rw [pow_succ]
    have hrfoot : (2*(j.val/2^(height.val+1))+1)*2^height.val < 512 := by
      nlinarith
    have hnl : UScalar.cast .U32 l ≠ target ^^^ 1#u32 := by
      intro he; have hv := congrArg UScalar.val he; rw [hcast, hs] at hv; nlinarith
    have hnr : rightIdx ≠ target ^^^ 1#u32 := by
      intro he; have hv := congrArg UScalar.val he; rw [hrv, hs] at hv; nlinarith
    simp only [if_neg hnl, if_neg hnr, WP.spec_ok]

theorem xmss_auth_carry_outside_spec (seed sk : Std.Array Std.U8 32#usize)
    (layer leaf : Std.U32) (tree : Std.U64)
    (stack : Std.Array (Std.Array Std.U8 16#usize) 10#usize)
    (heights : Std.Array Std.U32 10#usize) (j sp : Std.Usize)
    (keep : Std.Array (Std.Array Std.U8 16#usize) 9#usize)
    (flags : Std.Array Bool 9#usize)
    (node : Std.Array Std.U8 16#usize) (height : Std.U32)
    (hleaf : 512 ≤ leaf.val)
    (hj : j.val < 512) (hheight : height.val < 10)
    (hdiv : (j.val+1) % 2^height.val = 0)
    (hsp : sp.val = (xmssRootSlots j.val).length - height.val)
    (hn : node = xmssRootNode seed sk layer tree height.val (j.val / 2^height.val))
    (hstack : xmssRootStack seed sk layer tree j.val stack heights) :
    merkle.build_subtree_with_auth_loop0_loop0 seed layer tree leaf stack heights sp keep flags j node height
      ⦃ r => r.1.val < 10 ∧ r.1.val ≤ (xmssRootSlots j.val).length ∧ r.2.2.2.2.val < 10 ∧
        r.2.2.2.1 = xmssRootNode seed sk layer tree r.2.2.2.2.val (j.val / 2^r.2.2.2.2.val) ∧
        xmssRootSlots (j.val+1) = (xmssRootSlots j.val).take r.1.val ++
          [(r.2.2.2.2.val, j.val / 2^r.2.2.2.2.val)] ∧
        (r.2.1, r.2.2.1) = (keep, flags) ⦄ := by
  unfold merkle.build_subtree_with_auth_loop0_loop0
  apply loop.spec_decr_nat
    (measure := fun (s : Std.Usize × Std.Array (Std.Array Std.U8 16#usize) 9#usize ×
      Std.Array Bool 9#usize × Std.Array Std.U8 16#usize × Std.U32) => s.1.val)
    (inv := fun (s : Std.Usize × Std.Array (Std.Array Std.U8 16#usize) 9#usize ×
      Std.Array Bool 9#usize × Std.Array Std.U8 16#usize × Std.U32) =>
      s.2.2.2.2.val < 10 ∧ (j.val+1) % 2^s.2.2.2.2.val = 0 ∧
      s.1.val = (xmssRootSlots j.val).length - s.2.2.2.2.val ∧
      s.2.2.2.1 = xmssRootNode seed sk layer tree s.2.2.2.2.val (j.val / 2^s.2.2.2.2.val) ∧
      (s.2.1, s.2.2.1) = (keep, flags))
  · rintro ⟨sp0, kept, marked, nd, h⟩ ⟨hh, hd, hs, hnd, hap⟩
    simp only at hh hd hs hnd hap
    have hsch := xmss_root_schedule ⟨j.val, hj⟩ ⟨h.val, hh⟩
    simp only [xmssRootScheduleAt, Fin.val_mk] at hsch
    obtain ⟨hhlen, hsch⟩ := hsch hd
    have hac := xmss_auth_carry_schedule ⟨j.val, hj⟩ ⟨h.val, hh⟩
    simp only [xmssAuthCarryAt, Fin.val_mk] at hac
    have hac := hac hd
    have hlen := xmssRootSlots_length j.val
    have hsp0 : sp0.val ≤ 10 := by omega
    unfold merkle.build_subtree_with_auth_loop0_loop0.body
    simp only [lift, core.convert.num.FromU64U32.from]
    split
    · rename_i hp0
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
        rw [if_pos hc] at hsch hac
        obtain ⟨hh9, hleft, hright, hdivnext⟩ := hsch
        let* ⟨leftNode, hleftNode⟩ ← Array.index_usize_spec stack i (by scalar_tac)
        have hsib : leftNode = xmssRootNode seed sk layer tree h.val
            (2 * (j.val / 2^(h.val+1))) := by
          have hsz : stack.val.length = 10 := by simpa using stack.property
          rw [hleftNode, ← getElem!_pos stack.val i.val (by omega), (hstack i.val hib).2, heqv]
          rw [show (xmssRootSlots j.val)[i.val]!.2 = 2 * (j.val / 2^(h.val+1)) from
            (by simpa [hiv, hs] using hleft)]
        have hrightNode : nd = xmssRootNode seed sk layer tree h.val
            (2 * (j.val / 2^(h.val+1))+1) := by rw [hnd, hright]
        have hidx : (UScalar.cast .Usize h).val = h.val := by
          rw [UScalar.cast_val_eq, Nat.mod_eq_of_lt (by scalar_tac)]
        let* ⟨b, hb⟩ ← Array.index_usize_spec marked (UScalar.cast .Usize h) (by scalar_tac)
        have hbval : b = marked.val[h.val]! := by
          have hsz : marked.val.length = 9 := by simpa using marked.property
          rw [hb, ← getElem!_pos marked.val (UScalar.cast .Usize h).val (by omega), hidx]
        have hcapture := xmss_auth_capture_outside leaf h j kept marked
          leftNode nd b hleaf hh9 hj hac
        simp only [lift, bind_tc_ok] at hcapture
        let* ⟨kept1, marked1, hap1⟩ ← hcapture
        let* ⟨h1, hh1⟩ ← Std.U32.add_spec (x := h) (y := 1#u32) (by scalar_tac)
        let* ⟨parentIdx, hparentIdx, hparentBv⟩ ← Std.Usize.ShiftRight_spec j h1
          (by have := System.Platform.numBits_eq; scalar_tac)
        have hip : parentIdx.val = j.val / 2^(h.val+1) := by
          rw [hparentIdx, Nat.shiftRight_eq_div_pow, hh1]
        have hipb : parentIdx.val < 512 := by rw [hip]; exact lt_of_le_of_lt (Nat.div_le_self _ _) hj
        have hcast : (UScalar.cast .U32 parentIdx).val = parentIdx.val := by
          rw [UScalar.cast_val_eq, Nat.mod_eq_of_lt (by scalar_tac)]
        let* ⟨adrs, hadrs⟩ ← make_adrs_spec layer tree params.ADRS_TREE 0#u32 0#u32 h1
          (UScalar.cast .U32 parentIdx)
        simp only [show params.ADRS_TREE.val = 2 by simp [params.ADRS_TREE], hh1, hcast, hip] at hadrs
        have hadeq := treeAdrs_eq_of_map_val adrs layer tree h.val
          (j.val / 2^(h.val+1)) hadrs
        let* ⟨left, hleftpad⟩ ← pad16_spec leftNode
        let* ⟨right, hrightpad⟩ ← pad16_spec nd
        let* ⟨parent, hparent⟩ ← hash.th_pair_spec seed adrs left right
        refine ⟨by omega, by simpa [hh1] using hdivnext, by omega, ?_,
          congrArg Prod.fst (hap1.trans hap), congrArg Prod.snd (hap1.trans hap), by omega⟩
        rw [hparent, hleftpad, hrightpad, ← hadeq, hsib, hnd, hright, hh1]
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
        rw [if_neg hc] at hsch hac
        simp only [WP.spec_ok]
        exact ⟨by omega, by omega, hh, hnd, by simpa [← hs] using hsch.2,
          by simpa only [Prod.mk.injEq] using hap⟩
    · rename_i hp0
      have hpv : sp0.val = 0 := by scalar_tac
      have hncond : ¬ ((xmssRootSlots j.val).length - h.val > 0 ∧
          (xmssRootSlots j.val)[(xmssRootSlots j.val).length - h.val - 1]!.1 = h.val) := by omega
      rw [if_neg hncond] at hsch hac
      simp only [WP.spec_ok]
      exact ⟨by omega, by omega, hh, hnd, by simpa [← hs] using hsch.2,
        by simpa only [Prod.mk.injEq] using hap⟩
  · exact ⟨hheight, hdiv, hsp, hn, rfl⟩

theorem xmss_auth_loop_outside_spec (seed sk : Std.Array Std.U8 32#usize)
    (layer leaf : Std.U32) (tree : Std.U64)
    (progress : hypertree.ProgressSink) (pct_lo pct_hi : Std.U8) (n_leaves : Std.Usize)
    (iter : core.ops.range.Range Std.Usize)
    (stack : Std.Array (Std.Array Std.U8 16#usize) 10#usize)
    (heights : Std.Array Std.U32 10#usize) (sp : Std.Usize)
    (keep : Std.Array (Std.Array Std.U8 16#usize) 9#usize)
    (flags : Std.Array Bool 9#usize)
    (hleaf : 512 ≤ leaf.val)
    (hnleaves : n_leaves.val = 512) (hend : iter.«end».val = 512) (hle : iter.start.val ≤ 512)
    (hsp : sp.val = (xmssRootSlots iter.start.val).length)
    (hstack : xmssRootStack seed sk layer tree iter.start.val stack heights) :
    merkle.build_subtree_with_auth_loop0 iter seed sk layer tree leaf progress pct_lo pct_hi
      n_leaves stack heights sp keep flags ⦃ r =>
        r.1.val[0]! = xmssRootNode seed sk layer tree 9 0 ∧
        r.2 = keep ⦄ := by
  unfold merkle.build_subtree_with_auth_loop0
  apply loop.spec_decr_nat
    (measure := fun (s : core.ops.range.Range Std.Usize ×
      Std.Array (Std.Array Std.U8 16#usize) 10#usize × Std.Array Std.U32 10#usize ×
      Std.Usize × Std.Array (Std.Array Std.U8 16#usize) 9#usize × Std.Array Bool 9#usize) =>
        512 - s.1.start.val)
    (inv := fun (s : core.ops.range.Range Std.Usize ×
      Std.Array (Std.Array Std.U8 16#usize) 10#usize × Std.Array Std.U32 10#usize ×
      Std.Usize × Std.Array (Std.Array Std.U8 16#usize) 9#usize × Std.Array Bool 9#usize) =>
        s.1.«end».val = 512 ∧ s.1.start.val ≤ 512 ∧
        s.2.2.2.1.val = (xmssRootSlots s.1.start.val).length ∧
        xmssRootStack seed sk layer tree s.1.start.val s.2.1 s.2.2.1 ∧
        (s.2.2.2.2.1, s.2.2.2.2.2) = (keep, flags))
  · rintro ⟨it, st, hs, sp0, kept, marked⟩ ⟨he, hl, hsp0, hst, hap⟩
    simp only at he hl hsp0 hst hap
    unfold merkle.build_subtree_with_auth_loop0.body
    simp only [lift, core.convert.num.FromU64U32.from]
    let* ⟨ob, it1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨j, it', heq, hj, hlt, hend', hstart'⟩
    · subst ho
      have hit : it.start.val = 512 := by omega
      have hx := hst 0 (by simp [hit])
      simp only [hit, xmssRootSlots_final, List.length_singleton, List.getElem!_cons_zero] at hx hsp0
      simp only [WP.spec_ok]
      exact ⟨hx.2, congrArg Prod.fst hap⟩
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      have hjv : j.val = it.start.val := by rw [hj]
      have hjb : j.val < 512 := by omega
      have hcastv : (UScalar.cast .U32 j).val = j.val := by
        rw [UScalar.cast_val_eq, Nat.mod_eq_of_lt (by scalar_tac)]
      have hcast : UScalar.cast .U32 j = (⟨BitVec.ofNat 32 j.val⟩ : Std.U32) := by
        apply UScalar.eq_of_val_eq
        rw [hcastv]
        exact (Nat.mod_eq_of_lt (show j.val < 2^32 by omega)).symm
      let* ⟨leafNode, hleafNode⟩ ← wots_keygen_pk_spec seed sk layer tree (UScalar.cast .U32 j)
      have hnode : leafNode = xmssRootNode seed sk layer tree 0 j.val := by
        rw [hleafNode, hcast, xmssRootNode]
      let* ⟨sp1, kept1, marked1, node, h, hs1, hsplen, hh, hn, hslots, hap1⟩ ←
        xmss_auth_carry_outside_spec seed sk layer leaf tree st hs j sp0 kept marked leafNode 0#u32
          hleaf hjb (by decide)
          (by simp [Nat.mod_one]) (by simpa [hjv] using hsp0) (by simpa using hnode)
          (by simpa [hjv] using hst)
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
        refine ⟨by rw [hend']; exact he, by omega, ?_, ?_, ?_, by omega⟩
        · rw [hsp2, hstart', ← hjv]
          exact hup.1.symm
        · rw [hst1, hhs2, hstart', ← hjv]
          exact hup.2
        · exact hap1.trans hap
  · exact ⟨hend, hle, hsp, hstack, rfl⟩

@[step] theorem xmss_build_auth_outside_spec (seed sk : Std.Array Std.U8 32#usize)
    (layer leaf : Std.U32) (tree : Std.U64)
    (progress : hypertree.ProgressSink) (pct_lo pct_hi : Std.U8)
    (hleaf : 512 ≤ leaf.val) :
    merkle.build_subtree_with_auth seed sk layer tree leaf progress pct_lo pct_hi ⦃ r =>
      r.2 = xmssRootNode seed sk layer tree 9 0 ∧
      r.1 = Array.repeat 9#usize (Array.repeat 16#usize 0#u8) ⦄ := by
  unfold merkle.build_subtree_with_auth
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
  let* ⟨stack, keep, hroot, hkeep⟩ ←
    xmss_auth_loop_outside_spec seed sk layer leaf tree progress pct_lo pct_hi n_leaves
      { start := 0#usize, «end» := n_leaves }
      (Array.repeat 10#usize (Array.repeat 16#usize 0#u8))
      (Array.repeat 10#usize 0#u32) 0#usize
      (Array.repeat 9#usize (Array.repeat 16#usize 0#u8)) (Array.repeat 9#usize false)
      hleaf hn hn
      (by simp) (by simp) (by intro p hp; simpa using hp)
  step* <;> first | scalar_tac | skip
  let* ⟨path, hpath⟩ ← xmss_auth_copy_spec keep
    (Array.repeat 9#usize (Array.repeat 16#usize 0#u8))
    { start := 0#usize, «end» := i }
    (by scalar_tac) (by simp) (by intro k hk; simp at hk)
  constructor
  · rw [root_post, ← getElem!_pos stack.val 0 (by simpa using stack.property)]
    exact hroot
  · exact hpath.trans hkeep

end Extracted.Equiv

/- Total correctness of the actual FORS authentication-path treehash. -/
import Extracted.ForsAuth.Funs
import Extracted.ForsAuthCapture

open Aeneas Aeneas.Std Result
set_option maxHeartbeats 2000000
set_option maxRecDepth 8192
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes
namespace Extracted.Equiv
open sphincs_c10
attribute [local irreducible] forsRootNode forsRootSlots forsAuthEnd forsAuthSibling

theorem fors_auth_carry_spec (seed sk : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) (auth : Std.Array (Std.Array Std.U8 16#usize) 11#usize) (stack : Std.Array (Std.Array Std.U8 16#usize) 12#usize)
    (heights : Std.Array Std.U32 12#usize) (j sp : Std.Usize)
    (node : Std.Array Std.U8 16#usize) (height : Std.U32)
    (hleaf : leaf.val < 2048) (hp : forsAuthPathAt seed sk ht tree leaf.val j.val height.val auth)
    (hj : j.val < 2048) (hheight : height.val < 12)
    (hdiv : (j.val+1) % 2^height.val = 0)
    (hsp : sp.val = (forsRootSlots j.val).length - height.val)
    (hn : node = forsRootNode seed sk ht tree height.val (j.val / 2^height.val))
    (hstack : forsRootStack seed sk ht tree j.val stack heights) :
    fors.sign_fors_tree_loop0_loop0 seed ht tree leaf auth stack heights sp j node height
      ⦃ r => r.2.1.val < 12 ∧ r.2.1.val ≤ (forsRootSlots j.val).length ∧ r.2.2.2.val < 12 ∧
        r.2.2.1 = forsRootNode seed sk ht tree r.2.2.2.val (j.val / 2^r.2.2.2.val) ∧
        forsRootSlots (j.val+1) = (forsRootSlots j.val).take r.2.1.val ++
          [(r.2.2.2.val, j.val / 2^r.2.2.2.val)] ∧
        forsAuthPathAt seed sk ht tree leaf.val (j.val+1) 0 r.1 ⦄ := by
  unfold fors.sign_fors_tree_loop0_loop0
  apply loop.spec_decr_nat
    (measure := fun (s : Std.Array (Std.Array Std.U8 16#usize) 11#usize ×
      Std.Usize × Std.Array Std.U8 16#usize × Std.U32) => s.2.1.val)
    (inv := fun (s : Std.Array (Std.Array Std.U8 16#usize) 11#usize ×
      Std.Usize × Std.Array Std.U8 16#usize × Std.U32) =>
      s.2.2.2.val < 12 ∧ (j.val+1) % 2^s.2.2.2.val = 0 ∧
      s.2.1.val = (forsRootSlots j.val).length - s.2.2.2.val ∧
      s.2.2.1 = forsRootNode seed sk ht tree s.2.2.2.val (j.val / 2^s.2.2.2.val) ∧
      forsAuthPathAt seed sk ht tree leaf.val j.val s.2.2.2.val s.1)
  · rintro ⟨ap, sp0, nd, h⟩ ⟨hh, hd, hs, hnd, hap⟩
    simp only at hh hd hs hnd hap
    have hsch := fors_root_schedule ⟨j.val, hj⟩ ⟨h.val, hh⟩
    simp only [forsRootScheduleAt, Fin.val_mk] at hsch
    obtain ⟨hhlen, hsch⟩ := hsch hd
    have hac := fors_auth_carry_schedule ⟨j.val, hj⟩ ⟨h.val, hh⟩
    simp only [forsAuthCarryAt, Fin.val_mk] at hac
    have hac := hac hd
    have hlen := forsRootSlots_length j.val
    have hsp0 : sp0.val ≤ 12 := by omega
    unfold fors.sign_fors_tree_loop0_loop0.body
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
        rw [if_pos hc] at hsch hac
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
        have hsib : sibling = forsRootNode seed sk ht tree h.val
            (2 * (j.val / 2^(h.val+1))) := by
          have hsz : stack.val.length = 12 := by simpa using stack.property
          rw [sibling_post, ← getElem!_pos stack.val i.val (by omega), (hstack i.val hib).2, heqv]
          rw [show (forsRootSlots j.val)[i.val]!.2 = 2 * (j.val / 2^(h.val+1)) from
            (by simpa [hiv, hs] using hleft)]
        have hrightnode : nd = forsRootNode seed sk ht tree h.val
            (2*(j.val/2^(h.val+1))+1) := by rw [hnd, hright]
        let* ⟨target, htarg, htbv⟩ ← Std.U32.ShiftRight_spec leaf h (by scalar_tac)
        try simp only [lift, bind_tc_ok]
        have hsibidx : (target ^^^ 1#u32).val = forsAuthSibling leaf.val h.val := by
          rw [UScalar.val_xor, htarg, Nat.shiftRight_eq_div_pow, forsAuthSibling]
          rfl
        let* ⟨q, hq, hqbv⟩ ← Std.Usize.ShiftRight_spec j i2
          (by have := System.Platform.numBits_eq; scalar_tac)
        have hqv : q.val = j.val/2^(h.val+1) := by
          rw [hq, Nat.shiftRight_eq_div_pow, i2_post]
        let* ⟨ls, hls, hlsbv⟩ ← Std.Usize.ShiftLeft_spec q i2
          (by have := System.Platform.numBits_eq; scalar_tac)
        have hlsb : (j.val/2^(h.val+1))*2^(h.val+1) < 2048 := by nlinarith [pow_pos (by decide : 0 < (2:Nat)) (h.val+1)]
        have hlsv : ls.val = (j.val/2^(h.val+1))*2^(h.val+1) := by
          rw [hls, Nat.shiftLeft_eq, hqv, i2_post]
          exact Nat.mod_eq_of_lt (by scalar_tac)
        let* ⟨one, hone, honebv⟩ ← Std.Usize.ShiftLeft_spec 1#usize h
          (by have := System.Platform.numBits_eq; scalar_tac)
        have hpowb : 2^h.val ≤ 1024 := by
          exact Nat.pow_le_pow_right (by decide : 0 < (2:Nat)) (show h.val ≤ 10 by omega)
        have honev : one.val = 2^h.val := by
          rw [hone, Nat.shiftLeft_eq]
          simp only [show (1#usize : Std.Usize).val = 1 from rfl, Nat.one_mul]
          exact Nat.mod_eq_of_lt (by scalar_tac)
        let* ⟨rs, hrs⟩ ← Std.Usize.add_spec (x := ls) (y := one) (by scalar_tac)
        try simp only [lift, bind_tc_ok]
        have hcapture := fors_auth_capture_spec seed sk ht tree leaf h (target ^^^ 1#u32)
          j ls rs ap sibling nd hleaf hh11 hj hsibidx hac hlsv (by rw [hrs, honev]) hsib hrightnode hap
        simp only [lift, bind_tc_ok] at hcapture
        let* ⟨ap1, hap1⟩ ← hcapture
        let* ⟨left, hleftpad⟩ ← pad16_spec sibling
        let* ⟨right, hrightpad⟩ ← pad16_spec nd
        let* ⟨parent, hparent⟩ ← hash.th_pair_spec seed adrs left right
        refine ⟨by omega, by simpa [i2_post] using hdivnext, by omega, ?_, by simpa [i2_post] using hap1, by omega⟩
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
        rw [if_neg hc] at hsch hac
        simp only [WP.spec_ok]
        exact ⟨by omega, by omega, hh, hnd, by simpa [← hs] using hsch.2,
          fors_auth_path_done seed sk ht tree leaf.val j.val h.val ap hleaf hac hap⟩
    · rename_i hp
      have hpv : sp0.val = 0 := by scalar_tac
      have hncond : ¬ ((forsRootSlots j.val).length - h.val > 0 ∧
          (forsRootSlots j.val)[(forsRootSlots j.val).length - h.val - 1]!.1 = h.val) := by
        omega
      rw [if_neg hncond] at hsch hac
      simp only [WP.spec_ok]
      exact ⟨by omega, by omega, hh, hnd, by simpa [← hs] using hsch.2,
          fors_auth_path_done seed sk ht tree leaf.val j.val h.val ap hleaf hac hap⟩
  · exact ⟨hheight, hdiv, hsp, hn, hp⟩


theorem fors_auth_loop_spec (seed sk : Std.Array Std.U8 32#usize) (ht tree leaf : Std.U32)
    (iter : core.ops.range.Range Std.Usize)
    (auth : Std.Array (Std.Array Std.U8 16#usize) 11#usize)
    (stack : Std.Array (Std.Array Std.U8 16#usize) 12#usize)
    (heights : Std.Array Std.U32 12#usize) (sp : Std.Usize)
    (hleaf : leaf.val < 2048)
    (hp : forsAuthPathAt seed sk ht tree leaf.val iter.start.val 0 auth)
    (hend : iter.«end».val = 2048) (hle : iter.start.val ≤ 2048)
    (hsp : sp.val = (forsRootSlots iter.start.val).length)
    (hstack : forsRootStack seed sk ht tree iter.start.val stack heights) :
    fors.sign_fors_tree_loop0 iter seed sk ht tree leaf auth stack heights sp
      ⦃ r => ∀ k, k < 11 → r.val[k]! = forsRootNode seed sk ht tree k (forsAuthSibling leaf.val k) ⦄ := by
  unfold fors.sign_fors_tree_loop0
  apply loop.spec_decr_nat
    (measure := fun (s : core.ops.range.Range Std.Usize ×
      Std.Array (Std.Array Std.U8 16#usize) 11#usize ×
      Std.Array (Std.Array Std.U8 16#usize) 12#usize × Std.Array Std.U32 12#usize × Std.Usize) =>
        2048 - s.1.start.val)
    (inv := fun (s : core.ops.range.Range Std.Usize ×
      Std.Array (Std.Array Std.U8 16#usize) 11#usize ×
      Std.Array (Std.Array Std.U8 16#usize) 12#usize × Std.Array Std.U32 12#usize × Std.Usize) =>
        s.1.«end».val = 2048 ∧ s.1.start.val ≤ 2048 ∧
        s.2.2.2.2.val = (forsRootSlots s.1.start.val).length ∧
        forsRootStack seed sk ht tree s.1.start.val s.2.2.1 s.2.2.2.1 ∧
        forsAuthPathAt seed sk ht tree leaf.val s.1.start.val 0 s.2.1)
  · rintro ⟨it, ap, st, hs, sp0⟩ ⟨he, hl, hsp0, hst, hap⟩
    simp only at he hl hsp0 hst hap
    unfold fors.sign_fors_tree_loop0.body
    simp only [lift, core.convert.num.FromU64U32.from]
    let* ⟨ob, it1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨j, it', heq, hj, hlt, hend', hstart'⟩
    · subst ho
      have hit : it.start.val = 2048 := by omega
      simp only [WP.spec_ok]
      exact fors_auth_path_final seed sk ht tree leaf.val ap hleaf (by simpa [hit] using hap)
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
      let* ⟨leafNode, hleafNode⟩ ← hash.th_spec seed adrs padded
      have hleafnode : leafNode = forsRootNode seed sk ht tree 0 j.val := by
        rw [hleafNode, hpadded, ← hadeq, hsecret, hcast]
        rw [forsRootNode]
      let* ⟨ap1, sp1, node, h, hs1, hsplen, hh, hn, hslots, hap1⟩ ←
        fors_auth_carry_spec seed sk ht tree leaf ap st hs j sp0 leafNode 0#u32 hleaf
          (by simpa [hjv] using hap) hjb (by decide)
          (by simp [Nat.mod_one]) (by simpa [hjv] using hsp0) (by simpa using hleafnode) (by simpa [hjv] using hst)
      let* ⟨st1, hst1⟩ ← Array.update_spec st sp1 node (by simpa using hs1)
      let* ⟨hs2, hhs2⟩ ← Array.update_spec hs sp1 h (by simpa using hs1)
      let* ⟨sp2, hsp2⟩ ← Std.Usize.add_spec (x := sp1) (y := 1#usize) (by scalar_tac)
      have hup := fors_root_stack_update seed sk ht tree j.val st hs sp1 node h hs1 hsplen hn hslots
        (by simpa [hjv] using hst)
      refine ⟨by rw [hend']; exact he, by omega, ?_, ?_, ?_, by omega⟩
      · rw [hsp2, hstart', ← hjv]
        exact hup.1.symm
      · rw [hst1, hhs2, hstart', ← hjv]
        exact hup.2
      · simpa [hstart', ← hjv] using hap1
  · exact ⟨hend, hle, hsp, hstack, hp⟩


/-- Totality and every output byte of the actual Rust helper for every valid
    leaf index. The leaf range is explicit, not a desired-output premise. -/
@[step] theorem fors_sign_tree_spec (seed sk : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) (hleaf : leaf.val < 2048) :
    fors.sign_fors_tree seed sk ht tree leaf ⦃ r =>
      r.1 = forsSecretPure sk ht tree leaf ∧
      ∀ k, k < 11 → r.2.val[k]! = forsRootNode seed sk ht tree k (forsAuthSibling leaf.val k) ⦄ := by
  unfold fors.sign_fors_tree
  let* ⟨secret, hsecret⟩ ← fors_secret_spec sk ht tree leaf
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
  let* ⟨path, hpath⟩ ← fors_auth_loop_spec seed sk ht tree leaf
    { start := 0#usize, «end» := n_leaves }
    (Array.repeat 11#usize (Array.repeat 16#usize 0#u8))
    (Array.repeat 12#usize (Array.repeat 16#usize 0#u8))
    (Array.repeat 12#usize 0#u32) 0#usize hleaf
    (fors_auth_path_initial seed sk ht tree leaf.val _) hn (by simp) (by simp)
    (by intro p hp; simpa using hp)
  exact ⟨hsecret, hpath⟩

end Extracted.Equiv

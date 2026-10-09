/- Actual keep/keep-set branches preserve the exact XMSS capture invariant. -/
import Extracted.XmssAuthInvariant
import Extracted.XmssAuth.Funs

open Aeneas Aeneas.Std Result
set_option maxHeartbeats 2000000
set_option maxRecDepth 8192
namespace Extracted.Equiv
attribute [local irreducible] xmssRootNode xmssRootSlots xmssAuthEnd xmssAuthSibling

theorem xmss_auth_capture_spec (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (leaf height : Std.U32) (j : Std.Usize)
    (keep : Std.Array (Std.Array Std.U8 16#usize) 9#usize)
    (flags : Std.Array Bool 9#usize) (left right : Std.Array Std.U8 16#usize) (b : Bool)
    (hleaf : leaf.val < 512) (hh : height.val < 9) (hj : j.val < 512)
    (halign : j.val+1 = (j.val / 2^(height.val+1)+1)*2^(height.val+1))
    (hleft : left = xmssRootNode seed sk layer tree height.val (2*(j.val/2^(height.val+1))))
    (hright : right = xmssRootNode seed sk layer tree height.val (2*(j.val/2^(height.val+1))+1))
    (hbval : b = flags.val[height.val]!)
    (hp : xmssAuthKeepAt seed sk layer tree leaf.val j.val height.val keep flags) :
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
      xmssAuthKeepAt seed sk layer tree leaf.val j.val (height.val+1) r.1 r.2 ⦄ := by
  have hidx : (UScalar.cast .Usize height).val = height.val := by
    rw [UScalar.cast_val_eq, Nat.mod_eq_of_lt (by scalar_tac)]
  have hupdate := xmss_auth_capture_update seed sk layer tree leaf.val j.val height.val
    keep flags (UScalar.cast .Usize height) hh hidx hp
  simp only [lift, bind_tc_ok]
  split
  · rename_i htrue
    have hr := (hp height.val hh).1.mp (by rw [← hbval]; exact htrue)
    have hne : xmssAuthEnd leaf.val height.val ≠ j.val := by
      unfold xmssAuthReady at hr
      omega
    simpa only [WP.spec_ok, if_neg hne] using hupdate
  · rename_i hfalse
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
    have hc := xmss_auth_leaf_schedule ⟨leaf.val, hleaf⟩ ⟨height.val, hh⟩
    simp only [xmssAuthLeafAt, Fin.val_mk] at hc
    obtain ⟨_, _, _, _, hend, _, hside, _⟩ := hc
    have hwhich : xmssAuthSibling leaf.val height.val =
          2*(xmssAuthEnd leaf.val height.val/2^(height.val+1)) ∨
        xmssAuthSibling leaf.val height.val =
          2*(xmssAuthEnd leaf.val height.val/2^(height.val+1))+1 := by
      split_ifs at hside
      · exact Or.inl hside
      · exact Or.inr hside
    have hmatch :
        (xmssAuthSibling leaf.val height.val = 2*(j.val/2^(height.val+1)) ∨
         xmssAuthSibling leaf.val height.val = 2*(j.val/2^(height.val+1))+1) ↔
        xmssAuthEnd leaf.val height.val = j.val := by
      constructor
      · intro hm
        have heq : xmssAuthEnd leaf.val height.val/2^(height.val+1) =
            j.val/2^(height.val+1) := by omega
        rw [heq] at hend
        omega
      · intro heq
        simpa only [heq] using hwhich
    split
    · rename_i heq
      have heqv := congrArg UScalar.val heq
      rw [hcast, hs] at heqv
      have hit := hmatch.mp (Or.inl heqv.symm)
      let* ⟨out, hout⟩ ← Array.update_spec keep (UScalar.cast .Usize height) left (by scalar_tac)
      let* ⟨set, hset⟩ ← Array.update_spec flags (UScalar.cast .Usize height) true (by scalar_tac)
      rw [hout, hset, hleft, heqv]
      simpa only [if_pos hit] using hupdate
    · rename_i hnotleft
      split
      · rename_i heq
        have heqv := congrArg UScalar.val heq
        rw [hrv, hs] at heqv
        have hit := hmatch.mp (Or.inr heqv.symm)
        let* ⟨out, hout⟩ ← Array.update_spec keep (UScalar.cast .Usize height) right (by scalar_tac)
        let* ⟨set, hset⟩ ← Array.update_spec flags (UScalar.cast .Usize height) true (by scalar_tac)
        rw [hout, hset, hright, heqv]
        simpa only [if_pos hit] using hupdate
      · rename_i hnotright
        have hne : xmssAuthEnd leaf.val height.val ≠ j.val := by
          intro hit
          rcases hmatch.mpr hit with hx | hx
          · apply hnotleft
            apply UScalar.eq_of_val_eq
            rw [hcast, hs, hx]
          · apply hnotright
            apply UScalar.eq_of_val_eq
            rw [hrv, hs, hx]
        simpa only [WP.spec_ok, if_neg hne] using hupdate

end Extracted.Equiv

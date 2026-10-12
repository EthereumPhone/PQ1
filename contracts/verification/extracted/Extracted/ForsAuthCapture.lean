/- The actual sibling-capture branches preserve every reached authentication slot. -/
import Extracted.ForsAuthInvariant

open Aeneas Aeneas.Std Result
set_option maxHeartbeats 2000000
set_option maxRecDepth 8192
namespace Extracted.Equiv
attribute [local irreducible] forsRootNode forsRootSlots forsAuthEnd forsAuthSibling

theorem fors_auth_capture_spec (seed sk : Std.Array Std.U8 32#usize) (ht tree leaf h s : Std.U32)
    (j leftStart rightStart : Std.Usize)
    (path : Std.Array (Std.Array Std.U8 16#usize) 11#usize)
    (left right : Std.Array Std.U8 16#usize)
    (hleaf : leaf.val < 2048) (hh : h.val < 11) (hjb : j.val < 2048)
    (hs : s.val = forsAuthSibling leaf.val h.val)
    (hj : j.val+1 = (j.val/2^(h.val+1)+1)*2^(h.val+1))
    (hleftStart : leftStart.val = (j.val/2^(h.val+1))*2^(h.val+1))
    (hrightStart : rightStart.val = leftStart.val + 2^h.val)
    (hleft : left = forsRootNode seed sk ht tree h.val (2*(j.val/2^(h.val+1))))
    (hright : right = forsRootNode seed sk ht tree h.val (2*(j.val/2^(h.val+1))+1))
    (hp : forsAuthPathAt seed sk ht tree leaf.val j.val h.val path) :
    (if s &&& 1#u32 = 0#u32 then do
        let i8 ← s <<< h
        let i9 ← lift (UScalar.cast .U32 leftStart)
        if i8 = i9 then do
          let i10 ← lift (UScalar.cast .Usize h)
          Array.update path i10 left
        else ok path
     else do
        let i8 ← s <<< h
        let i9 ← lift (UScalar.cast .U32 rightStart)
        if i8 = i9 then do
          let i10 ← lift (UScalar.cast .Usize h)
          Array.update path i10 right
        else ok path) ⦃ out =>
      forsAuthPathAt seed sk ht tree leaf.val j.val (h.val+1) out ⦄ := by
  have hc := fors_auth_leaf_schedule ⟨leaf.val, hleaf⟩ ⟨h.val, hh⟩
  simp only [forsAuthLeafAt, Fin.val_mk] at hc
  obtain ⟨hsb, hshiftb, heb, hediv, he, hsspec, hside, hfoot⟩ := hc
  have hp0 : 0 < 2^h.val := by positivity
  have hpow : 2^(h.val+1) = 2^h.val*2 := by rw [pow_succ]
  have hleftb : leftStart.val < 2048 := by nlinarith
  have hrightb : rightStart.val < 2048 := by nlinarith
  have hidx : (UScalar.cast .Usize h).val = h.val := by
    rw [UScalar.cast_val_eq]
    apply Nat.mod_eq_of_lt
    scalar_tac
  have hand : (s &&& 1#u32).val = forsAuthSibling leaf.val h.val % 2 := by
    rw [UScalar.val_and, hs]
    simp only [show (1#u32 : Std.U32).val = 1 from rfl, Nat.and_comm, Nat.one_and_eq_mod_two]
  have hresult := fors_auth_capture_update seed sk ht tree leaf.val j.val h.val path
    (UScalar.cast .Usize h) hh hidx hp
  split
  · rename_i heven
    have hev : forsAuthSibling leaf.val h.val % 2 = 0 := by rw [← hand, heven]; rfl
    rw [if_pos hev] at hside
    let* ⟨shifted, hshift, hbv⟩ ← Std.U32.ShiftLeft_spec s h (by scalar_tac)
    have hshiftval : shifted.val = forsAuthSibling leaf.val h.val * 2^h.val := by
      rw [hshift, Nat.shiftLeft_eq, hs, Nat.mod_eq_of_lt (by scalar_tac)]
    simp only [lift, bind_tc_ok]
    have hcast : (UScalar.cast .U32 leftStart).val = leftStart.val := by
      rw [UScalar.cast_val_eq, Nat.mod_eq_of_lt (by scalar_tac)]
    have hit : shifted = UScalar.cast .U32 leftStart ↔ forsAuthEnd leaf.val h.val = j.val := by
      constructor
      · intro hx
        have hxv := congrArg UScalar.val hx
        rw [hshiftval, hcast, hleftStart, hside, hpow] at hxv
        rw [hpow] at hj he
        nlinarith
      · intro hx
        apply UScalar.eq_of_val_eq
        rw [hshiftval, hcast, hleftStart, hside, hx, hpow]
        ring
    split
    · rename_i heq
      have heqj := hit.mp heq
      let* ⟨out, hout⟩ ← Array.update_spec path (UScalar.cast .Usize h) left (by scalar_tac)
      rw [hout]
      rw [if_pos heqj] at hresult
      have hn : left = forsRootNode seed sk ht tree h.val (forsAuthSibling leaf.val h.val) := by
        rw [hleft, hside, heqj]
      rw [hn]
      exact hresult
    · rename_i hne
      have hnej : forsAuthEnd leaf.val h.val ≠ j.val := fun hx => hne (hit.mpr hx)
      simpa only [WP.spec_ok, if_neg hnej] using hresult
  · rename_i hodd
    have hod : forsAuthSibling leaf.val h.val % 2 ≠ 0 := by
      intro hx
      apply hodd
      apply UScalar.eq_of_val_eq
      simpa [hand] using hx
    rw [if_neg hod] at hside
    let* ⟨shifted, hshift, hbv⟩ ← Std.U32.ShiftLeft_spec s h (by scalar_tac)
    have hshiftval : shifted.val = forsAuthSibling leaf.val h.val * 2^h.val := by
      rw [hshift, Nat.shiftLeft_eq, hs, Nat.mod_eq_of_lt (by scalar_tac)]
    simp only [lift, bind_tc_ok]
    have hcast : (UScalar.cast .U32 rightStart).val = rightStart.val := by
      rw [UScalar.cast_val_eq, Nat.mod_eq_of_lt (by scalar_tac)]
    have hit : shifted = UScalar.cast .U32 rightStart ↔ forsAuthEnd leaf.val h.val = j.val := by
      constructor
      · intro hx
        have hxv := congrArg UScalar.val hx
        rw [hshiftval, hcast, hrightStart, hleftStart, hside, hpow] at hxv
        rw [hpow] at hj he
        nlinarith
      · intro hx
        apply UScalar.eq_of_val_eq
        rw [hshiftval, hcast, hrightStart, hleftStart, hside, hx, hpow]
        ring
    split
    · rename_i heq
      have heqj := hit.mp heq
      let* ⟨out, hout⟩ ← Array.update_spec path (UScalar.cast .Usize h) right (by scalar_tac)
      rw [hout]
      rw [if_pos heqj] at hresult
      have hn : right = forsRootNode seed sk ht tree h.val (forsAuthSibling leaf.val h.val) := by
        rw [hright, hside, heqj]
      rw [hn]
      exact hresult
    · rename_i hne
      have hnej : forsAuthEnd leaf.val h.val ≠ j.val := fun hx => hne (hit.mpr hx)
      simpa only [WP.spec_ok, if_neg hnej] using hresult

end Extracted.Equiv

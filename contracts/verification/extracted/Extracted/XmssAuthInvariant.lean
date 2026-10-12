/- Sibling values and exact capture flags along the XMSS tree traversal. -/
import Extracted.XmssRootSpec
import Extracted.XmssAuthSchedule

open Aeneas Aeneas.Std Result
namespace Extracted.Equiv

attribute [local irreducible] xmssRootNode xmssRootSlots xmssAuthEnd xmssAuthSibling

def xmssAuthReady (leaf j h k : Nat) : Prop :=
  xmssAuthEnd leaf k < j ∨ xmssAuthEnd leaf k = j ∧ k < h

def xmssAuthKeepAt (seed sk : Std.Array Std.U8 32#usize) (layer : Std.U32)
    (tree : Std.U64) (leaf j h : Nat)
    (keep : Std.Array (Std.Array Std.U8 16#usize) 9#usize)
    (flags : Std.Array Bool 9#usize) : Prop :=
  ∀ k, k < 9 →
    (flags.val[k]! = true ↔ xmssAuthReady leaf j h k) ∧
    (xmssAuthReady leaf j h k →
      keep.val[k]! = xmssRootNode seed sk layer tree k (xmssAuthSibling leaf k))

theorem xmss_auth_capture_update (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (leaf j h : Nat)
    (keep : Std.Array (Std.Array Std.U8 16#usize) 9#usize)
    (flags : Std.Array Bool 9#usize) (idx : Std.Usize)
    (hh : h < 9) (hi : idx.val = h)
    (hp : xmssAuthKeepAt seed sk layer tree leaf j h keep flags) :
    xmssAuthKeepAt seed sk layer tree leaf j (h+1)
      (if xmssAuthEnd leaf h = j then
        keep.set idx (xmssRootNode seed sk layer tree h (xmssAuthSibling leaf h))
       else keep)
      (if xmssAuthEnd leaf h = j then flags.set idx true else flags) := by
  intro k hk
  by_cases hit : xmssAuthEnd leaf h = j
  · rw [if_pos hit, if_pos hit]
    simp only [Array.set_val_eq]
    by_cases heq : k = h
    · subst k
      have hflags : flags.val.length = 9 := by simpa using flags.property
      have hkeep : keep.val.length = 9 := by simpa using keep.property
      have hf := List.set_getElem!_eq flags.val idx.val h true
        ⟨by simpa [hflags] using hh, hi⟩
      have hv := List.set_getElem!_eq keep.val idx.val h
        (xmssRootNode seed sk layer tree h (xmssAuthSibling leaf h))
        ⟨by simpa [hkeep] using hh, hi⟩
      constructor
      · rw [hf]
        simp [xmssAuthReady, hit]
      · intro _; exact hv
    · rw [List.set_getElem!_ne _ _ _ _ (by omega),
        List.set_getElem!_ne _ _ _ _ (by omega)]
      have hr : xmssAuthReady leaf j (h+1) k ↔ xmssAuthReady leaf j h k := by
        unfold xmssAuthReady
        omega
      exact ⟨(hp k hk).1.trans hr.symm, fun hx => (hp k hk).2 (hr.mp hx)⟩
  · rw [if_neg hit, if_neg hit]
    have hr : xmssAuthReady leaf j (h+1) k ↔ xmssAuthReady leaf j h k := by
      unfold xmssAuthReady
      by_cases heq : k = h
      · subst k; omega
      · omega
    exact ⟨(hp k hk).1.trans hr.symm, fun hx => (hp k hk).2 (hr.mp hx)⟩

theorem xmss_auth_keep_done (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (leaf j h : Nat)
    (keep : Std.Array (Std.Array Std.U8 16#usize) 9#usize)
    (flags : Std.Array Bool 9#usize) (hleaf : leaf < 512)
    (hend : (j+1) % 2^(h+1) ≠ 0)
    (hp : xmssAuthKeepAt seed sk layer tree leaf j h keep flags) :
    xmssAuthKeepAt seed sk layer tree leaf (j+1) 0 keep flags := by
  intro k hk
  have hr : xmssAuthReady leaf (j+1) 0 k ↔ xmssAuthReady leaf j h k := by
    constructor
    · intro hx
      have he : xmssAuthEnd leaf k < j+1 := by unfold xmssAuthReady at hx; omega
      by_cases heq : xmssAuthEnd leaf k = j
      · right
        refine ⟨heq, ?_⟩
        by_contra hn
        have hs := xmss_auth_leaf_schedule ⟨leaf, hleaf⟩ ⟨k, hk⟩
        simp only [xmssAuthLeafAt, Fin.val_mk] at hs
        have halign := hs.2.2.2.1
        rw [heq] at halign
        have hd := (pow_dvd_pow (2 : Nat) (show h+1 ≤ k+1 by omega)).trans
          (Nat.dvd_of_mod_eq_zero halign)
        exact hend (Nat.mod_eq_zero_of_dvd hd)
      · left; omega
    · intro hx
      unfold xmssAuthReady at hx ⊢
      omega
  exact ⟨(hp k hk).1.trans hr.symm, fun hx => (hp k hk).2 (hr.mp hx)⟩

theorem xmss_auth_keep_initial (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (leaf : Nat)
    (keep : Std.Array (Std.Array Std.U8 16#usize) 9#usize) :
    xmssAuthKeepAt seed sk layer tree leaf 0 0 keep (Array.repeat 9#usize false) := by
  intro k hk
  constructor
  · rw [Array.repeat_val, List.getElem!_replicate false (by simpa using hk)]
    simp [xmssAuthReady]
  · intro hx
    unfold xmssAuthReady at hx
    omega

theorem xmss_auth_keep_final (seed sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (leaf : Nat)
    (keep : Std.Array (Std.Array Std.U8 16#usize) 9#usize)
    (flags : Std.Array Bool 9#usize) (hleaf : leaf < 512)
    (hp : xmssAuthKeepAt seed sk layer tree leaf 512 0 keep flags) :
    ∀ k, k < 9 → flags.val[k]! = true ∧
      keep.val[k]! = xmssRootNode seed sk layer tree k (xmssAuthSibling leaf k) := by
  intro k hk
  have hr : xmssAuthReady leaf 512 0 k := by
    left
    exact (xmss_auth_leaf_schedule ⟨leaf, hleaf⟩ ⟨k, hk⟩).2.2.1
  exact ⟨(hp k hk).1.mpr hr, (hp k hk).2 hr⟩

end Extracted.Equiv

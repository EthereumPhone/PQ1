/- Authentication slots already reached by a left-to-right tree traversal. -/
import Extracted.ForsRootSpec
import Extracted.ForsAuthSchedule

open Aeneas Aeneas.Std Result
namespace Extracted.Equiv

attribute [local irreducible] forsRootNode forsRootSlots forsAuthEnd forsAuthSibling

def forsAuthReady (leaf j h k : Nat) : Prop :=
  forsAuthEnd leaf k < j ∨ forsAuthEnd leaf k = j ∧ k < h

def forsAuthPathAt (seed sk : Std.Array Std.U8 32#usize) (ht tree : Std.U32)
    (leaf j h : Nat) (path : Std.Array (Std.Array Std.U8 16#usize) 11#usize) : Prop :=
  ∀ k, k < 11 → forsAuthReady leaf j h k →
    path.val[k]! = forsRootNode seed sk ht tree k (forsAuthSibling leaf k)

theorem fors_auth_capture_update (seed sk : Std.Array Std.U8 32#usize) (ht tree : Std.U32)
    (leaf j h : Nat) (path : Std.Array (Std.Array Std.U8 16#usize) 11#usize)
    (idx : Std.Usize) (hh : h < 11) (hi : idx.val = h)
    (hp : forsAuthPathAt seed sk ht tree leaf j h path) :
    forsAuthPathAt seed sk ht tree leaf j (h+1)
      (if forsAuthEnd leaf h = j then
        path.set idx (forsRootNode seed sk ht tree h (forsAuthSibling leaf h))
       else path) := by
  intro k hk hr
  by_cases hit : forsAuthEnd leaf h = j
  · rw [if_pos hit]
    simp only [Array.set_val_eq]
    by_cases heq : k = h
    · subst k
      exact List.set_getElem!_eq _ _ _ _ ⟨by simpa [hi] using hh, hi⟩
    · rw [List.set_getElem!_ne _ _ _ _ (by omega)]
      apply hp k hk
      unfold forsAuthReady at hr ⊢
      omega
  · rw [if_neg hit]
    apply hp k hk
    unfold forsAuthReady at hr ⊢
    by_cases heq : k = h
    · subst k; omega
    · omega

theorem fors_auth_path_done (seed sk : Std.Array Std.U8 32#usize) (ht tree : Std.U32)
    (leaf j h : Nat) (path : Std.Array (Std.Array Std.U8 16#usize) 11#usize)
    (hleaf : leaf < 2048) (hend : (j+1) % 2^(h+1) ≠ 0)
    (hp : forsAuthPathAt seed sk ht tree leaf j h path) :
    forsAuthPathAt seed sk ht tree leaf (j+1) 0 path := by
  intro k hk hr
  have hc : forsAuthEnd leaf k < j+1 := by unfold forsAuthReady at hr; omega
  apply hp k hk
  by_cases heq : forsAuthEnd leaf k = j
  · right
    refine ⟨heq, ?_⟩
    by_contra hn
    have hleafs := fors_auth_leaf_schedule ⟨leaf, hleaf⟩ ⟨k, hk⟩
    simp only [forsAuthLeafAt, Fin.val_mk] at hleafs
    have halign := hleafs.2.2.2.1
    rw [heq] at halign
    have hd := (pow_dvd_pow (2 : Nat) (show h+1 ≤ k+1 by omega)).trans
      (Nat.dvd_of_mod_eq_zero halign)
    exact hend (Nat.mod_eq_zero_of_dvd hd)
  · left; omega

theorem fors_auth_path_initial (seed sk : Std.Array Std.U8 32#usize) (ht tree : Std.U32)
    (leaf : Nat) (path : Std.Array (Std.Array Std.U8 16#usize) 11#usize) :
    forsAuthPathAt seed sk ht tree leaf 0 0 path := by
  intro k hk hr
  unfold forsAuthReady at hr
  omega

theorem fors_auth_path_final (seed sk : Std.Array Std.U8 32#usize) (ht tree : Std.U32)
    (leaf : Nat) (path : Std.Array (Std.Array Std.U8 16#usize) 11#usize)
    (hleaf : leaf < 2048)
    (hp : forsAuthPathAt seed sk ht tree leaf 2048 0 path) :
    ∀ k, k < 11 → path.val[k]! = forsRootNode seed sk ht tree k (forsAuthSibling leaf k) := by
  intro k hk
  apply hp k hk
  left
  have hleafs := fors_auth_leaf_schedule ⟨leaf, hleaf⟩ ⟨k, hk⟩
  exact hleafs.2.2.1

end Extracted.Equiv

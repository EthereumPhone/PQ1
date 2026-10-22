/- Shared first-hit selectors. Zero means exhaustion, and a positive slot is
   the first accepted zero-based index plus one. These are finite list laws;
   constructing a digest schedule does not perform extra oracle queries. -/
import Aeneas
import Extracted.C10Representation

namespace Extracted.C10FirstHit
open C10Representation

def firstSlot {α : Type} (p : α → Prop) [DecidablePred p] (xs : List α) : Nat :=
  xs.foldr (fun x slot => if p x then 1 else if slot = 0 then 0 else slot + 1) 0

theorem firstSlot_nil {α : Type} (p : α → Prop) [DecidablePred p] :
    firstSlot p [] = 0 := rfl

theorem firstSlot_cons {α : Type} (p : α → Prop) [DecidablePred p]
    (x : α) (xs : List α) :
    firstSlot p (x :: xs) =
      if p x then 1 else if firstSlot p xs = 0 then 0 else firstSlot p xs + 1 := rfl

theorem all_rejected {α : Type} (p : α → Prop) [DecidablePred p]
    (xs : List α) :
    (∀ x ∈ xs, ¬p x) → firstSlot p xs = 0 := by
  induction xs with
  | nil => simp [firstSlot]
  | cons x xs ih =>
    intro h
    have hx : ¬p x := h x (by simp)
    have ht : ∀ y ∈ xs, ¬p y := fun y hy => h y (by simp [hy])
    simp [firstSlot_cons, hx, ih ht]

theorem first_hit {α : Type} (p : α → Prop) [DecidablePred p]
    (pre : List α) (a : α) (post : List α) (ha : p a) :
    (∀ x ∈ pre, ¬p x) → firstSlot p (pre ++ a :: post) = pre.length + 1 := by
  induction pre with
  | nil => simp [firstSlot_cons, ha]
  | cons x xs ih =>
    intro h
    have hx : ¬p x := h x (by simp)
    have ht : ∀ y ∈ xs, ¬p y := fun y hy => h y (by simp [hy])
    simp [firstSlot_cons, hx, ih ht]

theorem firstSlot_le_length {α : Type} (p : α → Prop) [DecidablePred p]
    (xs : List α) : firstSlot p xs ≤ xs.length := by
  induction xs with
  | nil => rfl
  | cons x xs ih =>
    rw [firstSlot_cons, List.length_cons]
    split
    · omega
    · split <;> omega

theorem firstSlot_zero_iff {α : Type} (p : α → Prop) [DecidablePred p]
    (xs : List α) : firstSlot p xs = 0 ↔ ∀ x ∈ xs, ¬p x := by
  induction xs with
  | nil => simp [firstSlot]
  | cons x xs ih =>
    rw [firstSlot_cons]
    by_cases hx : p x
    · simp [hx]
    · simp [hx, ih]

theorem firstSlot_at {α : Type} (p : α → Prop) [DecidablePred p]
    (xs : List α) (i : Nat) (hi : i < xs.length)
    (hp : p (xs[i]))
    (hpre : ∀ j (hj : j < i), ¬p (xs[j]'(Nat.lt_trans hj hi))) :
    firstSlot p xs = i + 1 := by
  induction xs generalizing i with
  | nil => simp at hi
  | cons x xs ih =>
    cases i with
    | zero => simp [firstSlot_cons, show p x from hp]
    | succ i =>
      have hx : ¬p x := hpre 0 (by omega)
      have htail : i < xs.length := by simpa using hi
      have hptail : p (xs[i]) := hp
      have hpretail : ∀ j (hj : j < i), ¬p (xs[j]'(Nat.lt_trans hj htail)) := by
        intro j hj
        exact hpre (j+1) (by omega)
      simp [firstSlot_cons, hx, ih i htail hptail hpretail]

theorem firstSlot_range_hit {α : Type} (p : α → Prop) [DecidablePred p]
    (f : Nat → α) (n i : Nat) (hi : i < n) (hp : p (f i))
    (hpre : ∀ j, j < i → ¬p (f j)) :
    firstSlot p ((List.range n).map f) = i + 1 := by
  apply firstSlot_at p _ i (by simpa using hi)
  · simpa using hp
  · intro j hj
    simpa using hpre j hj

theorem firstSlot_range_exhausted {α : Type} (p : α → Prop) [DecidablePred p]
    (f : Nat → α) (n : Nat) (h : ∀ i, i < n → ¬p (f i)) :
    firstSlot p ((List.range n).map f) = 0 := by
  apply all_rejected
  intro x hx
  obtain ⟨i, hi, rfl⟩ := List.mem_map.mp hx
  exact h i (List.mem_range.mp hi)

theorem wots_first_slot_common (digests : List (List Int)) :
    wots_first_slot digests = firstSlot (fun d => wots_sum d = wots_target) digests := by
  simp only [wots_first_slot, firstSlot, sub_eq_zero]

theorem fors_first_slot_common (digests : List (List Int)) :
    fors_first_slot digests = firstSlot (fun d => fors_zero_field d = 0) digests := rfl

end Extracted.C10FirstHit

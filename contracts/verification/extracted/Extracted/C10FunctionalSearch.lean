/- Actual bounded Rust-extracted searches consume the paired first-hit result.
   The supplied executable SHA model and erased progress callbacks remain the
   existing interpretation boundary. No success/freshness premise is imposed. -/
import Extracted.C10FirstHit
import Extracted.C10AcceptanceBridge

open Aeneas Aeneas.Std Result
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.C10FunctionalSearch
open C10Representation Extracted.C10FirstHit Extracted.C10AcceptanceBridge
open Extracted.Equiv sphincs_c10

def searchCounter (i : Nat) : Std.U32 := ⟨BitVec.ofNat 32 i⟩

theorem searchCounter_val (i : Nat) (hi : i < 4294967296) :
    (searchCounter i).val = i := by
  change i % 4294967296 = i
  exact Nat.mod_eq_of_lt hi

theorem searchCounter_of_val (c : Std.U32) : searchCounter c.val = c := by
  cases c
  simp [searchCounter, UScalar.val]

def digestBytes (d : Std.Array Std.U8 32#usize) : List Int :=
  d.val.map (fun b => Int.ofNat b.val)

noncomputable def wotsSchedule (seed adrs message : Std.Array Std.U8 32#usize)
    (n : Nat) : List (List Int) :=
  (List.range n).map (fun i => digestBytes (wots_digest_pure seed adrs message (searchCounter i)))

noncomputable def forsSchedule (sk seed root message : Std.Array Std.U8 32#usize)
    (opt : Option (Std.Array Std.U8 16#usize)) (n : Nat) : List (List Int) :=
  (List.range n).map (fun i => digestBytes (forsGrindDigest sk seed root message opt (searchCounter i)))

theorem wots_schedule_hit (seed adrs message : Std.Array Std.U8 32#usize)
    (c : Std.U32) (hc : c.val < 10000000)
    (ha : pairedWotsAccept seed adrs message c)
    (hpre : ∀ earlier : Std.U32, earlier.val < c.val →
      ¬pairedWotsAccept seed adrs message earlier) :
    wots_first_slot (wotsSchedule seed adrs message 10000000) = c.val + 1 := by
  rw [wots_first_slot_common]
  unfold wotsSchedule
  apply firstSlot_range_hit (fun d => wots_sum d = wots_target)
    (fun i => digestBytes (wots_digest_pure seed adrs message (searchCounter i))) 10000000 c.val hc
  · rw [searchCounter_of_val]
    exact ha
  · intro j hj
    have hj32 : j < 4294967296 := by omega
    have h := hpre (searchCounter j) (by rw [searchCounter_val j hj32]; exact hj)
    exact h

theorem wots_schedule_exhausted (seed adrs message : Std.Array Std.U8 32#usize)
    (h : ∀ c : Std.U32, c.val < 10000000 → ¬pairedWotsAccept seed adrs message c) :
    wots_first_slot (wotsSchedule seed adrs message 10000000) = 0 := by
  rw [wots_first_slot_common]
  apply firstSlot_range_exhausted
  intro i hi
  exact h (searchCounter i) (by rw [searchCounter_val i (by omega)]; exact hi)

theorem fors_schedule_hit (sk seed root message : Std.Array Std.U8 32#usize)
    (opt : Option (Std.Array Std.U8 16#usize)) (c : Std.U32) (hc : c.val < 10000000)
    (ha : pairedForsAccept sk seed root message opt c)
    (hpre : ∀ earlier : Std.U32, earlier.val < c.val →
      ¬pairedForsAccept sk seed root message opt earlier) :
    fors_first_slot (forsSchedule sk seed root message opt 10000000) = c.val + 1 := by
  rw [fors_first_slot_common]
  unfold forsSchedule
  apply firstSlot_range_hit (fun d => fors_zero_field d = 0)
    (fun i => digestBytes (forsGrindDigest sk seed root message opt (searchCounter i))) 10000000 c.val hc
  · rw [searchCounter_of_val]
    exact ha
  · intro j hj
    have hj32 : j < 4294967296 := by omega
    exact hpre (searchCounter j) (by rw [searchCounter_val j hj32]; exact hj)

theorem fors_schedule_exhausted (sk seed root message : Std.Array Std.U8 32#usize)
    (opt : Option (Std.Array Std.U8 16#usize))
    (h : ∀ c : Std.U32, c.val < 10000000 → ¬pairedForsAccept sk seed root message opt c) :
    fors_first_slot (forsSchedule sk seed root message opt 10000000) = 0 := by
  rw [fors_first_slot_common]
  apply firstSlot_range_exhausted
  intro i hi
  exact h (searchCounter i) (by rw [searchCounter_val i (by omega)]; exact hi)

/-- Actual WOTS outputs, including digits, retain the first shared-selector hit.
    The other branch is the exact exhaustion failure. -/
theorem extracted_wots_first_slot (seed message : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (progress : hypertree.ProgressSink) (pct : Std.U8) :
    (∃ c d digits,
      wots.find_count seed layer tree kp message progress pct = .ok (c, d, digits) ∧
      c.val < 10000000 ∧
      wots_first_slot (wotsSchedule seed (adrsArr layer tree 0 kp.val 0 0 0) message 10000000) = c.val + 1 ∧
      d = wots_digest_pure seed (adrsArr layer tree 0 kp.val 0 0 0) message c ∧
      ∀ j, j < 43 → (digits.val[j]!).val = wotsDigit d j) ∨
    (wots.find_count seed layer tree kp message progress pct = .fail .assertionFailure ∧
      wots_first_slot (wotsSchedule seed (adrsArr layer tree 0 kp.val 0 0 0) message 10000000) = 0) := by
  rcases extracted_wots_search seed message layer tree kp progress pct with h | h
  · obtain ⟨c, d, digits, hr, hc, ha, hpre, hd, hdigits⟩ := h
    exact Or.inl ⟨c, d, digits, hr, hc, wots_schedule_hit _ _ _ c hc ha hpre, hd, hdigits⟩
  · exact Or.inr ⟨h.1, wots_schedule_exhausted _ _ _ h.2⟩

/-- Both OptRand modes preserve their exact randomizer/digest or exhaustion. -/
theorem extracted_fors_first_slot (sk message : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize)) :
    (∃ c : Std.U32, c.val < 10000000 ∧
      fors_first_slot (forsSchedule sk (pad16Pure seed) (pad16Pure root) message opt 10000000) = c.val + 1 ∧
      fors.grind_r sk seed root message opt = .ok
        (forsRandomizer sk message opt c,
          forsGrindDigest sk (pad16Pure seed) (pad16Pure root) message opt c)) ∨
    (fors.grind_r sk seed root message opt = .fail .assertionFailure ∧
      fors_first_slot (forsSchedule sk (pad16Pure seed) (pad16Pure root) message opt 10000000) = 0) := by
  rcases extracted_fors_search sk message seed root opt with h | h
  · obtain ⟨c, hc, ha, hpre, hr⟩ := h
    exact Or.inl ⟨c, hc, fors_schedule_hit _ _ _ _ opt c hc ha hpre, hr⟩
  · exact Or.inr ⟨h.1, fors_schedule_exhausted _ _ _ _ opt h.2⟩

theorem extracted_wots_exhaustion_iff (seed message : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (progress : hypertree.ProgressSink) (pct : Std.U8) :
    wots.find_count seed layer tree kp message progress pct = .fail .assertionFailure ↔
      wots_first_slot (wotsSchedule seed (adrsArr layer tree 0 kp.val 0 0 0) message 10000000) = 0 := by
  rcases extracted_wots_first_slot seed message layer tree kp progress pct with h | h
  · obtain ⟨c, d, digits, hr, _, hs, _, _⟩ := h
    simp [hr, hs]
  · simp [h.1, h.2]

theorem extracted_fors_exhaustion_iff (sk message : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize)) :
    fors.grind_r sk seed root message opt = .fail .assertionFailure ↔
      fors_first_slot (forsSchedule sk (pad16Pure seed) (pad16Pure root) message opt 10000000) = 0 := by
  rcases extracted_fors_first_slot sk message seed root opt with h | h
  · obtain ⟨c, _, hs, hr⟩ := h
    simp [hr, hs]
  · simp [h.1, h.2]

end Extracted.C10FunctionalSearch

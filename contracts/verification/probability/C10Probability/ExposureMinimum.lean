import C10Probability.WotsPrefixComparison

/-! Coordinatewise minimum over every returned word, capped by the public
chain endpoint seven. Empty history stays explicit. The accepted-word
comparison requires uniform words; a minimum of arbitrary accepted words
need not itself have sum 205. -/
namespace C10Probability
noncomputable section

def wotsExposureMinimum (words : List WotsWord) (i : Fin 43) : ℕ :=
  words.foldr (fun word value => min (word i).val value) 7

theorem wots_exposure_minimum_nil (i : Fin 43) : wotsExposureMinimum [] i = 7 := by
  rfl

theorem wots_exposure_minimum_cons (word : WotsWord) (words : List WotsWord) (i : Fin 43) :
    wotsExposureMinimum (word :: words) i = min (word i).val (wotsExposureMinimum words i) := by
  rfl

theorem wots_exposure_minimum_le_endpoint (words : List WotsWord) (i : Fin 43) :
    wotsExposureMinimum words i ≤ 7 := by
  induction words with
  | nil => exact le_refl _
  | cons word words ih => exact (min_le_right _ _).trans ih

theorem wots_exposure_minimum_le_member (words : List WotsWord) (word : WotsWord)
    (member : word ∈ words) (i : Fin 43) : wotsExposureMinimum words i ≤ (word i).val := by
  induction words with
  | nil => cases member
  | cons head tail ih =>
    rcases List.mem_cons.mp member with same | later
    · subst word
      exact min_le_left _ _
    · exact (min_le_right _ _).trans (ih later)

theorem wots_exposure_minimum_uniform (words : List WotsWord) (word : WotsWord)
    (nonempty : words ≠ []) (uniform : ∀ other ∈ words, other = word) (i : Fin 43) :
    wotsExposureMinimum words i = (word i).val := by
  induction words with
  | nil => exact False.elim (nonempty rfl)
  | cons head tail ih =>
    rw [wots_exposure_minimum_cons, uniform head (List.mem_cons_self ..)]
    by_cases empty : tail = []
    · subst tail
      apply min_eq_left
      have bound := (word i).isLt
      exact Nat.le_of_lt_succ bound
    · rw [ih empty (fun other member => uniform other (List.mem_cons_of_mem head member))]
      exact min_self _

theorem wots_below_exposure_minimum_iff (words : List WotsWord) (i : Fin 43) (position : ℕ) :
    position < wotsExposureMinimum words i ↔
      position < 7 ∧ ∀ word ∈ words, position < (word i).val := by
  induction words with
  | nil => simp only [wots_exposure_minimum_nil, List.not_mem_nil, false_implies, forall_const, and_true]
  | cons word words ih =>
    rw [wots_exposure_minimum_cons, lt_min_iff, ih]
    simp only [List.forall_mem_cons]
    tauto

theorem wots_accepted_exposure_comparison (words : List WotsWord) (word : WotsWord)
    (accepted : wotsAccept word = true)
    (priorAccepted : ∀ prior ∈ words, wotsAccept prior = true)
    (uniform : ∀ first ∈ words, ∀ second ∈ words, first = second) :
    (∃ prior ∈ words, word = prior) ∨ ∃ i, (word i).val < wotsExposureMinimum words i := by
  cases words with
  | nil => exact Or.inr (wots_accepted_word_proper_cut word accepted)
  | cons prior rest =>
    have present : prior ∈ prior :: rest := List.mem_cons_self
    rcases wots_accepted_word_eq_or_lower word prior accepted (priorAccepted prior present) with same | lower
    · exact Or.inl ⟨prior, present, same⟩
    · obtain ⟨i, hi⟩ := lower
      refine Or.inr ⟨i, ?_⟩
      rw [wots_exposure_minimum_uniform (prior :: rest) prior (by simp)
        (fun other member => uniform other member prior present) i]
      exact hi

end
end C10Probability

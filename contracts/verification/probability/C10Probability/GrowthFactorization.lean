import C10Probability.GrowthWords
import Mathlib.Data.Fin.Tuple.Embedding

/-! Every finite coordinate-to-witness map factors through a restricted-growth
word and an injective witness tuple. Labels are assigned on first occurrence
when reading coordinates from right to left. -/
namespace C10Probability
noncomputable section

theorem growth_assignment_factorization {A : Type*} (n : ℕ) (assignment : Fin n → A) :
    ∃ j, ∃ word : GrowthWord n j, ∃ positions : Fin j ↪ A,
      ∀ i, assignment i = positions (growthAssignment word i) := by
  classical
  induction n with
  | zero =>
    refine ⟨0, growthEmpty, ⟨Fin.elim0, fun i => Fin.elim0 i⟩, ?_⟩
    intro i
    exact Fin.elim0 i
  | succ n ih =>
    obtain ⟨j, word, positions, agrees⟩ := ih (fun i => assignment i.succ)
    by_cases repeated : assignment 0 ∈ Set.range positions
    · obtain ⟨label, same⟩ := repeated
      refine ⟨j, growthReuse label word, positions, ?_⟩
      intro i
      rw [growth_reuse_assignment]
      refine Fin.cases ?_ (fun k => ?_) i
      · exact same.symm
      · exact agrees k
    · refine ⟨j + 1, growthNew word, Fin.Embedding.snoc positions repeated, ?_⟩
      intro i
      rw [growth_new_assignment]
      refine Fin.cases ?_ (fun k => ?_) i
      · exact (Fin.Embedding.snoc_last).symm
      · change assignment k.succ =
          (Fin.Embedding.snoc positions repeated) (growthAssignment word k).castSucc
        rw [Fin.Embedding.snoc_castSucc]
        exact agrees k

theorem growth_nonempty_factorization {A : Type*} {n : ℕ} (nonempty : 0 < n)
    (assignment : Fin n → A) :
    ∃ j, 0 < j ∧ j ≤ n ∧ ∃ word : GrowthWord n j, ∃ positions : Fin j ↪ A,
      ∀ i, assignment i = positions (growthAssignment word i) := by
  obtain ⟨j, word, positions, agrees⟩ := growth_assignment_factorization n assignment
  exact ⟨j, growth_word_positive word nonempty, growth_word_width_le word,
    word, positions, agrees⟩

end
end C10Probability

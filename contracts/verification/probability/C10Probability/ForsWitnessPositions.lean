import C10Probability.ForsSelectedWitness
import Mathlib.Data.Fin.Tuple.Embedding
import Mathlib.Data.Fintype.CardEmbedding

/-! Ordered distinct witness positions, all excluding the target. Their exact
number is the falling factorial (n-1)_j, including impossible and empty cases. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

abbrev ForsOtherPosition {n : ℕ} (target : Fin n) := {i : Fin n // i ≠ target}

def forsOtherEmbedding {n j : ℕ} {target : Fin n}
    (positions : Fin j ↪ ForsOtherPosition target) : Fin j ↪ Fin n :=
  positions.trans (Function.Embedding.subtype (fun i => i ≠ target))

def forsWitnessSelection {n j : ℕ} {target : Fin n}
    (positions : Fin j ↪ ForsOtherPosition target) : Fin (j + 1) ↪ Fin n :=
  Fin.Embedding.cons (forsOtherEmbedding positions) (by
    rintro ⟨group, same⟩
    exact (positions group).property same)

theorem fors_other_positions_card {n : ℕ} (target : Fin n) :
    Fintype.card (ForsOtherPosition target) = n - 1 := by
  simp [ForsOtherPosition, Fintype.card_subtype_compl]

theorem fors_witness_positions_card {n : ℕ} (target : Fin n) (j : ℕ) :
    Fintype.card (Fin j ↪ ForsOtherPosition target) = (n - 1).descFactorial j := by
  rw [Fintype.card_embedding_eq, fors_other_positions_card, Fintype.card_fin]

theorem fors_witness_selection_zero {n j : ℕ} {target : Fin n}
    (positions : Fin j ↪ ForsOtherPosition target) : forsWitnessSelection positions 0 = target := by
  rfl

theorem fors_witness_selection_succ {n j : ℕ} {target : Fin n}
    (positions : Fin j ↪ ForsOtherPosition target) (group : Fin j) :
    forsWitnessSelection positions group.succ = (positions group).val := by
  rfl

theorem distinct_fors_assignment_mass {n j : ℕ} (target : Fin n)
    (positions : Fin j ↪ ForsOtherPosition target) (assignment : Fin 12 → Fin j) :
    (acceptedForsSamples n).toOuterMeasure {samples | ∀ group,
      samples (positions group).val ∈ forsGroupEvent assignment group (samples target)} =
      ((2 : ℝ≥0∞) ^ (132 + 18 * j))⁻¹ := by
  have h := selected_fors_assignment_mass assignment (forsWitnessSelection positions)
    (forsWitnessSelection positions).injective
  simpa only [fors_witness_selection_zero, fors_witness_selection_succ] using h

end
end C10Probability

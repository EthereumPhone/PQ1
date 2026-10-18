import C10Probability.ForsSelectedWitness
import C10Probability.ForsAcceptedSearch

/-! Finite boundary witnesses for the fixed-sample laws. Reusing a position
is deliberately distinguished from selecting independent witnesses. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def splitForsAssignment (i : Fin 12) : Fin 2 := if i.val < 6 then 0 else 1

def permutedForsSelection : Fin 3 → Fin 3 := ![1, 2, 0]

theorem fors_empty_samples_mass :
    (acceptedForsSamples 0).toOuterMeasure {samples | ∀ i : Fin 0, samples i = 0} = 1 := by
  simpa using accepted_fors_samples_event 0 (fun _ => ({0} : Set Digest))

theorem fors_zero_budget_mass (event : Digest → Bool) :
    (returnedMass digestDraw (forsAccept ∘ forsOfDigest) event 0).toReal = 0 := by
  rw [returned_fors_event_real]
  simp

theorem fors_single_witness_mass (target : Digest) :
    (acceptedForsSamples 1).toOuterMeasure {samples | ∀ group,
      samples group ∈ forsGroupEvent (fun _ => (0 : Fin 1)) group target} =
      ((2 : ℝ≥0∞) ^ 150)⁻¹ := by
  exact fixed_fors_assignment_mass (fun _ => (0 : Fin 1)) target

theorem fors_split_witness_mass (target : Digest) :
    (acceptedForsSamples 2).toOuterMeasure {samples | ∀ group,
      samples group ∈ forsGroupEvent splitForsAssignment group target} =
      ((2 : ℝ≥0∞) ^ 168)⁻¹ := by
  exact fixed_fors_assignment_mass splitForsAssignment target

theorem fors_unused_group_joint_mass (target : Digest) :
    (acceptedForsSamples 2).toOuterMeasure {samples | ∀ group,
      samples group ∈ forsGroupEvent (fun _ => (0 : Fin 2)) group target} =
      ((2 : ℝ≥0∞) ^ 168)⁻¹ := by
  exact fixed_fors_assignment_mass (fun _ => (0 : Fin 2)) target

theorem fors_unused_group_address_mass (target : Digest) :
    acceptedForsDraw.toOuterMeasure
      (forsGroupEvent (fun _ => (0 : Fin 2)) 1 target) = ((2 : ℝ≥0∞) ^ 18)⁻¹ := by
  rw [accepted_fors_group_mass]
  norm_num [forsGroupMass]

theorem fors_reused_position_mass :
    (acceptedForsSamples 1).toOuterMeasure {samples | ∀ group : Fin 1,
      samples 0 ∈ forsGroupEvent (fun _ => (0 : Fin 1)) group (samples 0)} = 1 := by
  apply (PMF.toOuterMeasure_apply_eq_one_iff _ _).2
  intro samples _ group
  rw [fors_group_event_coordinates]
  exact ⟨rfl, fun _ _ => rfl⟩

theorem fors_address_separates_same_indices :
    (∀ i : Fin 12, forestIndex (2 ^ 143) i.val = forestIndex 0 i.val) ∧
      (2 ^ 143 : Digest) ∉ forsGroupEvent (fun _ => (0 : Fin 1)) 0 0 := by
  constructor
  · decide +kernel
  · rw [fors_group_event_coordinates]
    have address : hypertreeIndex (2 ^ 143) = 1 := by decide +kernel
    rw [address]
    norm_num [hypertreeIndex]

theorem fors_rejected_guard_atom : acceptedForsDraw (2 ^ 132) = 0 := by
  rw [accepted_fors_atom]
  have rejected : forsAccept (forsOfDigest (2 ^ 132)) = false := by decide +kernel
  simp [rejected]

theorem fors_permuted_selection_mass :
    (acceptedForsSamples 3).toOuterMeasure {samples | ∀ group,
      samples (permutedForsSelection group.succ) ∈
        forsGroupEvent splitForsAssignment group (samples (permutedForsSelection 0))} =
      ((2 : ℝ≥0∞) ^ 168)⁻¹ := by
  exact selected_fors_assignment_mass splitForsAssignment permutedForsSelection (by decide +kernel)

theorem fors_unused_high_bit_preserved :
    (0 : Digest) ≠ 2 ^ 161 ∧ forsCoordinates 0 = forsCoordinates (2 ^ 161) ∧
      forsAccept (forsOfDigest (2 ^ 161)) = true := by
  decide +kernel

end
end C10Probability

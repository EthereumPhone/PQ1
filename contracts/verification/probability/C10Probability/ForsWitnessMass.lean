import C10Probability.ForsAssignment

/-! Joint witness probabilities under finite independent accepted sampling.
The target is fixed before the witnesses, or sampled independently of them. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def acceptedForsSamples (n : ℕ) : PMF (Fin n → Digest) :=
  (PMF.uniformOfFintype (Fin n → AcceptedForsDigest)).map
    (fun samples i => (samples i).val)

theorem accepted_fors_samples_event (n : ℕ) (events : Fin n → Set Digest) :
    (acceptedForsSamples n).toOuterMeasure {samples | ∀ i, samples i ∈ events i} =
      ∏ i, acceptedForsDraw.toOuterMeasure (events i) := by
  rw [acceptedForsSamples, PMF.toOuterMeasure_map_apply]
  change (PMF.uniformOfFintype (Fin n → AcceptedForsDigest)).toOuterMeasure
    {samples | ∀ i, (samples i).val ∈ events i} = _
  have productLaw := uniform_samples_event (fun i => {d : AcceptedForsDigest | d.val ∈ events i})
  simp only [Set.mem_setOf_eq] at productLaw
  rw [productLaw]
  apply Finset.prod_congr rfl
  intro i _
  rw [acceptedForsDraw, PMF.toOuterMeasure_map_apply]
  rfl

theorem fixed_fors_assignment_mass {j : ℕ} (assignment : Fin 12 → Fin j) (target : Digest) :
    (acceptedForsSamples j).toOuterMeasure
      {samples | ∀ group, samples group ∈ forsGroupEvent assignment group target} =
      ((2 : ℝ≥0∞) ^ (132 + 18 * j))⁻¹ := by
  rw [accepted_fors_samples_event]
  simp_rw [accepted_fors_group_mass]
  exact fors_assignment_product_mass assignment

def targetForsWitnessSamples (target : PMF Digest) (j : ℕ) :
    PMF (Digest × (Fin j → Digest)) :=
  target.bind fun d => (acceptedForsSamples j).map fun samples => (d, samples)

theorem independent_target_fors_assignment_mass {j : ℕ}
    (assignment : Fin 12 → Fin j) (target : PMF Digest) :
    (targetForsWitnessSamples target j).toOuterMeasure
      {out | ∀ group, out.2 group ∈ forsGroupEvent assignment group out.1} =
      ((2 : ℝ≥0∞) ^ (132 + 18 * j))⁻¹ := by
  rw [targetForsWitnessSamples, PMF.toOuterMeasure_bind_apply]
  simp_rw [PMF.toOuterMeasure_map_apply]
  change (∑' d, target d * (acceptedForsSamples j).toOuterMeasure
    {samples | ∀ group, samples group ∈ forsGroupEvent assignment group d}) = _
  simp_rw [fixed_fors_assignment_mass]
  rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]

end
end C10Probability

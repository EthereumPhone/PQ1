import C10Probability.ForsWitnessMass
import C10Probability.UniformSelection

/-! A target and its witnesses selected at distinct positions of a larger
independent accepted pool. Neither values nor positions are postselected. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def sampleHeadTailEquiv (n : ℕ) (A : Type*) : (Fin (n + 1) → A) ≃ A × (Fin n → A) where
  toFun samples := (samples 0, fun i => samples i.succ)
  invFun pair := Fin.cases pair.1 pair.2
  left_inv samples := by
    funext i
    exact Fin.cases rfl (fun _ => rfl) i
  right_inv pair := by
    cases pair
    rfl

theorem uniform_samples_head_tail (n : ℕ) (A : Type*) [Fintype A] [Nonempty A] :
    (PMF.uniformOfFintype (Fin (n + 1) → A)).map
      (fun samples => (samples 0, fun i : Fin n => samples i.succ)) =
      (PMF.uniformOfFintype A).bind fun head =>
        (PMF.uniformOfFintype (Fin n → A)).map fun tail => (head, tail) := by
  exact (uniform_map_equiv (sampleHeadTailEquiv n A)).trans uniform_product_bind

theorem accepted_fors_samples_selection {m n : ℕ} (select : Fin m → Fin n)
    (distinct : Function.Injective select) :
    (acceptedForsSamples n).map (fun samples i => samples (select i)) =
      acceptedForsSamples m := by
  have h := congrArg (PMF.map (fun samples : Fin m → AcceptedForsDigest =>
    fun i => (samples i).val))
    (uniform_samples_selection (A := AcceptedForsDigest) select distinct)
  simpa only [acceptedForsSamples, PMF.map_comp, Function.comp_def] using h

theorem accepted_fors_samples_head_tail (n : ℕ) :
    (acceptedForsSamples (n + 1)).map
      (fun samples => (samples 0, fun i : Fin n => samples i.succ)) =
      targetForsWitnessSamples acceptedForsDraw n := by
  have h := congrArg (PMF.map (fun pair : AcceptedForsDigest × (Fin n → AcceptedForsDigest) =>
    (pair.1.val, fun i => (pair.2 i).val)))
    (uniform_samples_head_tail n AcceptedForsDigest)
  simpa only [acceptedForsSamples, acceptedForsDraw, targetForsWitnessSamples,
    PMF.map_comp, PMF.map_bind, PMF.bind_map, Function.comp_def] using h

theorem ordered_fors_assignment_mass {j : ℕ} (assignment : Fin 12 → Fin j) :
    (acceptedForsSamples (j + 1)).toOuterMeasure
      {samples | ∀ group, samples group.succ ∈ forsGroupEvent assignment group (samples 0)} =
      ((2 : ℝ≥0∞) ^ (132 + 18 * j))⁻¹ := by
  have h := congrArg (fun p : PMF (Digest × (Fin j → Digest)) =>
    p.toOuterMeasure {out | ∀ group, out.2 group ∈ forsGroupEvent assignment group out.1})
    (accepted_fors_samples_head_tail j)
  dsimp only at h
  rw [PMF.toOuterMeasure_map_apply, independent_target_fors_assignment_mass] at h
  exact h

theorem selected_fors_assignment_mass {j n : ℕ} (assignment : Fin 12 → Fin j)
    (select : Fin (j + 1) → Fin n) (distinct : Function.Injective select) :
    (acceptedForsSamples n).toOuterMeasure {samples | ∀ group,
      samples (select group.succ) ∈ forsGroupEvent assignment group (samples (select 0))} =
      ((2 : ℝ≥0∞) ^ (132 + 18 * j))⁻¹ := by
  have h := congrArg (fun p : PMF (Fin (j + 1) → Digest) =>
    p.toOuterMeasure {samples | ∀ group,
      samples group.succ ∈ forsGroupEvent assignment group (samples 0)})
    (accepted_fors_samples_selection select distinct)
  dsimp only at h
  rw [PMF.toOuterMeasure_map_apply, ordered_fors_assignment_mass] at h
  exact h

end
end C10Probability

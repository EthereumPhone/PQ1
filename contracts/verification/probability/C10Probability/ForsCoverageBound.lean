import C10Probability.ForsPoolCoverage

/-! Exact canonical-witness counts give an upper bound on the union of pool
coverage events. The union may overlap; its probability is not asserted equal
to the sum. Adaptive selection is handled by this union and prefix domination. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

abbrev ForsWitnessCode (n j : ℕ) :=
  Σ target : Fin n, GrowthWord 12 j × (Fin j ↪ ForsOtherPosition target)

def forsWitnessEvent {n j : ℕ} (code : ForsWitnessCode n j) : Set (Fin n → Digest) :=
  {samples | ∀ group, samples (code.2.2 group).val ∈
    forsGroupEvent (growthAssignment code.2.1) group (samples code.1)}

def forsCoverageCharge (n : ℕ) : ℝ≥0∞ :=
  ∑ j ∈ Finset.Icc 1 12,
    (n : ℝ≥0∞) * ((n - 1).descFactorial j : ℝ≥0∞) * (Nat.stirlingSecond 12 j : ℝ≥0∞) *
      ((2 : ℝ≥0∞) ^ (132 + 18 * j))⁻¹

theorem fors_witness_code_card (n j : ℕ) :
    Fintype.card (ForsWitnessCode n j) =
      n * Nat.stirlingSecond 12 j * (n - 1).descFactorial j := by
  rw [Fintype.card_sigma]
  simp_rw [Fintype.card_prod, growth_word_card, fors_witness_positions_card]
  simp [Nat.mul_assoc]

theorem fors_coverage_by_codes {n j : ℕ} (samples : Fin n → Digest) :
    ForsCoverageByGroups samples j ↔ ∃ code : ForsWitnessCode n j, samples ∈ forsWitnessEvent code := by
  constructor
  · rintro ⟨target, word, positions, groups⟩
    exact ⟨⟨target, word, positions⟩, groups⟩
  · rintro ⟨⟨target, word, positions⟩, groups⟩
    exact ⟨target, word, positions, groups⟩

theorem fors_witness_event_mass {n j : ℕ} (code : ForsWitnessCode n j) :
    (acceptedForsSamples n).toOuterMeasure (forsWitnessEvent code) =
      ((2 : ℝ≥0∞) ^ (132 + 18 * j))⁻¹ := by
  exact distinct_fors_assignment_mass code.1 code.2.2 (growthAssignment code.2.1)

theorem fors_coverage_group_bound (n j : ℕ) :
    (acceptedForsSamples n).toOuterMeasure {samples | ForsCoverageByGroups samples j} ≤
      (n : ℝ≥0∞) * ((n - 1).descFactorial j : ℝ≥0∞) * (Nat.stirlingSecond 12 j : ℝ≥0∞) *
        ((2 : ℝ≥0∞) ^ (132 + 18 * j))⁻¹ := by
  classical
  have union : {samples | ForsCoverageByGroups samples j} =
      ⋃ code : ForsWitnessCode n j, forsWitnessEvent code := by
    ext samples
    simpa only [Set.mem_setOf_eq, Set.mem_iUnion] using fors_coverage_by_codes samples
  rw [union]
  calc
    _ ≤ ∑ code : ForsWitnessCode n j,
        (acceptedForsSamples n).toOuterMeasure (forsWitnessEvent code) :=
      MeasureTheory.measure_iUnion_fintype_le _ _
    _ = (Fintype.card (ForsWitnessCode n j) : ℝ≥0∞) *
        ((2 : ℝ≥0∞) ^ (132 + 18 * j))⁻¹ := by
      simp_rw [fors_witness_event_mass]
      simp [nsmul_eq_mul]
    _ = _ := by
      rw [fors_witness_code_card]
      push_cast
      ring

theorem iid_fors_coverage_bound (n : ℕ) :
    (acceptedForsSamples n).toOuterMeasure {samples | ForsPoolCoverage samples} ≤
      forsCoverageCharge n := by
  classical
  have included : {samples : Fin n → Digest | ForsPoolCoverage samples} ⊆
      ⋃ j ∈ Finset.Icc 1 12, {samples | ForsCoverageByGroups samples j} := by
    intro samples covered
    obtain ⟨j, positive, bounded, groups⟩ := (fors_pool_coverage_canonical samples).mp covered
    simp only [Set.mem_iUnion, Set.mem_setOf_eq]
    exact ⟨j, Finset.mem_Icc.mpr ⟨positive, bounded⟩, groups⟩
  calc
    _ ≤ (acceptedForsSamples n).toOuterMeasure
        (⋃ j ∈ Finset.Icc 1 12, {samples | ForsCoverageByGroups samples j}) :=
      MeasureTheory.measure_mono included
    _ ≤ ∑ j ∈ Finset.Icc 1 12,
        (acceptedForsSamples n).toOuterMeasure {samples | ForsCoverageByGroups samples j} :=
      MeasureTheory.measure_biUnion_finset_le _ _
    _ ≤ _ := by
      apply Finset.sum_le_sum
      intro j _
      exact fors_coverage_group_bound n j

theorem adaptive_fors_coverage_bound {R : Type*} {work : ℕ}
    (client : PMF (SampleProgram Digest R work)) (cap : ℕ) :
    (randomizedSampleProgram acceptedForsDraw client).toOuterMeasure
      {out | out.2.length ≤ cap ∧ ForsListCoverage out.2} ≤ forsCoverageCharge cap := by
  have transfer := accepted_fors_program_prefix_bound client cap ForsListCoverage
    fors_list_coverage_extension
  simp_rw [fors_list_coverage_ofFn] at transfer
  exact transfer.trans (iid_fors_coverage_bound cap)

theorem fors_coverage_charge_ne_top (n : ℕ) : forsCoverageCharge n ≠ ⊤ := by
  apply ENNReal.sum_ne_top.mpr
  intro j _
  apply ENNReal.mul_ne_top
  · exact ENNReal.mul_ne_top (ENNReal.mul_ne_top (by simp) (by simp)) (by simp)
  · simp

theorem iid_fors_coverage_bound_real (n : ℕ) :
    ((acceptedForsSamples n).toOuterMeasure {samples | ForsPoolCoverage samples}).toReal ≤
      (forsCoverageCharge n).toReal := by
  exact ENNReal.toReal_mono (fors_coverage_charge_ne_top n) (iid_fors_coverage_bound n)

theorem adaptive_fors_coverage_bound_real {R : Type*} {work : ℕ}
    (client : PMF (SampleProgram Digest R work)) (cap : ℕ) :
    ((randomizedSampleProgram acceptedForsDraw client).toOuterMeasure
      {out | out.2.length ≤ cap ∧ ForsListCoverage out.2}).toReal ≤
        (forsCoverageCharge cap).toReal := by
  exact ENNReal.toReal_mono (fors_coverage_charge_ne_top cap)
    (adaptive_fors_coverage_bound client cap)

end
end C10Probability

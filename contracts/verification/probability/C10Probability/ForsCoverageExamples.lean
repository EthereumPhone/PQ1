import C10Probability.ForsCoverageBound

/-! Finite checks of the canonical count, pool coverage and numerical charge. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def mixedForsPool : Fin 3 → Digest :=
  ![0, ∑ i : Fin 6, (2 : Digest) ^ (11 * i.val),
    ∑ i : Fin 6, (2 : Digest) ^ (11 * (i.val + 6))]

theorem growth_three_two_count : Fintype.card (GrowthWord 3 2) = 3 := by
  rw [growth_word_card]
  decide +kernel

theorem growth_twelve_two_count : Fintype.card (GrowthWord 12 2) = 2047 := by
  rw [growth_word_card]
  decide +kernel

theorem fors_two_positions_count : Fintype.card (Fin 2 ↪ ForsOtherPosition (0 : Fin 3)) = 2 := by
  rw [fors_witness_positions_card]
  decide +kernel

theorem fors_insufficient_positions_count :
    Fintype.card (Fin 3 ↪ ForsOtherPosition (0 : Fin 3)) = 0 := by
  rw [fors_witness_positions_card]
  decide +kernel

theorem fors_empty_pool_uncovered (samples : Fin 0 → Digest) : ¬ ForsPoolCoverage samples := by
  rintro ⟨target, _⟩
  exact Fin.elim0 target

theorem fors_singleton_pool_uncovered (samples : Fin 1 → Digest) : ¬ ForsPoolCoverage samples := by
  rintro ⟨target, covered⟩
  obtain ⟨position, different, _⟩ := covered 0
  exact different (Subsingleton.elim position target)

theorem fors_two_equal_samples_covered (digest : Digest) :
    ForsPoolCoverage (fun _ : Fin 2 => digest) := by
  refine ⟨0, fun _ => ⟨1, ?_, rfl, rfl⟩⟩
  decide +kernel

theorem fors_mixed_pool_covered :
    ForsPoolCoverage mixedForsPool ∧
      ∀ position : Fin 2, ¬ (∀ coordinate : Fin 12,
        forestIndex (mixedForsPool position.succ) coordinate.val = forestIndex 0 coordinate.val) := by
  unfold ForsPoolCoverage
  decide +kernel

theorem fors_zero_pool_charge : forsCoverageCharge 0 = 0 := by
  simp [forsCoverageCharge]

theorem fors_singleton_pool_charge : forsCoverageCharge 1 = 0 := by
  apply Finset.sum_eq_zero
  intro j hj
  have positive : 0 < j := (Finset.mem_Icc.mp hj).1
  obtain ⟨k, rfl⟩ := Nat.exists_eq_succ_of_ne_zero (Nat.ne_of_gt positive)
  simp [Nat.descFactorial]

theorem fors_two_pool_charge : forsCoverageCharge 2 = ((2 : ℝ≥0∞) ^ 149)⁻¹ := by
  have h : forsCoverageCharge 2 = (2 : ℝ≥0∞) * ((2 : ℝ≥0∞) ^ 150)⁻¹ := by
    norm_num [forsCoverageCharge, Finset.sum_Icc_succ_top, Nat.descFactorial, Nat.stirlingSecond]
  rw [h, show (2 : ℝ≥0∞) ^ 150 = 2 ^ 149 * 2 by rw [pow_succ],
    ENNReal.mul_inv (Or.inl (by norm_num)) (Or.inl (by norm_num)), mul_left_comm,
    ENNReal.mul_inv_cancel (by norm_num) (by norm_num), mul_one]

end
end C10Probability

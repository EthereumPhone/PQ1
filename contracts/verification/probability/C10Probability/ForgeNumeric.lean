import C10Probability.ForgeArithmetic

/-! Kernel arithmetic for the conservative composed bound. These budgets
instantiate the finite ideal model, not a concrete implementation security level. -/
namespace C10Probability
open scoped ENNReal
noncomputable section
set_option exponentiation.threshold 512

def forgeExampleConfig : C10SessionConfig :=
  ⟨List.replicate 32 0, nodeBlock 1, signingBudget, signingBudget, by decide, by decide⟩

theorem forge_example_costs :
    sessionSignCost forgeExampleConfig = 40435044 ∧
    sessionSignSelected forgeExampleConfig = 10435042 ∧
    sessionSignPublic forgeExampleConfig = 30364290 := by decide +kernel

theorem forge_coverage_singleton : forsCoverageCharge 1 = 0 := by
  norm_num [forsCoverageCharge, Finset.sum_Icc_succ_top, Nat.descFactorial, Nat.stirlingSecond]

theorem forge_example_charge_small :
    sharedForgeCharge forgeExampleConfig (2 ^ 20) 65536 < (1 : ℝ≥0∞) / 2 ^ 50 := by
  apply (ENNReal.toReal_lt_toReal (shared_forge_charge_ne_top _ _ _)
    (ENNReal.div_ne_top (by finiteness) (by simp))).mp
  rw [shared_forge_charge_real, independent_forge_charge_real, fors_coverage_charge_real]
  norm_num [
    sessionGameSelected, sessionGameRaw, sessionGamePublic, sessionSignSelected,
    sessionSignCost, sessionSignPublic, forgeExampleConfig, signingBudget,
    Finset.sum_Icc_succ_top, Nat.descFactorial, Nat.stirlingSecond,
    Nat.choose_two_right, ENNReal.toReal_div,
    ENNReal.toReal_pow, ENNReal.toReal_inv]

theorem c10_shared_forge_example_small {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) :
    (c10InitializedShared forgeExampleConfig sampler (2 ^ 20) 65536).toOuterMeasure {true} <
      (1 : ℝ≥0∞) / 2 ^ 50 := by
  exact (c10_shared_forge_bound forgeExampleConfig sampler (2 ^ 20) 65536).trans_lt
    forge_example_charge_small

theorem forge_example_charge_medium :
    sharedForgeCharge forgeExampleConfig (2 ^ 24) 65536 < (1 : ℝ≥0∞) / 2 ^ 34 := by
  apply (ENNReal.toReal_lt_toReal (shared_forge_charge_ne_top _ _ _)
    (ENNReal.div_ne_top (by finiteness) (by simp))).mp
  rw [shared_forge_charge_real, independent_forge_charge_real, fors_coverage_charge_real]
  norm_num [sessionGameSelected, sessionGameRaw, sessionGamePublic, sessionSignSelected,
    sessionSignCost, sessionSignPublic, forgeExampleConfig, signingBudget,
    Finset.sum_Icc_succ_top, Nat.descFactorial, Nat.stirlingSecond,
    Nat.choose_two_right, ENNReal.toReal_div, ENNReal.toReal_pow]

theorem c10_shared_forge_example_medium {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) :
    (c10InitializedShared forgeExampleConfig sampler (2 ^ 24) 65536).toOuterMeasure {true} <
      (1 : ℝ≥0∞) / 2 ^ 34 := by
  exact (c10_shared_forge_bound forgeExampleConfig sampler (2 ^ 24) 65536).trans_lt
    forge_example_charge_medium

theorem forge_large_coverage_exceeds_one :
    (1 : ℝ≥0∞) < forsCoverageCharge ((2 ^ 32) + 65536 + 1) := by
  apply (ENNReal.toReal_lt_toReal (show (1 : ℝ≥0∞) ≠ ⊤ by simp)
    (fors_coverage_charge_ne_top _)).mp
  rw [fors_coverage_charge_real]
  norm_num [Finset.sum_Icc_succ_top, Nat.descFactorial, Nat.stirlingSecond]

theorem forge_large_charge_exceeds_one (cfg : C10SessionConfig) :
    (1 : ℝ≥0∞) < sharedForgeCharge cfg (2 ^ 32) 65536 := by
  apply forge_large_coverage_exceeds_one.trans_le
  unfold sharedForgeCharge independentForgeCharge
  exact le_add_right (le_add_left (le_add_left (le_add_left (le_add_left (le_add_left le_rfl)))))

theorem forge_large_capped_charge_one (cfg : C10SessionConfig) :
    min 1 (sharedForgeCharge cfg (2 ^ 32) 65536) = 1 := by
  exact min_eq_left (forge_large_charge_exceeds_one cfg).le

end
end C10Probability

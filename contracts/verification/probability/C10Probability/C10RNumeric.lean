import C10Probability.C10RReal
import C10Probability.RSessionNumeric

/-! A conservative numerical R-only bound at the modeled ten-million-trial
budgets and finite quotas. Actual keygen supplies seed/root; empty placeholders
in this configuration are overwritten before the client begins. -/
namespace C10Probability
noncomputable section

def c10RSigningConfig : C10SessionConfig :=
  ⟨[], [], signingBudget, signingBudget, signing_counter_fits, signing_counter_fits⟩

theorem c10_r_charge_of_tail_bound (cfg : C10SessionConfig) (qr qs : ℕ)
    (tail : ℝ) (bounded : (1 - (1 : ℝ) / 2048) ^ cfg.rTrials ≤ tail) :
    c10RChargeReal cfg qr qs ≤
      (qs : ℝ) * (tail + (collisionPairs (c10RHistoryCap cfg qr qs) cfg.rTrials : ℝ) / 2 ^ 128) +
        (c10RPublicCalls cfg qr qs : ℝ) / 2 ^ 256 := by
  exact add_le_add (mul_le_mul_of_nonneg_left
    (add_le_add bounded le_rfl) (Nat.cast_nonneg qs)) le_rfl

theorem c10_r_charge_quota_bound :
    c10RChargeReal c10RSigningConfig (2 ^ 32) (2 ^ 20) ≤ (2 : ℝ)⁻¹ ^ 39 := by
  apply (c10_r_charge_of_tail_bound c10RSigningConfig (2 ^ 32) (2 ^ 20)
    ((2 : ℝ)⁻¹ ^ 64) r_signing_geometric_bound).trans
  simp only [c10RSigningConfig]
  rw [collision_pairs_formula]
  norm_num [c10RHistoryCap, c10RPublicCalls, sessionSignPublic, signingBudget]

theorem c10_r_signing_concrete_exhaustion (publicSeed : Digest) {fuel : ℕ}
    (adversaries : PMF (C10Adversary fuel)) :
    (((c10RShared c10RSigningConfig publicSeed adversaries (2 ^ 32) (2 ^ 20)).map
      c10RFailure) true).toReal ≤ (2 : ℝ)⁻¹ ^ 39 := by
  exact (c10_r_shared_exhaustion_real c10RSigningConfig publicSeed adversaries _ _).trans
    c10_r_charge_quota_bound

end
end C10Probability

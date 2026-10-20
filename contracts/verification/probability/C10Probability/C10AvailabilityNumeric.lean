import C10Probability.C10AvailabilityReal
import C10Probability.C10RNumeric
import C10Probability.WotsDomainNumeric

/-! A conservative full signing-availability endpoint in the finite ideal
model. Both R and WOTS searches use ten million trials. This is a probability
of admitted signing failure, not a forgery margin or concrete-backend claim. -/
namespace C10Probability
noncomputable section

theorem c10_signing_charge_quota_bound :
    c10SigningChargeReal c10RSigningConfig (2 ^ 32) (2 ^ 20) ≤ (2 : ℝ)⁻¹ ^ 38 := by
  have wbound : wotsDomainChargeReal c10RSigningConfig.wTrials ≤ (2 : ℝ)⁻¹ ^ 64 :=
    wots_signing_domain_charge_bound
  exact (add_le_add c10_r_charge_quota_bound wbound).trans (by norm_num)

theorem c10_signing_concrete_failure_bound (publicSeed : Digest) {fuel : ℕ}
    (adversaries : PMF (C10Adversary fuel)) :
    (((c10RShared c10RSigningConfig publicSeed adversaries (2 ^ 32) (2 ^ 20)).map
      c10SigningFailure) true).toReal ≤ (2 : ℝ)⁻¹ ^ 38 := by
  exact (c10_shared_signing_failure_real c10RSigningConfig publicSeed adversaries _ _).trans
    c10_signing_charge_quota_bound

end
end C10Probability

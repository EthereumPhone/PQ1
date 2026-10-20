import C10Probability.C10Availability
import C10Probability.C10RReal

/-! Finite, real and capped bounds for actual admitted signing failure.
Refusal is not exhaustion. The public seed/configuration/adversary PMF remain
independent of the hidden uniform prefix as required by the R component. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def c10SigningChargeReal (cfg : C10SessionConfig) (qr qs : ℕ) : ℝ :=
  c10RChargeReal cfg qr qs + wotsDomainChargeReal cfg.wTrials

theorem c10_signing_charge_ne_top (cfg : C10SessionConfig) (qr qs : ℕ) :
    c10SigningCharge cfg qr qs ≠ ⊤ := by
  exact ENNReal.add_ne_top.mpr ⟨c10_r_charge_ne_top cfg qr qs, wots_domain_charge_ne_top cfg.wTrials⟩

theorem c10_signing_charge_real (cfg : C10SessionConfig) (qr qs : ℕ) :
    (c10SigningCharge cfg qr qs).toReal = c10SigningChargeReal cfg qr qs := by
  rw [c10SigningCharge, ENNReal.toReal_add (c10_r_charge_ne_top cfg qr qs)
    (wots_domain_charge_ne_top cfg.wTrials), c10_r_charge_real, wots_domain_charge_real]
  rfl

theorem c10_shared_signing_failure_real (cfg : C10SessionConfig) (publicSeed : Digest)
    {fuel : ℕ} (adversaries : PMF (C10Adversary fuel)) (qr qs : ℕ) :
    (((c10RShared cfg publicSeed adversaries qr qs).map c10SigningFailure) true).toReal ≤
      c10SigningChargeReal cfg qr qs := by
  simpa only [c10_signing_charge_real] using ENNReal.toReal_mono
    (c10_signing_charge_ne_top cfg qr qs)
    (c10_shared_signing_failure_bound cfg publicSeed adversaries qr qs)

theorem c10_shared_signing_failure_real_capped (cfg : C10SessionConfig) (publicSeed : Digest)
    {fuel : ℕ} (adversaries : PMF (C10Adversary fuel)) (qr qs : ℕ) :
    (((c10RShared cfg publicSeed adversaries qr qs).map c10SigningFailure) true).toReal ≤
      min 1 (c10SigningChargeReal cfg qr qs) := by
  apply le_min
  · simpa only [ENNReal.toReal_one] using ENNReal.toReal_mono
      (by simp : (1 : ℝ≥0∞) ≠ ⊤)
      (PMF.coe_le_one ((c10RShared cfg publicSeed adversaries qr qs).map c10SigningFailure) true)
  · exact c10_shared_signing_failure_real cfg publicSeed adversaries qr qs

end
end C10Probability

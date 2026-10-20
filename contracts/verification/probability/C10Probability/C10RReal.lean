import C10Probability.C10RTransfer
import C10Probability.RSessionReal

/-! Finite and real-valued charges for R exhaustion in initialized full C10
games. The public history includes keygen and complete signing; the prefix
charge also includes final verification. WOTS availability is not asserted. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem c10_r_charge_ne_top (cfg : C10SessionConfig) (qr qs : ℕ) :
    c10RCharge cfg qr qs ≠ ⊤ := by
  have finite := r_exhaustion_charge_ne_top (c10RHistoryCap cfg qr qs) cfg.rTrials
  unfold c10RCharge
  finiteness

def c10RChargeReal (cfg : C10SessionConfig) (qr qs : ℕ) : ℝ :=
  (qs : ℝ) * ((1 - (1 : ℝ) / 2048) ^ cfg.rTrials +
    (collisionPairs (c10RHistoryCap cfg qr qs) cfg.rTrials : ℝ) / 2 ^ 128) +
      (c10RPublicCalls cfg qr qs : ℝ) / 2 ^ 256

theorem c10_r_charge_real (cfg : C10SessionConfig) (qr qs : ℕ) :
    (c10RCharge cfg qr qs).toReal = c10RChargeReal cfg qr qs := by
  have finite := r_exhaustion_charge_ne_top (c10RHistoryCap cfg qr qs) cfg.rTrials
  unfold c10RCharge c10RChargeReal
  rw [ENNReal.toReal_add (by finiteness) (by finiteness)]
  simp only [ENNReal.toReal_mul, ENNReal.toReal_natCast, r_exhaustion_charge_real,
    ENNReal.toReal_div, ENNReal.toReal_pow, ENNReal.toReal_ofNat]

theorem c10_r_shared_exhaustion_real (cfg : C10SessionConfig) (publicSeed : Digest)
    {fuel : ℕ} (adversaries : PMF (C10Adversary fuel)) (qr qs : ℕ) :
    (((c10RShared cfg publicSeed adversaries qr qs).map c10RFailure) true).toReal ≤
      c10RChargeReal cfg qr qs := by
  simpa only [c10_r_charge_real] using ENNReal.toReal_mono
    (c10_r_charge_ne_top cfg qr qs) (c10_r_shared_exhaustion cfg publicSeed adversaries qr qs)

theorem c10_r_shared_exhaustion_real_capped (cfg : C10SessionConfig) (publicSeed : Digest)
    {fuel : ℕ} (adversaries : PMF (C10Adversary fuel)) (qr qs : ℕ) :
    (((c10RShared cfg publicSeed adversaries qr qs).map c10RFailure) true).toReal ≤
      min 1 (c10RChargeReal cfg qr qs) := by
  apply le_min
  · simpa only [ENNReal.toReal_one] using ENNReal.toReal_mono
      (by simp : (1 : ℝ≥0∞) ≠ ⊤)
      (PMF.coe_le_one ((c10RShared cfg publicSeed adversaries qr qs).map c10RFailure) true)
  · exact c10_r_shared_exhaustion_real cfg publicSeed adversaries qr qs

end
end C10Probability

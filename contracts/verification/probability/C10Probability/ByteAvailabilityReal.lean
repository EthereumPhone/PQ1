import C10Probability.ByteAvailability
import C10Probability.C10AvailabilityNumeric

/-! Finite real-valued and numeric byte-game signing-availability endpoints.
The charge and its parameters are unchanged; serialization adds no loss.
These statements concern admitted failure, not malformed/capped refusal or
forgery probability, and assert no concrete backend correspondence. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {fuel : ℕ}

theorem c10_byte_initialized_signing_failure_real (cfg : C10SessionConfig)
    (sampler : PMF (Digest × C10ByteAdversary fuel)) (qr qs : ℕ) :
    (((c10ByteObservedInitializedShared cfg sampler qr qs).map c10ByteSigningFailure) true).toReal ≤
      c10SigningChargeReal cfg qr qs := by
  simpa only [c10_signing_charge_real] using ENNReal.toReal_mono
    (c10_signing_charge_ne_top cfg qr qs)
    (c10_byte_initialized_signing_failure_bound cfg sampler qr qs)

theorem c10_byte_initialized_signing_failure_real_capped (cfg : C10SessionConfig)
    (sampler : PMF (Digest × C10ByteAdversary fuel)) (qr qs : ℕ) :
    (((c10ByteObservedInitializedShared cfg sampler qr qs).map c10ByteSigningFailure) true).toReal ≤
      min 1 (c10SigningChargeReal cfg qr qs) := by
  apply le_min
  · simpa only [ENNReal.toReal_one] using ENNReal.toReal_mono
      (by simp : (1 : ℝ≥0∞) ≠ ⊤) (PMF.coe_le_one
        ((c10ByteObservedInitializedShared cfg sampler qr qs).map c10ByteSigningFailure) true)
  · exact c10_byte_initialized_signing_failure_real cfg sampler qr qs

theorem c10_byte_signing_concrete_failure_bound
    (sampler : PMF (Digest × C10ByteAdversary fuel)) :
    (((c10ByteObservedInitializedShared c10RSigningConfig sampler (2 ^ 32) (2 ^ 20)).map
      c10ByteSigningFailure) true).toReal ≤ (2 : ℝ)⁻¹ ^ 38 := by
  exact (c10_byte_initialized_signing_failure_real c10RSigningConfig sampler _ _).trans
    c10_signing_charge_quota_bound

end
end C10Probability

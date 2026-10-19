import C10Probability.ByteGame
import C10Probability.SharedForgeBound

/-! The existing six-case bound on the actual finite initialized byte game.
Serialization and client translation add no statistical error. Only the final
Boolean event transfers between independent and shared oracle interpretations. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem c10_byte_independent_forge_bound (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10ByteAdversary fuel)) (qr qs : ℕ) :
    (c10ByteInitializedIndependent cfg sampler qr qs).toOuterMeasure {true} ≤
      independentForgeCharge cfg qr qs := by
  rw [← c10_byte_initialized_independent_eq]
  exact c10_independent_forge_bound cfg (structuredByteSampler sampler) qr qs

theorem c10_byte_initialized_prefix_bounds (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10ByteAdversary fuel)) (qr qs : ℕ) (event : Set Bool) :
    (c10ByteInitializedShared cfg sampler qr qs).toOuterMeasure event ≤
      (c10ByteInitializedIndependent cfg sampler qr qs).toOuterMeasure event +
        (sessionGamePublic cfg qr qs : ℝ≥0∞) / 2 ^ 256 ∧
    (c10ByteInitializedIndependent cfg sampler qr qs).toOuterMeasure event ≤
      (c10ByteInitializedShared cfg sampler qr qs).toOuterMeasure event +
        (sessionGamePublic cfg qr qs : ℝ≥0∞) / 2 ^ 256 := by
  rw [← c10_byte_initialized_shared_eq, ← c10_byte_initialized_independent_eq]
  exact c10_initialized_prefix_bounds cfg (structuredByteSampler sampler) qr qs event

theorem c10_byte_shared_forge_bound (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10ByteAdversary fuel)) (qr qs : ℕ) :
    (c10ByteInitializedShared cfg sampler qr qs).toOuterMeasure {true} ≤ sharedForgeCharge cfg qr qs := by
  rw [← c10_byte_initialized_shared_eq]
  exact c10_shared_forge_bound cfg (structuredByteSampler sampler) qr qs

theorem c10_byte_shared_forge_bound_capped (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10ByteAdversary fuel)) (qr qs : ℕ) :
    (c10ByteInitializedShared cfg sampler qr qs).toOuterMeasure {true} ≤
      min 1 (sharedForgeCharge cfg qr qs) := by
  rw [← c10_byte_initialized_shared_eq]
  exact c10_shared_forge_bound_capped cfg (structuredByteSampler sampler) qr qs

theorem c10_byte_shared_forge_bound_real (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10ByteAdversary fuel)) (qr qs : ℕ) :
    ((c10ByteInitializedShared cfg sampler qr qs).toOuterMeasure {true}).toReal ≤
      (independentForgeCharge cfg qr qs).toReal + (sessionGamePublic cfg qr qs : ℝ) / 2 ^ 256 := by
  rw [← c10_byte_initialized_shared_eq]
  exact c10_shared_forge_bound_real cfg (structuredByteSampler sampler) qr qs

theorem c10_byte_shared_forge_bound_real_capped (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10ByteAdversary fuel)) (qr qs : ℕ) :
    ((c10ByteInitializedShared cfg sampler qr qs).toOuterMeasure {true}).toReal ≤
      min 1 (sharedForgeCharge cfg qr qs).toReal := by
  rw [← c10_byte_initialized_shared_eq]
  exact c10_shared_forge_bound_real_capped cfg (structuredByteSampler sampler) qr qs

end
end C10Probability

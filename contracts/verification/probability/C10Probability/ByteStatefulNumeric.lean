import C10Probability.ByteStatefulBounds
import C10Probability.ForgeNumeric

/-! Existing numerical forgery charges now apply to almost-surely terminating
stateful byte clients, without a uniform attempted-interaction bound. The
cryptographic assumptions, admitted caps and numerical charges are unchanged. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem c10_stateful_byte_forge_example_small {S : Type*}
    (step : S → PMF (C10ByteAction S C10ByteForgery))
    (sampler : PMF (Digest × C10StatefulByteAdversary S))
    (terminates : C10StatefulByteTerminates forgeExampleConfig step sampler (2 ^ 20) 65536) :
    (c10StatefulByteInitialized forgeExampleConfig step sampler (2 ^ 20) 65536 terminates).toOuterMeasure
      {out | out.1 = true} < (1 : ℝ≥0∞) / 2 ^ 50 := by
  exact (c10_stateful_byte_forge_bound forgeExampleConfig step sampler _ _ terminates).trans_lt
    ((min_le_right _ _).trans_lt forge_example_charge_small)

theorem c10_stateful_byte_forge_example_medium {S : Type*}
    (step : S → PMF (C10ByteAction S C10ByteForgery))
    (sampler : PMF (Digest × C10StatefulByteAdversary S))
    (terminates : C10StatefulByteTerminates forgeExampleConfig step sampler (2 ^ 24) 65536) :
    (c10StatefulByteInitialized forgeExampleConfig step sampler (2 ^ 24) 65536 terminates).toOuterMeasure
      {out | out.1 = true} < (1 : ℝ≥0∞) / 2 ^ 34 := by
  exact (c10_stateful_byte_forge_bound forgeExampleConfig step sampler _ _ terminates).trans_lt
    ((min_le_right _ _).trans_lt forge_example_charge_medium)

end
end C10Probability

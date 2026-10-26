import C10Probability.ByteStatefulExecution
import C10Probability.KernelLimit
import C10Probability.ByteAvailabilityReal

/-! Cap-only initialized bounds for stateful randomized byte clients that
terminate almost surely. No uniform bound on attempted interactions is assumed.
The finite operational observations compile exactly to the existing games;
their proved bounds transfer through monotone completed-output mass. Only
almost-sure completion justifies the normalized terminal PMF, without dividing
by a success/termination probability. This remains the classical ideal model. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem c10_stateful_byte_forge_bound {S : Type*} (cfg : C10SessionConfig)
    (step : S → PMF (C10ByteAction S C10ByteForgery))
    (sampler : PMF (Digest × C10StatefulByteAdversary S)) (qr qs : ℕ)
    (terminates : C10StatefulByteTerminates cfg step sampler qr qs) :
    (c10StatefulByteInitialized cfg step sampler qr qs terminates).toOuterMeasure
      {out | out.1 = true} ≤ min 1 (sharedForgeCharge cfg qr qs) := by
  apply kernel_terminal_pmf_observation_bound
    (c10StatefulByteGameStep cfg step sampler qr qs) .initialize terminates
    (c10StatefulByteObservation qr qs) (fun _ => rfl)
  intro n
  cases n with
  | zero =>
    simp [kernelCutoff, c10StatefulByteObservation, PMF.toOuterMeasure_pure_apply]
  | succ n =>
    rw [c10_stateful_byte_execution_cutoff]
    simpa only [PMF.toOuterMeasure_map_apply] using
      c10_stateful_byte_cutoff_forge_bound cfg step n sampler qr qs

theorem c10_stateful_byte_failure_bound {S : Type*} (cfg : C10SessionConfig)
    (step : S → PMF (C10ByteAction S C10ByteForgery))
    (sampler : PMF (Digest × C10StatefulByteAdversary S)) (qr qs : ℕ)
    (terminates : C10StatefulByteTerminates cfg step sampler qr qs) :
    (c10StatefulByteInitialized cfg step sampler qr qs terminates).toOuterMeasure
      {out | c10ByteSigningFailure out = true} ≤ min 1 (c10SigningCharge cfg qr qs) := by
  apply kernel_terminal_pmf_observation_bound
    (c10StatefulByteGameStep cfg step sampler qr qs) .initialize terminates
    (c10StatefulByteObservation qr qs) (fun _ => rfl)
  intro n
  cases n with
  | zero =>
    simp [kernelCutoff, c10StatefulByteObservation, PMF.toOuterMeasure_pure_apply,
      c10ByteSigningFailure, emptySessionLedger]
  | succ n =>
    rw [c10_stateful_byte_execution_cutoff, c10_byte_signing_failure_event]
    exact c10_stateful_byte_cutoff_failure_bound cfg step n sampler qr qs

theorem c10_stateful_byte_forge_bound_real {S : Type*} (cfg : C10SessionConfig)
    (step : S → PMF (C10ByteAction S C10ByteForgery))
    (sampler : PMF (Digest × C10StatefulByteAdversary S)) (qr qs : ℕ)
    (terminates : C10StatefulByteTerminates cfg step sampler qr qs) :
    ((c10StatefulByteInitialized cfg step sampler qr qs terminates).toOuterMeasure
      {out | out.1 = true}).toReal ≤ min 1 (sharedForgeCharge cfg qr qs).toReal := by
  have bound := ENNReal.toReal_mono (show min 1 (sharedForgeCharge cfg qr qs) ≠ ⊤ by simp)
    (c10_stateful_byte_forge_bound cfg step sampler qr qs terminates)
  simpa only [ENNReal.toReal_min (show (1 : ℝ≥0∞) ≠ ⊤ by simp)
    (shared_forge_charge_ne_top cfg qr qs), ENNReal.toReal_one] using bound

theorem c10_stateful_byte_failure_bound_real {S : Type*} (cfg : C10SessionConfig)
    (step : S → PMF (C10ByteAction S C10ByteForgery))
    (sampler : PMF (Digest × C10StatefulByteAdversary S)) (qr qs : ℕ)
    (terminates : C10StatefulByteTerminates cfg step sampler qr qs) :
    ((c10StatefulByteInitialized cfg step sampler qr qs terminates).toOuterMeasure
      {out | c10ByteSigningFailure out = true}).toReal ≤ min 1 (c10SigningChargeReal cfg qr qs) := by
  have bound := ENNReal.toReal_mono (show min 1 (c10SigningCharge cfg qr qs) ≠ ⊤ by simp)
    (c10_stateful_byte_failure_bound cfg step sampler qr qs terminates)
  simpa only [ENNReal.toReal_min (show (1 : ℝ≥0∞) ≠ ⊤ by simp)
    (c10_signing_charge_ne_top cfg qr qs), ENNReal.toReal_one, c10_signing_charge_real] using bound

theorem c10_stateful_byte_signing_quota_bound {S : Type*}
    (step : S → PMF (C10ByteAction S C10ByteForgery))
    (sampler : PMF (Digest × C10StatefulByteAdversary S))
    (terminates : C10StatefulByteTerminates c10RSigningConfig step sampler (2 ^ 32) (2 ^ 20)) :
    ((c10StatefulByteInitialized c10RSigningConfig step sampler (2 ^ 32) (2 ^ 20) terminates).toOuterMeasure
      {out | c10ByteSigningFailure out = true}).toReal ≤ (2 : ℝ)⁻¹ ^ 38 := by
  exact (c10_stateful_byte_failure_bound_real c10RSigningConfig step sampler _ _ terminates).trans
    ((min_le_right _ _).trans c10_signing_charge_quota_bound)

end
end C10Probability

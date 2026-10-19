import C10Probability.ForgeBound

/-! Transfer only the final Boolean forge event. The independent-cache six
cases are never asserted to have the same probabilities in the shared oracle. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def sharedForgeCharge (cfg : C10SessionConfig) (qr qs : ℕ) : ℝ≥0∞ :=
  independentForgeCharge cfg qr qs + (sessionGamePublic cfg qr qs : ℝ≥0∞) / 2 ^ 256

theorem shared_forge_charge_ne_top (cfg : C10SessionConfig) (qr qs : ℕ) :
    sharedForgeCharge cfg qr qs ≠ ⊤ := by
  exact ENNReal.add_ne_top.mpr ⟨independent_forge_charge_ne_top cfg qr qs,
    ENNReal.div_ne_top (by finiteness) (by simp)⟩

theorem c10_shared_forge_bound (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    (c10InitializedShared cfg sampler qr qs).toOuterMeasure {true} ≤ sharedForgeCharge cfg qr qs := by
  exact (c10_initialized_prefix_bounds cfg sampler qr qs {true}).1.trans
    (add_le_add (c10_independent_forge_bound cfg sampler qr qs) le_rfl)

theorem c10_shared_forge_bound_real (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    ((c10InitializedShared cfg sampler qr qs).toOuterMeasure {true}).toReal ≤
      (independentForgeCharge cfg qr qs).toReal + (sessionGamePublic cfg qr qs : ℝ) / 2 ^ 256 := by
  exact (c10_initialized_forge_transfer_real cfg sampler qr qs).trans
    (add_le_add (c10_independent_forge_bound_real cfg sampler qr qs) le_rfl)

theorem shared_forge_charge_real (cfg : C10SessionConfig) (qr qs : ℕ) :
    (sharedForgeCharge cfg qr qs).toReal =
      (independentForgeCharge cfg qr qs).toReal + (sessionGamePublic cfg qr qs : ℝ) / 2 ^ 256 := by
  rw [sharedForgeCharge, ENNReal.toReal_add (independent_forge_charge_ne_top cfg qr qs)
    (ENNReal.div_ne_top (by finiteness) (by simp))]
  simp only [ENNReal.toReal_div, ENNReal.toReal_natCast, ENNReal.toReal_pow, ENNReal.toReal_ofNat]

theorem c10_observed_shared_forge_bound (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    (c10ObservedInitializedShared cfg sampler qr qs).toOuterMeasure
      {out | out.1.driver.accepted = true} ≤ sharedForgeCharge cfg qr qs := by
  change (c10ObservedInitializedShared cfg sampler qr qs).toOuterMeasure
    {out | out.1.driver.accepted ∈ ({true} : Set Bool)} ≤ _
  rw [c10_observed_initialized_shared_event]
  exact c10_shared_forge_bound cfg sampler qr qs

theorem c10_shared_forge_bound_capped (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    (c10InitializedShared cfg sampler qr qs).toOuterMeasure {true} ≤
      min 1 (sharedForgeCharge cfg qr qs) := by
  apply le_min
  · rw [PMF.toOuterMeasure_apply_singleton]
    exact PMF.coe_le_one _ true
  · exact c10_shared_forge_bound cfg sampler qr qs

theorem c10_shared_forge_bound_real_capped (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    ((c10InitializedShared cfg sampler qr qs).toOuterMeasure {true}).toReal ≤
      min 1 (sharedForgeCharge cfg qr qs).toReal := by
  have bound := ENNReal.toReal_mono
    (show min 1 (sharedForgeCharge cfg qr qs) ≠ ⊤ by simp)
    (c10_shared_forge_bound_capped cfg sampler qr qs)
  simpa only [ENNReal.toReal_min (show (1 : ℝ≥0∞) ≠ ⊤ by simp) (shared_forge_charge_ne_top cfg qr qs),
    ENNReal.toReal_one] using bound

end
end C10Probability

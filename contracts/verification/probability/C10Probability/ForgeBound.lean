import C10Probability.ObservedForgeCases
import C10Probability.ObservedCacheCharges

/-! A quantitative forgery bound for the finite initialized structured model.
Six potentially overlapping events are charged in one independent experiment.
No concrete hash, codec or unbounded-adversary correspondence is asserted. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem pmf_six_event_bound {α : Type*} (p : PMF α) (win a b c d e f : Set α)
    (qa qb qc qd qe qf : ℝ≥0∞)
    (cover : ∀ out ∈ p.support, out ∈ win →
      out ∈ a ∨ out ∈ b ∨ out ∈ c ∨ out ∈ d ∨ out ∈ e ∨ out ∈ f)
    (ha : p.toOuterMeasure a ≤ qa) (hb : p.toOuterMeasure b ≤ qb)
    (hc : p.toOuterMeasure c ≤ qc) (hd : p.toOuterMeasure d ≤ qd)
    (he : p.toOuterMeasure e ≤ qe) (hf : p.toOuterMeasure f ≤ qf) :
    p.toOuterMeasure win ≤ qa + (qb + (qc + (qd + (qe + qf)))) := by
  have included : win ∩ p.support ⊆ a ∪ (b ∪ (c ∪ (d ∪ (e ∪ f)))) := by
    intro out hit
    exact cover out hit.2 hit.1
  refine (p.toOuterMeasure_mono included).trans ?_
  exact (MeasureTheory.measure_union_le _ _).trans (add_le_add ha
    ((MeasureTheory.measure_union_le _ _).trans (add_le_add hb
      ((MeasureTheory.measure_union_le _ _).trans (add_le_add hc
        ((MeasureTheory.measure_union_le _ _).trans (add_le_add hd
          ((MeasureTheory.measure_union_le _ _).trans (add_le_add he hf)))))))))

def independentForgeCharge (cfg : C10SessionConfig) (qr qs : ℕ) : ℝ≥0∞ :=
  ((sessionGameSelected cfg qr qs).choose 2 : ℝ≥0∞) / 2 ^ 128 +
    ((sessionGameRaw cfg qr qs : ℝ≥0∞) / 2 ^ 128 +
      (acceptedWotsGameCharge (sessionGameRaw cfg qr qs) +
        (ordinaryWotsOpeningCharge qr qs +
          (ordinaryForsOpeningCharge cfg qr qs + forsCoverageCharge (qr + qs + 1)))))

theorem independent_forge_charge_ne_top (cfg : C10SessionConfig) (qr qs : ℕ) :
    independentForgeCharge cfg qr qs ≠ ⊤ := by
  unfold independentForgeCharge
  apply ENNReal.add_ne_top.mpr
  refine ⟨ENNReal.div_ne_top (by finiteness) (by simp), ?_⟩
  apply ENNReal.add_ne_top.mpr
  refine ⟨ENNReal.div_ne_top (by finiteness) (by simp), ?_⟩
  exact ENNReal.add_ne_top.mpr ⟨accepted_wots_game_charge_ne_top _,
    ENNReal.add_ne_top.mpr ⟨ordinary_wots_opening_charge_ne_top qr qs,
      ENNReal.add_ne_top.mpr ⟨ordinary_fors_opening_charge_ne_top cfg qr qs,
        fors_coverage_charge_ne_top _⟩⟩⟩

theorem c10_observed_independent_forge_bound (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    (c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure
      {out | out.1.driver.accepted = true} ≤ independentForgeCharge cfg qr qs := by
  exact pmf_six_event_bound (c10ObservedInitializedIndependent cfg sampler qr qs) _
    {out | ¬ PublicNodeCollisionFree Sum.inl out.2}
    {out | PublicNodeZero (fun key => out.2 (.inl key))}
    {out | AcceptedWotsCollision (fun key => out.2 (.inl key))}
    {out | ObservedWotsEarlierExposure cfg out}
    {out | ObservedForestOpening cfg out}
    {out | ObservedForestCoverage cfg out} _ _ _ _ _ _
    (c10_initialized_forge_cases cfg sampler qr qs)
    (c10_observed_node_collision_bound cfg sampler qr qs)
    (c10_observed_zero_bound cfg sampler qr qs)
    (c10_observed_accepted_collision_bound cfg sampler qr qs)
    (c10_observed_wots_earlier_bound cfg sampler qr qs)
    (c10_observed_forest_opening_bound cfg sampler qr qs)
    (c10_observed_forest_coverage_bound cfg sampler qr qs)

theorem c10_independent_forge_bound (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    (c10InitializedIndependent cfg sampler qr qs).toOuterMeasure {true} ≤
      independentForgeCharge cfg qr qs := by
  rw [← c10_observed_initialized_independent_event]
  exact c10_observed_independent_forge_bound cfg sampler qr qs

theorem c10_independent_forge_bound_real (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    ((c10InitializedIndependent cfg sampler qr qs).toOuterMeasure {true}).toReal ≤
      (independentForgeCharge cfg qr qs).toReal := by
  exact ENNReal.toReal_mono (independent_forge_charge_ne_top cfg qr qs)
    (c10_independent_forge_bound cfg sampler qr qs)

end
end C10Probability

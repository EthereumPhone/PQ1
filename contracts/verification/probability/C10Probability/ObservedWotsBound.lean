import C10Probability.ObservedWotsEvent

/-! Finite union over both actual layers, all43chains, and cuts0through6.
The recurrence weights sum to28, not49. The endpoint is the original
initialized observed independent game with its full cache. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def ordinaryWotsOpeningCharge (qr qs : ℕ) : ℝ≥0∞ :=
  316237824 * wotsCutCharge qr qs

theorem wots_cut_weight_sum : (∑ cut : Fin 7, ((cut.val + 1 : ℕ) : ℝ≥0∞)) = 28 := by
  norm_num [Fin.sum_univ_succ]

theorem wots_target_weight_sum (qr qs : ℕ) :
    (∑ target : WotsCutTarget, ((target.2.val + 1 : ℕ) : ℝ≥0∞) * wotsCutCharge qr qs) =
      ordinaryWotsOpeningCharge qr qs := by
  rw [Fintype.sum_prod_type]
  simp only [← Finset.sum_mul, wots_cut_weight_sum]
  simp only [Finset.sum_const, Finset.card_univ, wots_target_card, nsmul_eq_mul]
  norm_num [ordinaryWotsOpeningCharge, ← mul_assoc]

theorem c10_observed_wots_opening_bound (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    (c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure
      {out | ObservedWotsOpening cfg out} ≤ ordinaryWotsOpeningCharge qr qs := by
  calc
    _ ≤ (c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure
        (⋃ target : WotsCutTarget, observedWotsSelectedOpening target cfg) := by
      apply MeasureTheory.OuterMeasure.mono
      intro out opening
      obtain ⟨target, member⟩ := opening
      exact Set.mem_iUnion.mpr ⟨target, member⟩
    _ ≤ ∑ target : WotsCutTarget, (c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure
        (observedWotsSelectedOpening target cfg) := MeasureTheory.measure_iUnion_fintype_le _ _
    _ ≤ ∑ target : WotsCutTarget, ((target.2.val + 1 : ℕ) : ℝ≥0∞) * wotsCutCharge qr qs := by
      exact Finset.sum_le_sum (fun target _ => c10_initialized_wots_selected_bound target cfg sampler qr qs)
    _ = _ := wots_target_weight_sum qr qs

theorem ordinary_wots_opening_charge_ne_top (qr qs : ℕ) :
    ordinaryWotsOpeningCharge qr qs ≠ ⊤ := by
  unfold ordinaryWotsOpeningCharge wotsCutCharge
  exact ENNReal.mul_ne_top (by finiteness) (ENNReal.div_ne_top (by finiteness) (by simp))

theorem c10_observed_wots_opening_bound_real (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    ((c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure
      {out | ObservedWotsOpening cfg out}).toReal ≤
        (316237824 : ℝ) * (((155867 + 2 * qr + qs * 364076 : ℕ) : ℝ) / 2 ^ 128) := by
  have bound := ENNReal.toReal_mono (ordinary_wots_opening_charge_ne_top qr qs)
    (c10_observed_wots_opening_bound cfg sampler qr qs)
  simpa only [ordinaryWotsOpeningCharge, wotsCutCharge, ENNReal.toReal_mul,
    ENNReal.toReal_ofNat, ENNReal.toReal_div, ENNReal.toReal_natCast, ENNReal.toReal_pow] using bound

end
end C10Probability

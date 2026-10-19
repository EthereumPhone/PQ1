import C10Probability.WotsExposureSelection
import C10Probability.ObservedForestDescent

/-! The two earlier-exposure branches of the existing descent share one
finite-union charge. All other descent alternatives remain explicit. These
are independent-oracle cache-visible events, not a full forge theorem. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def ObservedWotsEarlierExposure (cfg : C10SessionConfig)
    (out : C10ObservedGame × Memo WotsQuery Digest) : Prop :=
  ∃ records, C10SigningHistory id out.2 (sessionConfigAt cfg out.1.key)
    out.1.driver.session.exposures records ∧
    ((∃ top, TopEarlierExposure id out.2 out.1.key.1 out.1.driver.session.session.value.2 records top) ∨
      ∃ top lower, LowerEarlierExposure id out.2 out.1.key.1 out.1.driver.session.session.value.2 records top lower)

theorem observed_wots_earlier_selected (cfg : C10SessionConfig)
    (out : C10ObservedGame × Memo WotsQuery Digest) (earlier : ObservedWotsEarlierExposure cfg out) :
    ObservedWotsOpening cfg out := by
  obtain ⟨records, history, top | lower⟩ := earlier
  · obtain ⟨opening, i, _, endpoint, replayed, allPrior⟩ := top
    exact observed_top_earlier_opening cfg out records history opening i endpoint replayed
      (fun prior member address => (allPrior prior member address).1)
  · obtain ⟨opening, lower, i, _, endpoint, replayed, allPrior⟩ := lower
    exact observed_lower_earlier_opening cfg out records history opening lower i endpoint replayed
      (fun prior member address => (allPrior prior member address).1)

theorem c10_observed_wots_earlier_bound (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    (c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure
      {out | ObservedWotsEarlierExposure cfg out} ≤ ordinaryWotsOpeningCharge qr qs := by
  refine le_trans ?_ (c10_observed_wots_opening_bound cfg sampler qr qs)
  exact MeasureTheory.OuterMeasure.mono _ (fun out earlier => observed_wots_earlier_selected cfg out earlier)

theorem c10_observed_wots_earlier_bound_real (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    ((c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure
      {out | ObservedWotsEarlierExposure cfg out}).toReal ≤
        (316237824 : ℝ) * (((155867 + 2 * qr + qs * 364076 : ℕ) : ℝ) / 2 ^ 128) := by
  have bound := ENNReal.toReal_mono (ordinary_wots_opening_charge_ne_top qr qs)
    (c10_observed_wots_earlier_bound cfg sampler qr qs)
  simpa only [ordinaryWotsOpeningCharge, wotsCutCharge, ENNReal.toReal_mul,
    ENNReal.toReal_ofNat, ENNReal.toReal_div, ENNReal.toReal_natCast, ENNReal.toReal_pow] using bound

def ObservedRepeatedLowerForest (cfg : C10SessionConfig)
    (out : C10ObservedGame × Memo WotsQuery Digest) : Prop :=
  ∃ records, C10SigningHistory id out.2 (sessionConfigAt cfg out.1.key)
    out.1.driver.session.exposures records ∧
    ∃ top lower, TopChainRecordValid id out.2 out.1.key.1 out.1.key.2
      out.1.driver.session.session.value.1 out.1.driver.session.session.value.2 top ∧
      LowerChainRecordValid id out.2 out.1.key.1 out.1.driver.session.session.value.2 top lower ∧
      RepeatedLowerForest id out.2 (sessionConfigAt cfg out.1.key) out.1.driver.session.exposures
        out.1.driver.session.session.value.2 records top lower

theorem observed_forest_descent_wots (cfg : C10SessionConfig)
    (out : C10ObservedGame × Memo WotsQuery Digest) (records : List C10SigningRecord)
    (history : C10SigningHistory id out.2 (sessionConfigAt cfg out.1.key)
      out.1.driver.session.exposures records) (top : TopChainRecord)
    (valid : TopChainRecordValid id out.2 out.1.key.1 out.1.key.2
      out.1.driver.session.session.value.1 out.1.driver.session.session.value.2 top)
    (descent : ForestDescentCase id out.2 (sessionConfigAt cfg out.1.key)
      out.1.driver.session.exposures out.1.driver.session.session.value.2 records top) :
    AcceptedWotsCollision (fun key => out.2 (.inl key)) ∨
      ObservedWotsEarlierExposure cfg out ∨ ObservedRepeatedLowerForest cfg out := by
  rcases descent with collision | earlier | repeated
  · exact Or.inl collision
  · exact Or.inr (Or.inl ⟨records, history, Or.inl ⟨top, earlier⟩⟩)
  · obtain ⟨_, _, _, _, _, _, lower, lowerValid, earlier | forest⟩ := repeated
    · exact Or.inr (Or.inl ⟨records, history, Or.inr ⟨top, lower, earlier⟩⟩)
    · exact Or.inr (Or.inr ⟨records, history, top, lower, valid, lowerValid, forest⟩)

theorem c10_initialized_wots_descent (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ)
    (out : C10ObservedGame × Memo WotsQuery Digest)
    (supported : out ∈ (c10ObservedInitializedIndependent cfg sampler qr qs).support)
    (win : out.1.driver.accepted = true) :
    ¬ PublicNodeCollisionFree Sum.inl out.2 ∨ PublicNodeZero (fun key => out.2 (.inl key)) ∨
      AcceptedWotsCollision (fun key => out.2 (.inl key)) ∨
      ObservedWotsEarlierExposure cfg out ∨ ObservedRepeatedLowerForest cfg out := by
  obtain ⟨records, history, _, collision | zero | opening⟩ :=
    c10_initialized_independent_forest_descent cfg sampler qr qs out supported win
  · exact Or.inl collision
  · exact Or.inr (Or.inl zero)
  · obtain ⟨top, valid, descent⟩ := opening
    exact Or.inr (Or.inr (observed_forest_descent_wots cfg out records history top valid descent))

end
end C10Probability

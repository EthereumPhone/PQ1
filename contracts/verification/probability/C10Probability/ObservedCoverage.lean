import C10Probability.HmsgCacheCoverage
import C10Probability.ObservedOutput
import C10Probability.ForestHistoryOpening
import C10Probability.RandomizerReplay

/-! The actual successful forgery's ordinary FORS coverage branch embeds into
the fresh accepted H_msg pool. Different coordinates may use different prior
signatures; freshness of the final message separates its key from every one. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem hmsg_input_message_eq (seed root first second : ByteKey) (a b : Randomizer)
    (equal : hmsgRandomizerInput seed root first a = hmsgRandomizerInput seed root second b) :
    first = second := by
  unfold hmsgRandomizerInput at equal
  exact List.append_cancel_right (List.append_inj_right equal (by simp))

def ObservedForestCoverage (cfg : C10SessionConfig)
    (out : C10ObservedGame × Memo WotsQuery Digest) : Prop :=
  out.1.driver.accepted = true ∧ ∃ digest records,
    out.2 (.inl (hmsgRandomizerInput out.1.key.1 out.1.key.2
      out.1.driver.session.session.value.1 out.1.driver.session.session.value.2.randomizer)) = some digest ∧
    ForestHistoryCovered id out.2 (sessionConfigAt cfg out.1.key)
      out.1.driver.session.exposures records digest out.1.driver.session.session.value.2.secrets

theorem observed_forest_cache_coverage (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ)
    (out : C10ObservedGame × Memo WotsQuery Digest)
    (supported : out ∈ (c10ObservedInitializedIndependent cfg sampler qr qs).support)
    (covered : ObservedForestCoverage cfg out) : HmsgCacheCoverage hmsgQuery out.2 := by
  obtain ⟨win, digest, records, lookup, coverage⟩ := covered
  obtain ⟨_, _, _, witness⟩ :=
    c10_observed_initialized_independent_witness cfg sampler qr qs out supported win
  obtain ⟨actualDigest, _, _, actualLookup, accepted, _, _, _⟩ := witness.verification
  have same : actualDigest = digest := Option.some.inj (actualLookup.symm.trans lookup)
  subst actualDigest
  refine ⟨Sum.inl (hmsgRandomizerInput out.1.key.1 out.1.key.2
    out.1.driver.session.session.value.1 out.1.driver.session.session.value.2.randomizer),
    digest, ?_, accepted, lookup, ?_⟩
  · simp only [hmsgQuery, hmsgWidth,
      hmsg_randomizer_length _ _ _ _ witness.seed_width witness.root_width witness.message_width,
      decide_true]
  · intro coordinate
    obtain ⟨prior, _, entry, member, valid, address, index, _⟩ := coverage coordinate
    obtain ⟨_, priorLookup, priorAccepted⟩ := replay_randomizer_under_success id out.2
      entry.request.random entry.request.message out.1.key.1 out.1.key.2
      cfg.rTrials cfg.rBound prior.trial entry.signature.randomizer prior.digest valid.randomizer
    refine ⟨Sum.inl (hmsgRandomizerInput out.1.key.1 out.1.key.2
      entry.request.message entry.signature.randomizer), prior.digest, ?_, ?_,
      priorAccepted, priorLookup, address, index⟩
    · intro equal
      exact witness.fresh entry member
        (hmsg_input_message_eq _ _ _ _ _ _ (Sum.inl.inj equal)).symm
    · simp only [hmsgQuery, hmsgWidth,
        hmsg_randomizer_length _ _ _ _ witness.seed_width witness.root_width
          (witness.exposures entry member).1, decide_true]

theorem c10_observed_forest_coverage_bound (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    (c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure
      {out | ObservedForestCoverage cfg out} ≤ forsCoverageCharge (qr + qs + 1) := by
  apply (PMF.toOuterMeasure_mono _ ?_).trans (c10_observed_cache_coverage_bound cfg sampler qr qs)
  intro out hit
  exact observed_forest_cache_coverage cfg sampler qr qs out hit.2 hit.1

theorem c10_observed_forest_coverage_bound_real (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    ((c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure
      {out | ObservedForestCoverage cfg out}).toReal ≤ (forsCoverageCharge (qr + qs + 1)).toReal := by
  exact ENNReal.toReal_mono (fors_coverage_charge_ne_top _)
    (c10_observed_forest_coverage_bound cfg sampler qr qs)

end
end C10Probability

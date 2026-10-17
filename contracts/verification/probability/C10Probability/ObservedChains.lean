import C10Probability.C10SigningReplay
import C10Probability.TopChainOpening

/-! Every returned signing exposure and the winning top-layer opening retain
their actual WOTS chain witnesses in one final cache. This does not expose
the cache to the adversary or charge the probability of these events. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem exposure_supported_chain_witness (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (table : Memo K Digest) (entry : C10Exposure)
    (supported : ExposureSupported encode cfg table entry) :
    C10ChainWitness encode table entry.request.random entry.request.message cfg.seed cfg.root
      entry.request.shuffle cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound entry.signature := by
  exact replay_c10_chain_witness encode table entry.request.random entry.request.message
    cfg.seed cfg.root entry.request.shuffle cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound
    entry.signature supported.2.2.2.2

theorem observed_output_chain_witnesses (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (publicSeed : Digest) (qr qs : ℕ) (out : C10ObservedGame × Memo K Digest)
    (witness : ObservedOutputWitness encode cfg publicSeed qr qs out) :
    (∀ entry ∈ out.1.driver.session.exposures,
      C10ChainWitness encode out.2 entry.request.random entry.request.message out.1.key.1 out.1.key.2
        entry.request.shuffle cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound entry.signature) ∧
    (¬ PublicNodeCollisionFree (fun key => encode (.inl key)) out.2 ∨
      PublicNodeZero (fun key => out.2 (encode (.inl key))) ∨
      TopChainOpening encode out.2 out.1.key.1 out.1.key.2
        out.1.driver.session.session.value.1 out.1.driver.session.session.value.2) := by
  refine ⟨?_, observed_output_top_chain_cases encode cfg publicSeed qr qs out witness⟩
  intro entry member
  exact exposure_supported_chain_witness encode (sessionConfigAt cfg out.1.key) out.2 entry
    (witness.exposures entry member)

theorem c10_observed_initialized_independent_chain_witnesses (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ)
    (out : C10ObservedGame × Memo WotsQuery Digest)
    (ho : out ∈ (c10ObservedInitializedIndependent cfg sampler qr qs).support)
    (win : out.1.driver.accepted = true) :
    (∀ entry ∈ out.1.driver.session.exposures,
      C10ChainWitness id out.2 entry.request.random entry.request.message out.1.key.1 out.1.key.2
        entry.request.shuffle cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound entry.signature) ∧
    (¬ PublicNodeCollisionFree Sum.inl out.2 ∨ PublicNodeZero (fun key => out.2 (.inl key)) ∨
      TopChainOpening id out.2 out.1.key.1 out.1.key.2
        out.1.driver.session.session.value.1 out.1.driver.session.session.value.2) := by
  obtain ⟨input, _, _, witness⟩ := c10_observed_initialized_independent_witness cfg sampler qr qs out ho win
  exact observed_output_chain_witnesses id cfg input.1 qr qs out witness

end
end C10Probability

import C10Probability.ForestDescent

/-! Actual observed/support/initialized winning outputs retain the complete
signing history and cap while descending to the FORS history alternatives.
Public-node collision/zero branches remain explicit; no probability bound. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem observed_output_forest_descent (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (publicSeed : Digest) (qr qs : ℕ) (out : C10ObservedGame × Memo K Digest)
    (witness : ObservedOutputWitness encode cfg publicSeed qr qs out) :
    ∃ records, C10SigningHistory encode out.2 (sessionConfigAt cfg out.1.key)
      out.1.driver.session.exposures records ∧ records.length ≤ qs ∧
      (¬ PublicNodeCollisionFree (fun key => encode (.inl key)) out.2 ∨
        PublicNodeZero (fun key => out.2 (encode (.inl key))) ∨
        ∃ top, TopChainRecordValid encode out.2 out.1.key.1 out.1.key.2
          out.1.driver.session.session.value.1 out.1.driver.session.session.value.2 top ∧
          ForestDescentCase encode out.2 (sessionConfigAt cfg out.1.key)
            out.1.driver.session.exposures out.1.driver.session.session.value.2 records top) := by
  obtain ⟨records, history, bound⟩ := observed_output_signing_history encode cfg publicSeed qr qs out witness
  refine ⟨records, history, bound, ?_⟩
  by_cases free : PublicNodeCollisionFree (fun key => encode (.inl key)) out.2
  · by_cases zero : PublicNodeZero (fun key => out.2 (encode (.inl key)))
    · exact Or.inr (Or.inl zero)
    · rcases observed_output_top_chain_cases encode cfg publicSeed qr qs out witness with collision | bad | opening
      · exact False.elim (collision free)
      · exact False.elim (zero bad)
      · obtain ⟨top, valid⟩ := top_chain_opening_record encode out.2 out.1.key.1 out.1.key.2
          out.1.driver.session.session.value.1 out.1.driver.session.session.value.2 opening
        exact Or.inr (Or.inr ⟨top, valid, top_chain_forest_descent encode out.2
          (sessionConfigAt cfg out.1.key) out.1.driver.session.exposures records history
          out.1.driver.session.session.value.1 out.1.driver.session.session.value.2 top valid
          witness.seed_width free zero⟩)
  · exact Or.inl free

theorem c10_observed_game_forest_descent [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel)
    (qr qs : ℕ) (table : Memo K Digest) (out : C10ObservedGame × Memo K Digest)
    (supported : out ∈ (c10ObservedGame encode cfg publicSeed adversary qr qs table).support)
    (win : out.1.driver.accepted = true) :
    ∃ records, C10SigningHistory encode out.2 (sessionConfigAt cfg out.1.key)
      out.1.driver.session.exposures records ∧ records.length ≤ qs ∧
      (¬ PublicNodeCollisionFree (fun key => encode (.inl key)) out.2 ∨
        PublicNodeZero (fun key => out.2 (encode (.inl key))) ∨
        ∃ top, TopChainRecordValid encode out.2 out.1.key.1 out.1.key.2
          out.1.driver.session.session.value.1 out.1.driver.session.session.value.2 top ∧
          ForestDescentCase encode out.2 (sessionConfigAt cfg out.1.key)
            out.1.driver.session.exposures out.1.driver.session.session.value.2 records top) := by
  exact observed_output_forest_descent encode cfg publicSeed qr qs out
    (c10_observed_output_witness encode cfg publicSeed adversary qr qs table out supported win)

theorem c10_initialized_independent_forest_descent (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ)
    (out : C10ObservedGame × Memo WotsQuery Digest)
    (supported : out ∈ (c10ObservedInitializedIndependent cfg sampler qr qs).support)
    (win : out.1.driver.accepted = true) :
    ∃ records, C10SigningHistory id out.2 (sessionConfigAt cfg out.1.key)
      out.1.driver.session.exposures records ∧ records.length ≤ qs ∧
      (¬ PublicNodeCollisionFree Sum.inl out.2 ∨ PublicNodeZero (fun key => out.2 (.inl key)) ∨
        ∃ top, TopChainRecordValid id out.2 out.1.key.1 out.1.key.2
          out.1.driver.session.session.value.1 out.1.driver.session.session.value.2 top ∧
          ForestDescentCase id out.2 (sessionConfigAt cfg out.1.key)
            out.1.driver.session.exposures out.1.driver.session.session.value.2 records top) := by
  obtain ⟨input, _, _, witness⟩ := c10_observed_initialized_independent_witness cfg sampler qr qs out supported win
  exact observed_output_forest_descent id cfg input.1 qr qs out witness

end
end C10Probability


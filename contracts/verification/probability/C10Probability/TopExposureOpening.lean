import C10Probability.TopChainRecord
import C10Probability.C10ExposureMinimum

/-! The actual winning top-chain opening either repeats a returned word and
its positional values, or contains a prefix earlier than every returned
position at that address. The latter includes actual suffixes to all matching
prior values. It does not assert secrecy or absence from raw hash queries. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

def TopExposureCase (encode : WotsQuery → K) (table : Memo K Digest) (seed : ByteKey)
    (sig : C10Signature) (records : List C10SigningRecord) (opening : TopChainRecord) : Prop :=
  (∃ prior ∈ records, hypertreeLeaf (hypertreeParent (hypertreeIndex prior.digest)) = opening.kp ∧
    opening.word = wotsOfDigest prior.upperDigest ∧
    ((sig.layers[1]?).getD emptyLayerSignature).sigma = prior.upper.sigma) ∨
  ∃ i, (opening.word i).val < wotsExposureMinimum (upperExposureWords records opening.kp) i ∧
    (opening.word i).val < 7 ∧
    replayProgram table (wotsSeedChainProgram encode seed 1 0 opening.kp i.val
      (opening.word i).val) = some (((sig.layers[1]?).getD emptyLayerSignature).sigma i) ∧
    ∀ prior ∈ records, hypertreeLeaf (hypertreeParent (hypertreeIndex prior.digest)) = opening.kp →
      (opening.word i).val < (wotsOfDigest prior.upperDigest i).val ∧
      replayProgram table (chainProgram (fun position value => encode (.inl
        (wotsChainInput seed 1 0 opening.kp i.val position value))) randomizerOfDigest
        (opening.word i).val ((wotsOfDigest prior.upperDigest i).val - (opening.word i).val)
        (((sig.layers[1]?).getD emptyLayerSignature).sigma i)) = some (prior.upper.sigma i)

theorem top_chain_exposure_comparison (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entries : List C10Exposure) (records : List C10SigningRecord)
    (history : C10SigningHistory encode table cfg entries records) (message : ByteKey)
    (sig : C10Signature) (opening : TopChainRecord)
    (valid : TopChainRecordValid encode table cfg.seed cfg.root message sig opening) :
    TopExposureCase encode table cfg.seed sig records opening := by
  rcases upper_exposure_minimum_comparison encode table cfg entries records history
    opening.kp opening.word valid.accepted with same | earlier
  · obtain ⟨prior, member, address, word⟩ := same
    obtain ⟨_, _, priorValid⟩ := exposure_history_record_member encode table cfg entries records history prior member
    have positions := priorValid.upper_prefixes
    rw [address, ← word] at positions
    exact Or.inl ⟨prior, member, address, word,
      wots_same_word_prefixes_eq encode table cfg.seed 1 0 opening.kp opening.word
        ((sig.layers[1]?).getD emptyLayerSignature).sigma prior.upper.sigma valid.prefixes positions⟩
  · obtain ⟨i, cut⟩ := earlier
    obtain ⟨endpoint, allPrior⟩ := (wots_below_exposure_minimum_iff
      (upperExposureWords records opening.kp) i (opening.word i).val).mp cut
    refine Or.inr ⟨i, cut, endpoint, valid.prefixes i, ?_⟩
    intro prior member address
    obtain ⟨_, _, priorValid⟩ := exposure_history_record_member encode table cfg entries records history prior member
    have positions := priorValid.upper_prefixes
    rw [address] at positions
    have priorMember := (mem_upper_exposure_words records opening.kp (wotsOfDigest prior.upperDigest)).mpr
      ⟨prior, member, address, rfl⟩
    have lower := allPrior _ priorMember
    exact ⟨lower, replay_wots_seed_chain_between encode table cfg.seed 1 0 opening.kp i.val
      (opening.word i).val (wotsOfDigest prior.upperDigest i).val
      (((sig.layers[1]?).getD emptyLayerSignature).sigma i) (prior.upper.sigma i)
      (Nat.le_of_lt lower) (valid.prefixes i) (positions i)⟩

theorem observed_output_top_exposure_cases (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (publicSeed : Digest) (qr qs : ℕ) (out : C10ObservedGame × Memo K Digest)
    (witness : ObservedOutputWitness encode cfg publicSeed qr qs out) :
    ∃ records, C10SigningHistory encode out.2 (sessionConfigAt cfg out.1.key)
      out.1.driver.session.exposures records ∧ records.length ≤ qs ∧
      (¬ PublicNodeCollisionFree (fun key => encode (.inl key)) out.2 ∨
        PublicNodeZero (fun key => out.2 (encode (.inl key))) ∨
        ∃ opening, TopChainRecordValid encode out.2 out.1.key.1 out.1.key.2
          out.1.driver.session.session.value.1 out.1.driver.session.session.value.2 opening ∧
          TopExposureCase encode out.2 out.1.key.1 out.1.driver.session.session.value.2 records opening) := by
  obtain ⟨records, history, bound⟩ := observed_output_signing_history encode cfg publicSeed qr qs out witness
  refine ⟨records, history, bound, ?_⟩
  rcases observed_output_top_chain_cases encode cfg publicSeed qr qs out witness with collision | zero | opening
  · exact Or.inl collision
  · exact Or.inr (Or.inl zero)
  · obtain ⟨record, valid⟩ := top_chain_opening_record encode out.2 out.1.key.1 out.1.key.2
      out.1.driver.session.session.value.1 out.1.driver.session.session.value.2 opening
    exact Or.inr (Or.inr ⟨record, valid, top_chain_exposure_comparison encode out.2
      (sessionConfigAt cfg out.1.key) out.1.driver.session.exposures records history
      out.1.driver.session.session.value.1 out.1.driver.session.session.value.2 record valid⟩)

theorem c10_observed_game_top_exposure_cases [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel)
    (qr qs : ℕ) (table : Memo K Digest) (out : C10ObservedGame × Memo K Digest)
    (supported : out ∈ (c10ObservedGame encode cfg publicSeed adversary qr qs table).support)
    (win : out.1.driver.accepted = true) :
    ∃ records, C10SigningHistory encode out.2 (sessionConfigAt cfg out.1.key)
      out.1.driver.session.exposures records ∧ records.length ≤ qs ∧
      (¬ PublicNodeCollisionFree (fun key => encode (.inl key)) out.2 ∨
        PublicNodeZero (fun key => out.2 (encode (.inl key))) ∨
        ∃ opening, TopChainRecordValid encode out.2 out.1.key.1 out.1.key.2
          out.1.driver.session.session.value.1 out.1.driver.session.session.value.2 opening ∧
          TopExposureCase encode out.2 out.1.key.1 out.1.driver.session.session.value.2 records opening) := by
  exact observed_output_top_exposure_cases encode cfg publicSeed qr qs out
    (c10_observed_output_witness encode cfg publicSeed adversary qr qs table out supported win)

theorem c10_initialized_independent_top_exposure_cases (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ)
    (out : C10ObservedGame × Memo WotsQuery Digest)
    (supported : out ∈ (c10ObservedInitializedIndependent cfg sampler qr qs).support)
    (win : out.1.driver.accepted = true) :
    ∃ records, C10SigningHistory id out.2 (sessionConfigAt cfg out.1.key)
      out.1.driver.session.exposures records ∧ records.length ≤ qs ∧
      (¬ PublicNodeCollisionFree Sum.inl out.2 ∨ PublicNodeZero (fun key => out.2 (.inl key)) ∨
        ∃ opening, TopChainRecordValid id out.2 out.1.key.1 out.1.key.2
          out.1.driver.session.session.value.1 out.1.driver.session.session.value.2 opening ∧
          TopExposureCase id out.2 out.1.key.1 out.1.driver.session.session.value.2 records opening) := by
  obtain ⟨input, _, _, witness⟩ := c10_observed_initialized_independent_witness cfg sampler qr qs out supported win
  exact observed_output_top_exposure_cases id cfg input.1 qr qs out witness

end
end C10Probability

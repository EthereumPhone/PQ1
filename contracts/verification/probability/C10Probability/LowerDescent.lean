import C10Probability.LowerExposureOpening
import C10Probability.TopExposureOpening

/-! Actual winning observed sessions descend through repeated upper words.
The branch keeps its prior actual signing record and equal lower root, then
compares the derived lower opening with the complete lower exposure history.
Public-node collision/zero and accepted-word collisions remain alternatives. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

def TopEarlierExposure (encode : WotsQuery → K) (table : Memo K Digest) (seed : ByteKey)
    (sig : C10Signature) (records : List C10SigningRecord) (opening : TopChainRecord) : Prop :=
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

def LowerDescentCase (encode : WotsQuery → K) (table : Memo K Digest) (seed : ByteKey)
    (sig : C10Signature) (records : List C10SigningRecord) (top : TopChainRecord) : Prop :=
  AcceptedWotsCollision (fun key => table (encode (.inl key))) ∨
    TopEarlierExposure encode table seed sig records top ∨
    ∃ prior ∈ records,
      hypertreeLeaf (hypertreeParent (hypertreeIndex prior.digest)) = top.kp ∧
      top.word = wotsOfDigest prior.upperDigest ∧
      ((sig.layers[1]?).getD emptyLayerSignature).sigma = prior.upper.sigma ∧
      top.middle = prior.middle ∧
      ∃ lower, LowerChainRecordValid encode table seed sig top lower ∧
        LowerExposureCase encode table seed sig records top lower

theorem top_chain_lower_descent (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entries : List C10Exposure) (records : List C10SigningRecord)
    (history : C10SigningHistory encode table cfg entries records) (message : ByteKey)
    (sig : C10Signature) (top : TopChainRecord)
    (valid : TopChainRecordValid encode table cfg.seed cfg.root message sig top)
    (width : cfg.seed.length = 32)
    (free : PublicNodeCollisionFree (fun key => encode (.inl key)) table)
    (nozero : ¬ PublicNodeZero (fun key => table (encode (.inl key)))) :
    LowerDescentCase encode table cfg.seed sig records top := by
  rcases top_chain_exposure_comparison encode table cfg entries records history message sig top valid with
    ⟨prior, member, address, word, sigma⟩ | earlier
  · obtain ⟨entry, _, signed⟩ := exposure_history_record_member encode table cfg entries records history prior member
    rcases repeated_upper_lower_opening encode table cfg entry prior signed message sig top valid width
      address word free nozero with collision | ⟨same, lower, lowerValid⟩
    · exact Or.inl collision
    · exact Or.inr (Or.inr ⟨prior, member, address, word, sigma, same, lower, lowerValid,
        lower_chain_exposure_comparison encode table cfg entries records history sig top lower lowerValid⟩)
  · exact Or.inr (Or.inl earlier)

theorem observed_output_lower_descent (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (publicSeed : Digest) (qr qs : ℕ) (out : C10ObservedGame × Memo K Digest)
    (witness : ObservedOutputWitness encode cfg publicSeed qr qs out) :
    ∃ records, C10SigningHistory encode out.2 (sessionConfigAt cfg out.1.key)
      out.1.driver.session.exposures records ∧ records.length ≤ qs ∧
      (¬ PublicNodeCollisionFree (fun key => encode (.inl key)) out.2 ∨
        PublicNodeZero (fun key => out.2 (encode (.inl key))) ∨
        ∃ top, TopChainRecordValid encode out.2 out.1.key.1 out.1.key.2
          out.1.driver.session.session.value.1 out.1.driver.session.session.value.2 top ∧
          LowerDescentCase encode out.2 out.1.key.1 out.1.driver.session.session.value.2 records top) := by
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
        exact Or.inr (Or.inr ⟨top, valid, top_chain_lower_descent encode out.2
          (sessionConfigAt cfg out.1.key) out.1.driver.session.exposures records history
          out.1.driver.session.session.value.1 out.1.driver.session.session.value.2 top valid
          witness.seed_width free zero⟩)
  · exact Or.inl free

theorem c10_observed_game_lower_descent [DecidableEq K] (encode : WotsQuery → K)
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
          LowerDescentCase encode out.2 out.1.key.1 out.1.driver.session.session.value.2 records top) := by
  exact observed_output_lower_descent encode cfg publicSeed qr qs out
    (c10_observed_output_witness encode cfg publicSeed adversary qr qs table out supported win)

theorem c10_initialized_independent_lower_descent (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ)
    (out : C10ObservedGame × Memo WotsQuery Digest)
    (supported : out ∈ (c10ObservedInitializedIndependent cfg sampler qr qs).support)
    (win : out.1.driver.accepted = true) :
    ∃ records, C10SigningHistory id out.2 (sessionConfigAt cfg out.1.key)
      out.1.driver.session.exposures records ∧ records.length ≤ qs ∧
      (¬ PublicNodeCollisionFree Sum.inl out.2 ∨ PublicNodeZero (fun key => out.2 (.inl key)) ∨
        ∃ top, TopChainRecordValid id out.2 out.1.key.1 out.1.key.2
          out.1.driver.session.session.value.1 out.1.driver.session.session.value.2 top ∧
          LowerDescentCase id out.2 out.1.key.1 out.1.driver.session.session.value.2 records top) := by
  obtain ⟨input, _, _, witness⟩ := c10_observed_initialized_independent_witness cfg sampler qr qs out supported win
  exact observed_output_lower_descent id cfg input.1 qr qs out witness

end
end C10Probability


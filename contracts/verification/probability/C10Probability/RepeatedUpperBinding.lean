import C10Probability.CountMessageBinding
import C10Probability.TopChainRecord
import C10Probability.C10ExposureHistory

/-! Repeated upper words are compared at their actual selected count inputs.
The collision alternative is retained; equality of messages is a conclusion.
The address relation also identifies the prior actual lower tree, even when
the two signatures select different leaves in that tree. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem signing_record_upper_count_lookup (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entry : C10Exposure) (prior : C10SigningRecord)
    (valid : C10SigningRecordValid encode table cfg entry prior) :
    table (encode (.inl (wotsRecoverCountInput cfg.seed 1 0
      (hypertreeLeaf (hypertreeParent (hypertreeIndex prior.digest))) (nodeValueBytes prior.middle)
      prior.upper.count))) = some prior.upperDigest := by
  exact (replay_wots_count_success (fun key => encode (.inl key)) table cfg.seed 1 0
    (hypertreeLeaf (hypertreeParent (hypertreeIndex prior.digest))) (nodeValueBytes prior.middle)
    0 cfg.wTrials (by simpa using cfg.wBound) prior.upper.count prior.upperDigest valid.upper_count).2.2.1

theorem signing_record_lower_count_lookup (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entry : C10Exposure) (prior : C10SigningRecord)
    (valid : C10SigningRecordValid encode table cfg entry prior) :
    table (encode (.inl (wotsRecoverCountInput cfg.seed 0
      (hypertreeParent (hypertreeIndex prior.digest)) (hypertreeLeaf (hypertreeIndex prior.digest))
      (nodeValueBytes prior.forest.pk) prior.lower.count))) = some prior.lowerDigest := by
  exact (replay_wots_count_success (fun key => encode (.inl key)) table cfg.seed 0
    (hypertreeParent (hypertreeIndex prior.digest)) (hypertreeLeaf (hypertreeIndex prior.digest))
    (nodeValueBytes prior.forest.pk) 0 cfg.wTrials (by simpa using cfg.wBound)
    prior.lower.count prior.lowerDigest valid.lower_count).2.2.1

theorem repeated_upper_message_cases (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entry : C10Exposure) (prior : C10SigningRecord)
    (signed : C10SigningRecordValid encode table cfg entry prior)
    (message : ByteKey) (sig : C10Signature) (opening : TopChainRecord)
    (valid : TopChainRecordValid encode table cfg.seed cfg.root message sig opening)
    (address : hypertreeLeaf (hypertreeParent (hypertreeIndex prior.digest)) = opening.kp)
    (word : opening.word = wotsOfDigest prior.upperDigest) :
    opening.middle = prior.middle ∨ AcceptedWotsCollision (fun key => table (encode (.inl key))) := by
  have lookup := signing_record_upper_count_lookup encode table cfg entry prior signed
  rw [address] at lookup
  exact accepted_count_message_cases (fun key => table (encode (.inl key))) cfg.seed 1 0
    opening.kp opening.middle prior.middle ((sig.layers[1]?).getD emptyLayerSignature).count
    prior.upper.count opening.countDigest prior.upperDigest valid.count lookup valid.accepted word

theorem repeated_upper_lower_tree_eq (prior : C10SigningRecord) (opening : TopChainRecord)
    (address : hypertreeLeaf (hypertreeParent (hypertreeIndex prior.digest)) = opening.kp) :
    hypertreeParent (hypertreeIndex prior.digest) = hypertreeParent (hypertreeIndex opening.digest) := by
  simpa only [TopChainRecord.kp, hypertree_top_leaf_eq_parent] using address

end
end C10Probability

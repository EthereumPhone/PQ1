import C10Probability.LowerChainOpening
import C10Probability.C10AddressStability

/-! A repeated lower word binds the actual forest message only after retaining
the accepted-word collision alternative. Both lower coordinates identify the
complete hypertree address of the prior executed forest signing program. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem repeated_lower_message_cases (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entry : C10Exposure) (prior : C10SigningRecord)
    (signed : C10SigningRecordValid encode table cfg entry prior)
    (sig : C10Signature) (top : TopChainRecord) (lower : LowerChainRecord)
    (valid : LowerChainRecordValid encode table cfg.seed sig top lower)
    (tree : hypertreeParent (hypertreeIndex prior.digest) = top.lowerTree)
    (leaf : hypertreeLeaf (hypertreeIndex prior.digest) = top.lowerKp)
    (word : lower.word = wotsOfDigest prior.lowerDigest) :
    top.forest = prior.forest.pk ∨ AcceptedWotsCollision (fun key => table (encode (.inl key))) := by
  have lookup := signing_record_lower_count_lookup encode table cfg entry prior signed
  rw [tree, leaf] at lookup
  exact accepted_count_message_cases (fun key => table (encode (.inl key))) cfg.seed 0
    top.lowerTree top.lowerKp top.forest prior.forest.pk
    ((sig.layers[0]?).getD emptyLayerSignature).count prior.lower.count
    lower.countDigest prior.lowerDigest valid.count lookup valid.accepted word

theorem repeated_lower_hypertree_eq (prior : C10SigningRecord) (top : TopChainRecord)
    (tree : hypertreeParent (hypertreeIndex prior.digest) = top.lowerTree)
    (leaf : hypertreeLeaf (hypertreeIndex prior.digest) = top.lowerKp) :
    hypertreeIndex prior.digest = hypertreeIndex top.digest := by
  exact hypertree_equal_lower_coordinates _ _ tree leaf

theorem repeated_lower_forest_binding (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entry : C10Exposure) (prior : C10SigningRecord)
    (signed : C10SigningRecordValid encode table cfg entry prior)
    (sig : C10Signature) (top : TopChainRecord) (lower : LowerChainRecord)
    (valid : LowerChainRecordValid encode table cfg.seed sig top lower)
    (tree : hypertreeParent (hypertreeIndex prior.digest) = top.lowerTree)
    (leaf : hypertreeLeaf (hypertreeIndex prior.digest) = top.lowerKp)
    (word : lower.word = wotsOfDigest prior.lowerDigest) :
    AcceptedWotsCollision (fun key => table (encode (.inl key))) ∨
      (hypertreeIndex prior.digest = hypertreeIndex top.digest ∧
        top.forest = prior.forest.pk ∧
        replayProgram table (forestSignProgram encode cfg.seed (hypertreeIndex top.digest)
          prior.digest entry.request.shuffle) = some prior.forest) := by
  rcases repeated_lower_message_cases encode table cfg entry prior signed sig top lower valid
    tree leaf word with same | collision
  · have address := repeated_lower_hypertree_eq prior top tree leaf
    exact Or.inr ⟨address, same, by simpa only [address] using signed.forest⟩
  · exact Or.inl collision

end
end C10Probability

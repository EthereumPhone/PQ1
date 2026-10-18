import C10Probability.ForestHistoryOpening
import C10Probability.LowerDescent

/-! Repeated upper and lower WOTS words descend to actual FORS openings and
complete-history comparison. Both earlier-chain alternatives and accepted-word
collisions survive; no probability charge or raw-query secrecy is inferred. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

def LowerEarlierExposure (encode : WotsQuery → K) (table : Memo K Digest) (seed : ByteKey)
    (sig : C10Signature) (records : List C10SigningRecord) (top : TopChainRecord)
    (lower : LowerChainRecord) : Prop :=
  ∃ i, (lower.word i).val < wotsExposureMinimum (lowerExposureWords records top.lowerTree top.lowerKp) i ∧
    (lower.word i).val < 7 ∧
    replayProgram table (wotsSeedChainProgram encode seed 0 top.lowerTree top.lowerKp i.val
      (lower.word i).val) = some (((sig.layers[0]?).getD emptyLayerSignature).sigma i) ∧
    ∀ prior ∈ records, hypertreeParent (hypertreeIndex prior.digest) = top.lowerTree ∧
      hypertreeLeaf (hypertreeIndex prior.digest) = top.lowerKp →
      (lower.word i).val < (wotsOfDigest prior.lowerDigest i).val ∧
      replayProgram table (chainProgram (fun position value => encode (.inl
        (wotsChainInput seed 0 top.lowerTree top.lowerKp i.val position value))) randomizerOfDigest
        (lower.word i).val ((wotsOfDigest prior.lowerDigest i).val - (lower.word i).val)
        (((sig.layers[0]?).getD emptyLayerSignature).sigma i)) = some (prior.lower.sigma i)

def RepeatedLowerForest (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entries : List C10Exposure) (sig : C10Signature)
    (records : List C10SigningRecord) (top : TopChainRecord) (lower : LowerChainRecord) : Prop :=
  ∃ prior ∈ records, ∃ entry ∈ entries, C10SigningRecordValid encode table cfg entry prior ∧
    hypertreeParent (hypertreeIndex prior.digest) = top.lowerTree ∧
    hypertreeLeaf (hypertreeIndex prior.digest) = top.lowerKp ∧
    lower.word = wotsOfDigest prior.lowerDigest ∧
    ((sig.layers[0]?).getD emptyLayerSignature).sigma = prior.lower.sigma ∧
    hypertreeIndex prior.digest = hypertreeIndex top.digest ∧ top.forest = prior.forest.pk ∧
    ∃ opening, ForestOpeningRecordValid encode table cfg.seed (hypertreeIndex top.digest) top.digest
      sig.secrets sig.auths top.forest prior.digest entry.request.shuffle prior.forest opening ∧
      ForestHistoryCase encode table cfg entries records top.digest sig.secrets

def ForestDescentCase (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entries : List C10Exposure) (sig : C10Signature)
    (records : List C10SigningRecord) (top : TopChainRecord) : Prop :=
  AcceptedWotsCollision (fun key => table (encode (.inl key))) ∨
    TopEarlierExposure encode table cfg.seed sig records top ∨
    ∃ prior ∈ records,
      hypertreeLeaf (hypertreeParent (hypertreeIndex prior.digest)) = top.kp ∧
      top.word = wotsOfDigest prior.upperDigest ∧
      ((sig.layers[1]?).getD emptyLayerSignature).sigma = prior.upper.sigma ∧
      top.middle = prior.middle ∧ ∃ lower, LowerChainRecordValid encode table cfg.seed sig top lower ∧
        (LowerEarlierExposure encode table cfg.seed sig records top lower ∨
          RepeatedLowerForest encode table cfg entries sig records top lower)

theorem lower_exposure_forest_descent (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entries : List C10Exposure) (records : List C10SigningRecord)
    (history : C10SigningHistory encode table cfg entries records) (message : ByteKey)
    (sig : C10Signature) (top : TopChainRecord) (lower : LowerChainRecord)
    (topValid : TopChainRecordValid encode table cfg.seed cfg.root message sig top)
    (lowerValid : LowerChainRecordValid encode table cfg.seed sig top lower)
    (cases : LowerExposureCase encode table cfg.seed sig records top lower)
    (width : cfg.seed.length = 32)
    (free : PublicNodeCollisionFree (fun key => encode (.inl key)) table) :
    AcceptedWotsCollision (fun key => table (encode (.inl key))) ∨
      LowerEarlierExposure encode table cfg.seed sig records top lower ∨
      RepeatedLowerForest encode table cfg entries sig records top lower := by
  rcases cases with ⟨prior, member, tree, leaf, word, sigma⟩ | earlier
  · obtain ⟨entry, entryMember, signed⟩ :=
      exposure_history_record_member encode table cfg entries records history prior member
    rcases repeated_lower_forest_opening encode table cfg entry prior signed message sig top lower
      topValid lowerValid tree leaf word width free with collision | ⟨address, same, opening, valid⟩
    · exact Or.inl collision
    · exact Or.inr (Or.inr ⟨prior, member, entry, entryMember, signed, tree, leaf, word, sigma,
        address, same, opening, valid, forest_opening_history_comparison encode table cfg entries
          records history top.digest sig.secrets sig.auths top.forest prior.digest entry.request.shuffle
          prior.forest opening valid⟩)
  · exact Or.inr (Or.inl earlier)

theorem top_chain_forest_descent (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entries : List C10Exposure) (records : List C10SigningRecord)
    (history : C10SigningHistory encode table cfg entries records) (message : ByteKey)
    (sig : C10Signature) (top : TopChainRecord)
    (valid : TopChainRecordValid encode table cfg.seed cfg.root message sig top)
    (width : cfg.seed.length = 32)
    (free : PublicNodeCollisionFree (fun key => encode (.inl key)) table)
    (nozero : ¬ PublicNodeZero (fun key => table (encode (.inl key)))) :
    ForestDescentCase encode table cfg entries sig records top := by
  rcases top_chain_lower_descent encode table cfg entries records history message sig top valid
    width free nozero with collision | earlier | repeated
  · exact Or.inl collision
  · exact Or.inr (Or.inl earlier)
  · obtain ⟨prior, member, address, word, sigma, same, lower, lowerValid, cases⟩ := repeated
    rcases lower_exposure_forest_descent encode table cfg entries records history message sig top lower
      valid lowerValid cases width free with collision | descent
    · exact Or.inl collision
    · exact Or.inr (Or.inr ⟨prior, member, address, word, sigma, same, lower, lowerValid, descent⟩)

end
end C10Probability

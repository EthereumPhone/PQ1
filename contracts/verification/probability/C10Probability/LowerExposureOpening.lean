import C10Probability.LowerChainOpening
import C10Probability.C10ExposureMinimum

/-! Compare a derived lower-chain opening with every successful signature at
its actual lower address. Duplicates remain present, the empty history has
minimum seven, and every strict earlier position carries actual suffix replay
to every matching prior value. No secrecy conclusion is asserted. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

def LowerExposureCase (encode : WotsQuery → K) (table : Memo K Digest) (seed : ByteKey)
    (sig : C10Signature) (records : List C10SigningRecord) (opening : TopChainRecord) (lower : LowerChainRecord) : Prop :=
  (∃ prior ∈ records, hypertreeParent (hypertreeIndex prior.digest) = opening.lowerTree ∧
      hypertreeLeaf (hypertreeIndex prior.digest) = opening.lowerKp ∧
    lower.word = wotsOfDigest prior.lowerDigest ∧
    ((sig.layers[0]?).getD emptyLayerSignature).sigma = prior.lower.sigma) ∨
  ∃ i, (lower.word i).val < wotsExposureMinimum (lowerExposureWords records opening.lowerTree opening.lowerKp) i ∧
    (lower.word i).val < 7 ∧
    replayProgram table (wotsSeedChainProgram encode seed 0 opening.lowerTree opening.lowerKp i.val
      (lower.word i).val) = some (((sig.layers[0]?).getD emptyLayerSignature).sigma i) ∧
    ∀ prior ∈ records, hypertreeParent (hypertreeIndex prior.digest) = opening.lowerTree ∧
      hypertreeLeaf (hypertreeIndex prior.digest) = opening.lowerKp →
      (lower.word i).val < (wotsOfDigest prior.lowerDigest i).val ∧
      replayProgram table (chainProgram (fun position value => encode (.inl
        (wotsChainInput seed 0 opening.lowerTree opening.lowerKp i.val position value))) randomizerOfDigest
        (lower.word i).val ((wotsOfDigest prior.lowerDigest i).val - (lower.word i).val)
        (((sig.layers[0]?).getD emptyLayerSignature).sigma i)) = some (prior.lower.sigma i)

theorem lower_chain_exposure_comparison (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entries : List C10Exposure) (records : List C10SigningRecord)
    (history : C10SigningHistory encode table cfg entries records)
    (sig : C10Signature) (opening : TopChainRecord) (lower : LowerChainRecord)
    (valid : LowerChainRecordValid encode table cfg.seed sig opening lower) :
    LowerExposureCase encode table cfg.seed sig records opening lower := by
  rcases lower_exposure_minimum_comparison encode table cfg entries records history
    opening.lowerTree opening.lowerKp lower.word valid.accepted with same | earlier
  · obtain ⟨prior, member, tree, address, word⟩ := same
    obtain ⟨_, _, priorValid⟩ := exposure_history_record_member encode table cfg entries records history prior member
    have positions := priorValid.lower_prefixes
    rw [tree, address, ← word] at positions
    exact Or.inl ⟨prior, member, tree, address, word,
      wots_same_word_prefixes_eq encode table cfg.seed 0 opening.lowerTree opening.lowerKp lower.word
        ((sig.layers[0]?).getD emptyLayerSignature).sigma prior.lower.sigma valid.prefixes positions⟩
  · obtain ⟨i, cut⟩ := earlier
    obtain ⟨endpoint, allPrior⟩ := (wots_below_exposure_minimum_iff
      (lowerExposureWords records opening.lowerTree opening.lowerKp) i (lower.word i).val).mp cut
    refine Or.inr ⟨i, cut, endpoint, valid.prefixes i, ?_⟩
    intro prior member both
    obtain ⟨tree, address⟩ := both
    obtain ⟨_, _, priorValid⟩ := exposure_history_record_member encode table cfg entries records history prior member
    have positions := priorValid.lower_prefixes
    rw [tree, address] at positions
    have priorMember := (mem_lower_exposure_words records opening.lowerTree opening.lowerKp (wotsOfDigest prior.lowerDigest)).mpr
      ⟨prior, member, tree, address, rfl⟩
    have earlier := allPrior _ priorMember
    exact ⟨earlier, replay_wots_seed_chain_between encode table cfg.seed 0 opening.lowerTree opening.lowerKp i.val
      (lower.word i).val (wotsOfDigest prior.lowerDigest i).val
      (((sig.layers[0]?).getD emptyLayerSignature).sigma i) (prior.lower.sigma i)
      (Nat.le_of_lt earlier) (valid.prefixes i) (positions i)⟩

end
end C10Probability

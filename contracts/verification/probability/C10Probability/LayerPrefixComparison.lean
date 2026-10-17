import C10Probability.LayerSigningReplay
import C10Probability.WotsPrefixComparison

/-! Compare a recovered component with an actual successful layer signature
at the same address. The equal-word branch is retained for the later encoding
argument; an earlier chain position is not itself a secrecy bound. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem layer_chain_prefix_comparison (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (priorMessage : Randomizer) (shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) (prior : LayerSignature) (root : Randomizer)
    (witness : LayerChainWitness encode table seed layer tree kp priorMessage shuffle n bound prior root)
    (word : WotsWord) (sigma : WotsSigma) (accepted : wotsAccept word = true)
    (recorded : ∀ i, replayProgram table (wotsSeedChainProgram encode seed layer tree kp i.val
      (word i).val) = some (sigma i)) :
    ∃ digest,
      replayProgram table (mapProgram (fun key => encode (.inl key))
        (wotsCountProgram seed layer tree kp (nodeValueBytes priorMessage) 0 n
          (by simpa using bound))) = some (some (prior.count, digest)) ∧
      wotsAccept (wotsOfDigest digest) = true ∧
      ((word = wotsOfDigest digest ∧ sigma = prior.sigma) ∨
        ∃ i, (word i).val < (wotsOfDigest digest i).val ∧
          replayProgram table (wotsSeedChainProgram encode seed layer tree kp i.val
            (word i).val) = some (sigma i) ∧
          replayProgram table (chainProgram (fun position value => encode (.inl
            (wotsChainInput seed layer tree kp i.val position value))) randomizerOfDigest
            (word i).val ((wotsOfDigest digest i).val - (word i).val) (sigma i)) = some (prior.sigma i)) := by
  obtain ⟨_, _, digest, _, _, counted, accepted', positions⟩ := witness
  exact ⟨digest, counted, accepted', wots_accepted_prefix_comparison encode table seed
    layer tree kp word (wotsOfDigest digest) sigma prior.sigma accepted accepted' recorded positions⟩

theorem wots_prefix_proper_cut (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (word : WotsWord) (sigma : WotsSigma)
    (accepted : wotsAccept word = true)
    (recorded : ∀ i, replayProgram table (wotsSeedChainProgram encode seed layer tree kp i.val
      (word i).val) = some (sigma i)) :
    ∃ i, (word i).val < 7 ∧ replayProgram table
      (wotsSeedChainProgram encode seed layer tree kp i.val (word i).val) = some (sigma i) := by
  obtain ⟨i, cut⟩ := wots_accepted_word_proper_cut word accepted
  exact ⟨i, cut, recorded i⟩

end
end C10Probability

import C10Probability.WotsHonest
import C10Probability.CountReplay

/-! Actual successful WOTS signing and an actual generated leaf imply recovery
of that leaf. The returned count's range and accepted lookup are conclusions
of the signer, rather than assumptions about the signature supplied to recovery. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem replay_wots_sign_recovery (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (message shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) (sigma : WotsSigma) (count : ℕ) (leaf : Randomizer)
    (signed : replayProgram table
      (wotsSignProgram encode seed layer tree kp message shuffle n bound) = some (some (sigma, count)))
    (generated : replayProgram table (wotsLeafProgram encode seed layer tree kp) = some leaf) :
    count < n ∧ replayProgram table (wotsRecoveryUnderProgram (fun key => encode (.inl key))
      seed layer tree kp message sigma count) = some leaf := by
  obtain ⟨digest, counted, accepted, prefixes⟩ := replay_wots_sign_witness encode table
    seed layer tree kp message shuffle n bound sigma count signed
  obtain ⟨_, range, lookup, _⟩ := replay_wots_count_success (fun key => encode (.inl key))
    table seed layer tree kp message 0 n (by simpa using bound) count digest counted
  refine ⟨by simpa only [Nat.zero_add] using range, ?_⟩
  rw [wotsRecoveryUnderProgram, replay_program_cached table _ _ digest lookup]
  exact replay_wots_recovery_after_leaf encode table seed layer tree kp sigma digest leaf
    accepted prefixes generated

end
end C10Probability

import C10Probability.ChainReplay
import C10Probability.WotsInputBinding
import C10Probability.NodePathBinding

/-! A recovered chain endpoint binds the submitted node to the actual
private-seeded prefix at its digit, unless the selected public cache has a
node collision. This says nothing about whether that prefix was disclosed. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem replay_wots_chain_start_eq (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp index start steps : ℕ)
    (first second endpoint : Randomizer) (width : seed.length = 32)
    (free : PublicNodeCollisionFree encode table)
    (recorded : replayProgram table
      (chainProgram (fun position value => encode (wotsChainInput seed layer tree kp index position value))
        randomizerOfDigest start steps first) = some endpoint)
    (recorded' : replayProgram table
      (chainProgram (fun position value => encode (wotsChainInput seed layer tree kp index position value))
        randomizerOfDigest start steps second) = some endpoint) : first = second := by
  apply replay_chain_start_eq table _ randomizerOfDigest _ start steps first second endpoint
    recorded recorded'
  intro position left right firstReply secondReply hl hr same
  apply wots_chain_input_injective seed layer tree kp index position
  exact free _ _ firstReply secondReply
    (by simpa only [selectedCache, wots_chain_input_selected _ _ _ _ _ _ _ width, ↓reduceIte] using hl)
    (by simpa only [selectedCache, wots_chain_input_selected _ _ _ _ _ _ _ width, ↓reduceIte] using hr) same

theorem replay_wots_seed_chain_cut (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp index steps cut : ℕ) (endpoint : Randomizer)
    (bound : cut ≤ steps)
    (recorded : replayProgram table
      (wotsSeedChainProgram encode seed layer tree kp index steps) = some endpoint) :
    ∃ middle, replayProgram table
      (wotsSeedChainProgram encode seed layer tree kp index cut) = some middle ∧
      replayProgram table
        (chainProgram (fun position value => encode (.inl
          (wotsChainInput seed layer tree kp index position value))) randomizerOfDigest
          cut (steps - cut) middle) = some endpoint := by
  unfold wotsSeedChainProgram at recorded ⊢
  cases hd : table (encode (.inr (wotsPrivateTail layer tree kp index))) with
  | none => simp only [replayProgram, hd, Option.bind_none] at recorded; cases recorded
  | some digest =>
    rw [replay_program_cached table _ _ digest hd] at recorded
    obtain ⟨middle, hp, suffix⟩ := replay_chain_prefix table _ randomizerOfDigest
      0 steps cut (randomizerOfDigest digest) endpoint bound recorded
    refine ⟨middle, ?_, ?_⟩
    · rw [replay_program_cached table _ _ digest hd]
      exact hp
    · simpa only [Nat.zero_add] using suffix

theorem replay_wots_recovery_chain_reference (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp index cut : ℕ) (submitted endpoint : Randomizer)
    (width : seed.length = 32) (bound : cut ≤ 7)
    (free : PublicNodeCollisionFree (fun key => encode (.inl key)) table)
    (reference : replayProgram table
      (wotsSeedChainProgram encode seed layer tree kp index 7) = some endpoint)
    (recovery : replayProgram table
      (chainProgram (fun position value => encode (.inl
        (wotsChainInput seed layer tree kp index position value))) randomizerOfDigest
        cut (7 - cut) submitted) = some endpoint) :
    replayProgram table (wotsSeedChainProgram encode seed layer tree kp index cut) = some submitted := by
  obtain ⟨middle, hp, suffix⟩ := replay_wots_seed_chain_cut encode table seed
    layer tree kp index 7 cut endpoint bound reference
  have same := replay_wots_chain_start_eq (fun key => encode (.inl key)) table seed
    layer tree kp index cut (7 - cut) middle submitted endpoint width free suffix recovery
  exact same ▸ hp

end
end C10Probability

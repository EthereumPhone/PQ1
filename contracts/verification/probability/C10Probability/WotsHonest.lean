import C10Probability.WotsSigningReplay
import C10Probability.WotsPrefixComparison
import C10Probability.WotsRecoveryUnder

/-! Forward recovery of actual private-seeded WOTS prefixes. The independently
recorded generated leaf supplies the full chains and compression lookup. This
uses functional cache consistency, with no collision or freshness premise. -/
namespace C10Probability
noncomputable section

variable {I K α N : Type*}

theorem replay_chain_collection_assemble (table : Memo K α)
    (input : I → ℕ → N → K) (project : α → N) (starts steps : I → ℕ)
    (values endpoints : I → N) (indices : List I)
    (recorded : ∀ i ∈ indices, replayProgram table
      (chainProgram (input i) project (starts i) (steps i) (values i)) = some (endpoints i)) :
    replayProgram table (chainCollectionProgram input project starts steps values indices) =
      some (indices.map endpoints) := by
  induction indices with
  | nil => rfl
  | cons i rest ih =>
    have head := recorded i (List.mem_cons_self ..)
    have tail := ih (fun j member => recorded j (List.mem_cons_of_mem i member))
    simp only [chainCollectionProgram, replay_program_cast, replay_program_bind,
      replay_program_map_return, head, Option.bind_some, tail, Option.map_some, List.map_cons]

theorem replay_wots_accepted_chains_forward (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree kp : ℕ)
    (word : WotsWord) (accepted : wotsAccept word = true) (sigma endpoints : WotsSigma)
    (prefixes : ∀ i, replayProgram table (wotsSeedChainProgram encode seed layer tree kp i.val
      (word i).val) = some (sigma i))
    (full : ∀ i, replayProgram table (wotsSeedChainProgram encode seed layer tree kp i.val 7) =
      some (endpoints i)) :
    replayProgram table (mapProgram (fun key => encode (.inl key))
      (wotsAcceptedChainsProgram seed layer tree kp word accepted sigma)) =
      some (List.ofFn endpoints) := by
  have suffixes : ∀ i : Fin 43, replayProgram table (chainProgram
      (fun position value => encode (.inl (wotsChainInput seed layer tree kp i.val position value)))
      randomizerOfDigest (word i).val (7 - (word i).val) (sigma i)) = some (endpoints i) := by
    intro i
    exact replay_wots_seed_chain_between encode table seed layer tree kp i.val
      (word i).val 7 (sigma i) (endpoints i) (by have h := (word i).isLt; omega)
      (prefixes i) (full i)
  rw [wotsAcceptedChainsProgram, mapProgram_cast, replay_program_cast]
  change replayProgram table (mapProgram (fun key => encode (.inl key))
    (chainCollectionProgram (fun i : Fin 43 => wotsChainInput seed layer tree kp i.val)
      randomizerOfDigest (fun i => (word i).val) (fun i => 7 - (word i).val) sigma wotsIndices)) = _
  rw [chain_collection_program_map]
  have assembled := replay_chain_collection_assemble table
    (fun (i : Fin 43) position value => encode (.inl
      (wotsChainInput seed layer tree kp i.val position value))) randomizerOfDigest
    (fun i => (word i).val) (fun i => 7 - (word i).val) sigma endpoints wotsIndices
    (fun i _ => suffixes i)
  simpa only [wotsIndices, List.map_ofFn, Function.comp_def, id_eq] using assembled

theorem replay_wots_recovery_after_leaf (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree kp : ℕ)
    (sigma : WotsSigma) (digest : Digest) (leaf : Randomizer)
    (accepted : wotsAccept (wotsOfDigest digest) = true)
    (prefixes : ∀ i, replayProgram table (wotsSeedChainProgram encode seed layer tree kp i.val
      (wotsOfDigest digest i).val) = some (sigma i))
    (generated : replayProgram table (wotsLeafProgram encode seed layer tree kp) = some leaf) :
    replayProgram table (mapProgram (fun key => encode (.inl key))
      (wotsRecoveryAfter seed layer tree kp sigma digest)) = some leaf := by
  obtain ⟨endpoints, reply, full, compressed, value⟩ :=
    replay_wots_leaf_witness encode table seed layer tree kp leaf generated
  rw [wotsRecoveryAfter, dif_pos accepted, mapProgram_bind, replay_program_bind,
    replay_wots_accepted_chains_forward encode table seed layer tree kp
      (wotsOfDigest digest) accepted sigma endpoints prefixes full, Option.bind_some]
  simp only [wotsCompressProgram, mapProgram, replayProgram, compressed, Option.bind_some, value]

end
end C10Probability

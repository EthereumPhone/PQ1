import C10Probability.WotsChainBinding
import C10Probability.WotsFillReplay
import C10Probability.WotsRecoveryReplay
import C10Probability.RecoveryWitness

/-! An accepted actual recovery of the key-generation leaf binds every
submitted signature position to its private-seeded chain prefix. Collision
freedom is confined to the selected public-node domain in the same cache. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem replay_wots_compression_witness (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (values : List Randomizer) (leaf : Randomizer)
    (recorded : replayProgram table (mapProgram encode
      (wotsCompressProgram seed layer tree kp values)) = some leaf) :
    ∃ digest, table (encode (wotsPkInput seed layer tree kp values)) = some digest ∧
      randomizerOfDigest digest = leaf := by
  cases h : table (encode (wotsPkInput seed layer tree kp values)) with
  | none => simp only [wotsCompressProgram, mapProgram, replayProgram, h, Option.bind_none] at recorded; cases recorded
  | some digest =>
    simp only [wotsCompressProgram, mapProgram, replayProgram, h, Option.bind_some,
      Option.some.injEq] at recorded
    exact ⟨digest, rfl, recorded⟩

theorem wots_compression_values_eq (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (first second : List Randomizer)
    (firstDigest secondDigest : Digest) (width : seed.length = 32)
    (firstLength : first.length = 43) (secondLength : second.length = 43)
    (free : PublicNodeCollisionFree encode table)
    (hf : table (encode (wotsPkInput seed layer tree kp first)) = some firstDigest)
    (hs : table (encode (wotsPkInput seed layer tree kp second)) = some secondDigest)
    (equal : randomizerOfDigest firstDigest = randomizerOfDigest secondDigest) : first = second := by
  apply wots_pk_input_injective seed layer tree kp
  exact free _ _ firstDigest secondDigest
    (by simpa only [selectedCache, wots_pk_input_selected _ _ _ _ _ width firstLength, ↓reduceIte] using hf)
    (by simpa only [selectedCache, wots_pk_input_selected _ _ _ _ _ width secondLength, ↓reduceIte] using hs) equal

theorem replay_wots_accepted_reference (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (message : ByteKey) (sigma : WotsSigma)
    (count : ℕ) (leaf : Randomizer) (digest : Digest) (width : seed.length = 32)
    (free : PublicNodeCollisionFree (fun key => encode (.inl key)) table)
    (counted : table (encode (.inl (wotsRecoverCountInput seed layer tree kp message count))) = some digest)
    (accepted : wotsAccept (wotsOfDigest digest) = true)
    (reference : replayProgram table (wotsLeafProgram encode seed layer tree kp) = some leaf)
    (recovery : replayProgram table (wotsRecoveryUnderProgram (fun key => encode (.inl key))
      seed layer tree kp message sigma count) = some leaf) :
    ∀ i, replayProgram table (wotsSeedChainProgram encode seed layer tree kp i.val
      (wotsOfDigest digest i).val) = some (sigma i) := by
  obtain ⟨actual, ha, branch⟩ := replay_wots_witness (fun key => encode (.inl key)) table
    seed layer tree kp message sigma count leaf recovery
  have sameDigest : actual = digest := Option.some.inj (ha.symm.trans counted)
  subst actual
  rcases branch with ⟨rejected, _⟩ | ⟨accepted', values, chains, compressed⟩
  · rw [accepted] at rejected
    cases rejected
  · obtain ⟨endpoints, referenceDigest, positions, referenceCompression, referenceLeaf⟩ :=
      replay_wots_leaf_witness encode table seed layer tree kp leaf reference
    obtain ⟨recoveredDigest, recoveredCompression, recoveredLeaf⟩ :=
      replay_wots_compression_witness (fun key => encode (.inl key)) table
        seed layer tree kp values leaf compressed
    have same := wots_compression_values_eq (fun key => encode (.inl key)) table
      seed layer tree kp values (List.ofFn endpoints) recoveredDigest referenceDigest width
      (replay_wots_recovery_length (fun key => encode (.inl key)) table seed layer tree kp
        (wotsOfDigest digest) accepted' sigma values chains)
      (List.length_ofFn) free recoveredCompression referenceCompression
      (recoveredLeaf.trans referenceLeaf.symm)
    rw [same] at chains
    intro i
    exact replay_wots_recovery_chain_reference encode table seed layer tree kp i.val
      (wotsOfDigest digest i).val (sigma i) (endpoints i) width
      (by have h := (wotsOfDigest digest i).isLt; omega) free (positions i)
      (replay_wots_recovery_endpoint (fun key => encode (.inl key)) table seed layer tree kp
        (wotsOfDigest digest) accepted' sigma endpoints chains i)

end
end C10Probability

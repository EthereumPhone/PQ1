import C10Probability.ForestCompressionBinding
import C10Probability.RepeatedLowerBinding

/-! Every ordinary submitted FORS secret is derived from a prior actually built
tree at the selected coordinate. The special last transmitted root remains
separate. All signing, recovery and private lookups share the same cache. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem forest_compression_position (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest priorDigest : Digest) (secrets : List Randomizer)
    (auths : List (List Randomizer)) (pk : Randomizer) (shuffle : ByteKey) (prior : ForestOutput)
    (recovery : ForestRecoveryRecord) (signing : ForestSigningRecord)
    (recovered : ForestRecoveryRecordValid (fun key => encode (.inl key)) table seed ht
      digest secrets auths pk recovery)
    (signed : ForestSigningRecordValid encode table seed ht priorDigest shuffle prior signing)
    (width : seed.length = 32) (free : PublicNodeCollisionFree (fun key => encode (.inl key)) table)
    (same : pk = prior.pk) (i : Fin 12) :
    (recovery.roots[i.val]?).getD 0 = (signing.state.roots[i.val]?).getD 0 := by
  have equal := (forest_compression_components encode table seed ht digest priorDigest secrets auths
    pk shuffle prior recovery signing recovered signed width free same).1
  rw [equal, List.getElem?_eq_getElem
    (by simpa only [List.length_map, forest_tree_indices_length] using i.isLt)]
  simp only [Option.getD_some, List.getElem_map, forestTreeIndices, List.getElem_ofFn, id_eq]

theorem forest_recovery_private_values (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest priorDigest : Digest) (secrets : List Randomizer)
    (auths : List (List Randomizer)) (pk : Randomizer) (shuffle : ByteKey) (prior : ForestOutput)
    (recovery : ForestRecoveryRecord) (signing : ForestSigningRecord)
    (recovered : ForestRecoveryRecordValid (fun key => encode (.inl key)) table seed ht
      digest secrets auths pk recovery)
    (signed : ForestSigningRecordValid encode table seed ht priorDigest shuffle prior signing)
    (width : seed.length = 32) (free : PublicNodeCollisionFree (fun key => encode (.inl key)) table)
    (same : pk = prior.pk) :
    ∀ i : Fin 12, ∃ value, table (encode (.inr (forsPrivateTail ht i.val
      (forestIndex digest i.val)))) = some value ∧
      randomizerOfDigest value = (secrets[i.val]?).getD 0 := by
  intro i
  have recoveredAt := recovered.positions i
  rw [forest_compression_position encode table seed ht digest priorDigest secrets auths pk
    shuffle prior recovery signing recovered signed width free same i] at recoveredAt
  exact fors_recovery_matches_certificate encode table seed ht i.val (forestIndex digest i.val)
    width (forest_index_bound digest i.val) ((signing.state.roots[i.val]?).getD 0)
    ((secrets[i.val]?).getD 0) ((auths[i.val]?).getD []) (signed.certificates i) free recoveredAt

structure ForestOpeningRecord where
  signing : ForestSigningRecord
  recovery : ForestRecoveryRecord

structure ForestOpeningRecordValid (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (secrets : List Randomizer)
    (auths : List (List Randomizer)) (pk : Randomizer) (priorDigest : Digest)
    (shuffle : ByteKey) (prior : ForestOutput) (opening : ForestOpeningRecord) : Prop where
  signing : ForestSigningRecordValid encode table seed ht priorDigest shuffle prior opening.signing
  recovery : ForestRecoveryRecordValid (fun key => encode (.inl key)) table seed ht
    digest secrets auths pk opening.recovery
  publicKey : pk = prior.pk
  ordinaryRoots : ∀ i : Fin 12,
    (opening.recovery.roots[i.val]?).getD 0 = (opening.signing.state.roots[i.val]?).getD 0
  privateValues : ∀ i : Fin 12, ∃ value,
    table (encode (.inr (forsPrivateTail ht i.val (forestIndex digest i.val)))) = some value ∧
      randomizerOfDigest value = (secrets[i.val]?).getD 0
  lastRoot : (secrets[12]?).getD 0 = opening.signing.last

theorem forest_opening_of_equal_pk (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest priorDigest : Digest) (secrets : List Randomizer)
    (auths : List (List Randomizer)) (pk : Randomizer) (shuffle : ByteKey) (prior : ForestOutput)
    (signing : replayProgram table (forestSignProgram encode seed ht priorDigest shuffle) = some prior)
    (recovery : replayProgram table (forestRecoverProgram (fun key => encode (.inl key))
      seed ht digest secrets auths) = some pk)
    (width : seed.length = 32) (free : PublicNodeCollisionFree (fun key => encode (.inl key)) table)
    (same : pk = prior.pk) :
    ∃ opening, ForestOpeningRecordValid encode table seed ht digest secrets auths pk
      priorDigest shuffle prior opening := by
  obtain ⟨signed, validSigning⟩ := replay_forest_sign_record encode table seed ht priorDigest shuffle prior signing
  obtain ⟨recovered, validRecovery⟩ := replay_forest_recover_record (fun key => encode (.inl key)) table
    seed ht digest secrets auths pk recovery
  exact ⟨⟨signed, recovered⟩, validSigning, validRecovery, same,
    forest_compression_position encode table seed ht digest priorDigest secrets auths pk shuffle prior
      recovered signed validRecovery validSigning width free same,
    forest_recovery_private_values encode table seed ht digest priorDigest secrets auths pk shuffle prior
      recovered signed validRecovery validSigning width free same,
    forest_recovery_last_root encode table seed ht digest priorDigest secrets auths pk shuffle prior
      recovered signed validRecovery validSigning width free same⟩

theorem repeated_lower_forest_opening (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entry : C10Exposure) (prior : C10SigningRecord)
    (signed : C10SigningRecordValid encode table cfg entry prior) (message : ByteKey)
    (sig : C10Signature) (top : TopChainRecord) (lower : LowerChainRecord)
    (topValid : TopChainRecordValid encode table cfg.seed cfg.root message sig top)
    (lowerValid : LowerChainRecordValid encode table cfg.seed sig top lower)
    (tree : hypertreeParent (hypertreeIndex prior.digest) = top.lowerTree)
    (leaf : hypertreeLeaf (hypertreeIndex prior.digest) = top.lowerKp)
    (word : lower.word = wotsOfDigest prior.lowerDigest)
    (width : cfg.seed.length = 32) (free : PublicNodeCollisionFree (fun key => encode (.inl key)) table) :
    AcceptedWotsCollision (fun key => table (encode (.inl key))) ∨
      (hypertreeIndex prior.digest = hypertreeIndex top.digest ∧
        top.forest = prior.forest.pk ∧ ∃ opening,
          ForestOpeningRecordValid encode table cfg.seed (hypertreeIndex top.digest) top.digest
            sig.secrets sig.auths top.forest prior.digest entry.request.shuffle prior.forest opening) := by
  rcases repeated_lower_forest_binding encode table cfg entry prior signed sig top lower lowerValid
    tree leaf word with collision | ⟨address, same, actualSigning⟩
  · exact Or.inl collision
  · exact Or.inr ⟨address, same, forest_opening_of_equal_pk encode table cfg.seed
      (hypertreeIndex top.digest) top.digest prior.digest sig.secrets sig.auths top.forest
      entry.request.shuffle prior.forest actualSigning topValid.forest width free same⟩

end
end C10Probability

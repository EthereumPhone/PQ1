import C10Probability.ForestSigningRecord
import C10Probability.WotsInputBinding
import C10Probability.NodePathBinding

/-! Equal actual forest outputs bind all thirteen ordered compression inputs
under the existing selected-node collision exclusion. The last transmitted
value is recovered as a built root, not an ordinary private FORS leaf. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem fors_pk_input_injective (seed : ByteKey) (ht : ℕ) :
    Function.Injective (forsPkInput seed ht) := by
  intro first second equal
  exact node_blocks_injective (List.append_cancel_left equal)

theorem forest_compression_roots_eq (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (first second : List Randomizer) (one two : Digest)
    (width : seed.length = 32) (firstLength : first.length = 13) (secondLength : second.length = 13)
    (free : PublicNodeCollisionFree encode table)
    (firstLookup : table (encode (forsPkInput seed ht first)) = some one)
    (secondLookup : table (encode (forsPkInput seed ht second)) = some two)
    (same : randomizerOfDigest one = randomizerOfDigest two) : first = second := by
  apply fors_pk_input_injective seed ht
  exact free _ _ one two
    (by simpa only [selectedCache, fors_pk_input_selected seed ht first width firstLength,
      ↓reduceIte] using firstLookup)
    (by simpa only [selectedCache, fors_pk_input_selected seed ht second width secondLength,
      ↓reduceIte] using secondLookup) same

theorem forest_compression_components (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest priorDigest : Digest) (secrets : List Randomizer)
    (auths : List (List Randomizer)) (pk : Randomizer) (shuffle : ByteKey) (prior : ForestOutput)
    (recovery : ForestRecoveryRecord) (signing : ForestSigningRecord)
    (recovered : ForestRecoveryRecordValid (fun key => encode (.inl key)) table seed ht
      digest secrets auths pk recovery)
    (signed : ForestSigningRecordValid encode table seed ht priorDigest shuffle prior signing)
    (width : seed.length = 32) (free : PublicNodeCollisionFree (fun key => encode (.inl key)) table)
    (same : pk = prior.pk) :
    recovery.roots = forestTreeIndices.map (fun i => (signing.state.roots[i.val]?).getD 0) ∧
      randomizerOfDigest recovery.lastDigest = randomizerOfDigest signing.lastDigest := by
  have equal := forest_compression_roots_eq (fun key => encode (.inl key)) table seed ht
    (recovery.roots ++ [randomizerOfDigest recovery.lastDigest])
    (signing.state.roots.set 12 (randomizerOfDigest signing.lastDigest))
    recovery.pkDigest signing.pkDigest width
    (by simp only [List.length_append, recovered.length, List.length_cons, List.length_nil])
    (by simpa only [List.length_set] using signed.shape.2.2.1) free
    recovered.compression signed.compression (recovered.publicKey.trans (same.trans signed.publicKey))
  rw [← forest_roots_complete signing.state.roots (randomizerOfDigest signing.lastDigest)
    signed.shape.2.2.1] at equal
  have lengths : recovery.roots.length =
      (forestTreeIndices.map (fun i => (signing.state.roots[i.val]?).getD 0)).length := by
    simp only [recovered.length, List.length_map, forest_tree_indices_length]
  refine ⟨List.append_inj_left equal lengths, ?_⟩
  simpa only [List.singleton_inj] using (List.append_inj_right equal lengths)

theorem forest_recovery_last_root (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest priorDigest : Digest) (secrets : List Randomizer)
    (auths : List (List Randomizer)) (pk : Randomizer) (shuffle : ByteKey) (prior : ForestOutput)
    (recovery : ForestRecoveryRecord) (signing : ForestSigningRecord)
    (recovered : ForestRecoveryRecordValid (fun key => encode (.inl key)) table seed ht
      digest secrets auths pk recovery)
    (signed : ForestSigningRecordValid encode table seed ht priorDigest shuffle prior signing)
    (width : seed.length = 32) (free : PublicNodeCollisionFree (fun key => encode (.inl key)) table)
    (same : pk = prior.pk) : (secrets[12]?).getD 0 = signing.last := by
  have equal := (forest_compression_components encode table seed ht digest priorDigest secrets auths
    pk shuffle prior recovery signing recovered signed width free same).2
  apply fors_leaf_input_injective seed ht 12 0
  exact free _ _ recovery.lastDigest signing.lastDigest
    (by simpa only [selectedCache, fors_leaf_input_selected seed ht 12 0 _ width,
      ↓reduceIte] using recovered.last)
    (by simpa only [selectedCache, fors_leaf_input_selected seed ht 12 0 _ width,
      ↓reduceIte] using signed.lastLeaf) equal

end
end C10Probability

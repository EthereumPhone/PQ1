import C10Probability.RootReference
import C10Probability.NodePathBinding

/-! Root comparisons now use certificates derived from actual builders.
Reference leaves and FORS private derivations are conclusions, not premises. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem merkle_recovery_matches_certificate (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree index : ℕ) (width : seed.length = 32) (bound : index < 512)
    (root leaf : Randomizer) (auth : List Randomizer)
    (certificate : MerkleTreeCertificate encode table seed layer tree root)
    (free : PublicNodeCollisionFree (fun key => encode (.inl key)) table)
    (recorded : replayProgram table
      (merkleRecoverProgram (fun key => encode (.inl key)) seed layer tree leaf index auth) = some root) :
    replayProgram table (wotsLeafProgram encode seed layer tree index) = some leaf := by
  obtain ⟨reference, path, hl, _, hp⟩ := merkle_certificate_reference encode table seed layer tree root certificate index bound
  have equal := merkle_recover_leaf_eq (fun key => encode (.inl key)) table seed layer tree index
    width free leaf reference root auth path recorded hp
  simpa only [equal] using hl

theorem fors_recovery_matches_certificate (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree index : ℕ) (width : seed.length = 32) (bound : index < 2048)
    (root secret : Randomizer) (auth : List Randomizer)
    (certificate : ForsTreeCertificate encode table seed ht tree root)
    (free : PublicNodeCollisionFree (fun key => encode (.inl key)) table)
    (recorded : replayProgram table
      (forsRecoverProgram (fun key => encode (.inl key)) seed ht tree index secret auth) = some root) :
    ∃ digest, table (encode (.inr (forsPrivateTail ht tree index))) = some digest ∧
      randomizerOfDigest digest = secret := by
  obtain ⟨reference, _, path, hs, _, _, hp⟩ := fors_certificate_reference encode table seed ht tree root certificate index bound
  have equal := fors_recover_secret_eq (fun key => encode (.inl key)) table seed ht tree index
    width free secret (randomizerOfDigest reference) root auth path recorded hp
  exact ⟨reference, hs, equal.symm⟩

theorem replay_wots_leaf_compression (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree index : ℕ) (leaf : Randomizer)
    (recorded : replayProgram table (wotsLeafProgram encode seed layer tree index) = some leaf) :
    ∃ sigma digest,
      replayProgram table (wotsLeafFillProgram encode seed layer tree index) = some sigma ∧
      table (encode (.inl (wotsPkInput seed layer tree index (List.ofFn sigma)))) = some digest ∧
      randomizerOfDigest digest = leaf := by
  rw [wotsLeafProgram, replay_program_bind] at recorded
  cases hs : replayProgram table (wotsLeafFillProgram encode seed layer tree index) with
  | none => simp only [hs, Option.bind_none] at recorded; cases recorded
  | some sigma =>
    simp only [hs, Option.bind_some] at recorded
    cases hd : table (encode (.inl (wotsPkInput seed layer tree index (List.ofFn sigma)))) with
    | none => simp only [replayProgram, hd, Option.bind_none] at recorded; cases recorded
    | some digest =>
      simp only [replayProgram, hd, Option.bind_some, Option.some.injEq] at recorded
      exact ⟨sigma, digest, rfl, hd, recorded⟩

theorem replay_wots_leaf_nonzero (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree index : ℕ) (leaf : Randomizer)
    (recorded : replayProgram table (wotsLeafProgram encode seed layer tree index) = some leaf)
    (nozero : ¬ PublicNodeZero (fun key => table (encode (.inl key)))) : leaf ≠ 0 := by
  obtain ⟨sigma, digest, _, hd, he⟩ := replay_wots_leaf_compression encode table seed layer tree index leaf recorded
  intro zero
  exact nozero ⟨wotsPkInput seed layer tree index (List.ofFn sigma), digest, hd,
    (node_zero_iff digest).mpr (he.trans zero)⟩

end
end C10Probability

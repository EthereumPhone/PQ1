import C10Probability.TreeReference
import C10Probability.TreeRootCertificate
import C10Probability.PathRecovery

/-! Select an actual recorded leaf and a reference authentication path from a
builder root. FORS additionally retains its private derivation and public leaf
hash. These witnesses add no oracle calls and need no collision assumption. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem merkle_certificate_reference (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree : ℕ) (root : Randomizer)
    (certificate : MerkleTreeCertificate encode table seed layer tree root)
    (index : ℕ) (bound : index < 512) :
    ∃ leaf auth, replayProgram table (wotsLeafProgram encode seed layer tree index) = some leaf ∧
      auth.length = 9 ∧ replayProgram table
        (merkleRecoverProgram (fun key => encode (.inl key)) seed layer tree leaf index auth) = some root := by
  obtain ⟨leaf, auth, hl, hlen, hpath⟩ := recorded_tree_reference table
    (fun kp => replayProgram table (wotsLeafProgram encode seed layer tree kp))
    (fun h parent left right => encode (.inl (merklePairInput seed layer tree h parent left right)))
    randomizerOfDigest certificate 0 index (by decide) (by simpa using bound)
  refine ⟨leaf, auth, ?_, hlen, ?_⟩
  · simpa only [Nat.mul_zero, Nat.zero_add] using hl
  · exact replay_merkle_recover_reference _ table seed layer tree index leaf root auth hlen
      (by simpa only [Nat.mul_zero, Nat.zero_add] using hpath)

theorem replay_fors_leaf_recorded (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree index : ℕ) (leaf : Randomizer)
    (recorded : replayProgram table (forsLeafProgram encode seed ht tree index) = some leaf) :
    ∃ secret digest, table (encode (.inr (forsPrivateTail ht tree index))) = some secret ∧
      table (encode (.inl (forsLeafInput seed ht tree index (randomizerOfDigest secret)))) = some digest ∧
      randomizerOfDigest digest = leaf := by
  unfold forsLeafProgram at recorded
  cases hs : table (encode (.inr (forsPrivateTail ht tree index))) with
  | none => simp only [replayProgram, hs, Option.bind_none] at recorded; cases recorded
  | some secret =>
    rw [replay_program_cached table _ _ secret hs] at recorded
    cases hd : table (encode (.inl (forsLeafInput seed ht tree index (randomizerOfDigest secret)))) with
    | none => simp only [replayProgram, hd, Option.bind_none] at recorded; cases recorded
    | some digest =>
      simp only [replayProgram, hd, Option.bind_some, Option.some.injEq] at recorded
      exact ⟨secret, digest, rfl, hd, recorded⟩

theorem fors_certificate_reference (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree : ℕ) (root : Randomizer)
    (certificate : ForsTreeCertificate encode table seed ht tree root)
    (index : ℕ) (bound : index < 2048) :
    ∃ secret digest auth,
      table (encode (.inr (forsPrivateTail ht tree index))) = some secret ∧
      table (encode (.inl (forsLeafInput seed ht tree index (randomizerOfDigest secret)))) = some digest ∧
      auth.length = 11 ∧ replayProgram table
        (forsRecoverProgram (fun key => encode (.inl key)) seed ht tree index
          (randomizerOfDigest secret) auth) = some root := by
  obtain ⟨leaf, auth, hl, hlen, hpath⟩ := recorded_tree_reference table
    (fun kp => replayProgram table (forsLeafProgram encode seed ht tree kp))
    (fun h parent left right => encode (.inl (forsPairInput seed ht tree h parent left right)))
    randomizerOfDigest certificate 0 index (by decide) (by simpa using bound)
  have hl' : replayProgram table (forsLeafProgram encode seed ht tree index) = some leaf :=
    by simpa only [Nat.mul_zero, Nat.zero_add] using hl
  obtain ⟨secret, digest, hs, hd, he⟩ := replay_fors_leaf_recorded encode table seed ht tree index leaf hl'
  refine ⟨secret, digest, auth, hs, hd, hlen, ?_⟩
  apply replay_fors_recover_reference _ table seed ht tree index (randomizerOfDigest secret) root digest auth hlen hd
  simpa only [Nat.mul_zero, Nat.zero_add, he] using hpath

end
end C10Probability

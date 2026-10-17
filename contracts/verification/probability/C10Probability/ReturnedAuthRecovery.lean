import C10Probability.ReturnedAuth
import C10Probability.AuthPath
import C10Probability.RootReference

/-! Recovery consumes the actual returned arrays, with the actual leaf replay
or FORS private derivation in the same cache. No existential substitute path. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem merkle_auth_certificate_recovery (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree target : ℕ) (auth : List Randomizer) (root : Randomizer)
    (certificate : MerkleAuthCertificate encode table seed layer tree target auth root)
    (bound : target < 512) :
    ∃ leaf, replayProgram table (wotsLeafProgram encode seed layer tree target) = some leaf ∧
      replayProgram table (merkleRecoverProgram (fun key => encode (.inl key))
        seed layer tree leaf target auth) = some root := by
  obtain ⟨leaf, hl, hp⟩ := collected_complete_path table
    (fun kp => replayProgram table (wotsLeafProgram encode seed layer tree kp))
    (fun h parent left right => encode (.inl (merklePairInput seed layer tree h parent left right)))
    randomizerOfDigest target 9 auth root certificate.2 certificate.1 bound
  exact ⟨leaf, hl, replay_merkle_recover_reference _ table seed layer tree target
    leaf root auth certificate.1 hp⟩

theorem fors_auth_certificate_recovery (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree target : ℕ) (auth : List Randomizer) (root : Randomizer)
    (certificate : ForsAuthCertificate encode table seed ht tree target auth root)
    (bound : target < 2048) :
    ∃ secret digest,
      table (encode (.inr (forsPrivateTail ht tree target))) = some secret ∧
      table (encode (.inl (forsLeafInput seed ht tree target (randomizerOfDigest secret)))) = some digest ∧
      replayProgram table (forsRecoverProgram (fun key => encode (.inl key))
        seed ht tree target (randomizerOfDigest secret) auth) = some root := by
  obtain ⟨leaf, hl, hp⟩ := collected_complete_path table
    (fun kp => replayProgram table (forsLeafProgram encode seed ht tree kp))
    (fun h parent left right => encode (.inl (forsPairInput seed ht tree h parent left right)))
    randomizerOfDigest target 11 auth root certificate.2 certificate.1 bound
  obtain ⟨secret, digest, hs, hd, he⟩ := replay_fors_leaf_recorded encode table seed ht tree target leaf hl
  refine ⟨secret, digest, hs, hd, ?_⟩
  exact replay_fors_recover_reference _ table seed ht tree target (randomizerOfDigest secret)
    root digest auth certificate.1 hd (by simpa only [he] using hp)

theorem replay_merkle_build_recovery (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree target : ℕ) (out : List Randomizer × Randomizer)
    (recorded : replayProgram table (merkleBuildProgram encode seed layer tree target) = some out)
    (bound : target < 512) :
    out.1.length = 9 ∧ ∃ leaf,
      replayProgram table (wotsLeafProgram encode seed layer tree target) = some leaf ∧
      replayProgram table (merkleRecoverProgram (fun key => encode (.inl key))
        seed layer tree leaf target out.1) = some out.2 := by
  have cert := replay_merkle_auth_certificate encode table seed layer tree target out recorded
  exact ⟨cert.1, merkle_auth_certificate_recovery encode table seed layer tree target _ _ cert bound⟩

theorem replay_fors_tree_recovery (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree target : ℕ) (out : Randomizer × List Randomizer)
    (recorded : replayProgram table (forsTreeProgram encode seed ht tree target) = some out)
    (bound : target < 2048) :
    out.2.length = 11 ∧ ∃ secret digest,
      table (encode (.inr (forsPrivateTail ht tree target))) = some secret ∧
      table (encode (.inl (forsLeafInput seed ht tree target (randomizerOfDigest secret)))) = some digest ∧
      replayProgram table (forsRecoverProgram (fun key => encode (.inl key))
        seed ht tree target (randomizerOfDigest secret) out.2) = some out.1 := by
  have cert := replay_fors_auth_certificate encode table seed ht tree target out recorded
  exact ⟨cert.1, fors_auth_certificate_recovery encode table seed ht tree target _ _ cert bound⟩

theorem merkle_build_returned_recovery [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree target : ℕ)
    (out : (List Randomizer × Randomizer) × Memo K Digest)
    (supported : out ∈ (merkleBuild encode table seed layer tree target).support)
    (bound : target < 512) :
    out.1.1.length = 9 ∧ ∃ leaf,
      replayProgram out.2 (wotsLeafProgram encode seed layer tree target) = some leaf ∧
      replayProgram out.2 (merkleRecoverProgram (fun key => encode (.inl key))
        seed layer tree leaf target out.1.1) = some out.1.2 := by
  exact replay_merkle_build_recovery encode out.2 seed layer tree target out.1
    (eval_program_replay digestDraw _ table out (by rwa [merkle_build_eval])) bound

theorem fors_tree_returned_recovery [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (ht tree target : ℕ)
    (out : (Randomizer × List Randomizer) × Memo K Digest)
    (supported : out ∈ (forsTree encode table seed ht tree target).support)
    (bound : target < 2048) :
    out.1.2.length = 11 ∧ ∃ secret digest,
      out.2 (encode (.inr (forsPrivateTail ht tree target))) = some secret ∧
      out.2 (encode (.inl (forsLeafInput seed ht tree target (randomizerOfDigest secret)))) = some digest ∧
      replayProgram out.2 (forsRecoverProgram (fun key => encode (.inl key))
        seed ht tree target (randomizerOfDigest secret) out.1.2) = some out.1.1 := by
  exact replay_fors_tree_recovery encode out.2 seed ht tree target out.1
    (eval_program_replay digestDraw _ table out (by rwa [fors_tree_eval])) bound

theorem merkle_returned_recovery_extends (encode : WotsQuery → K) (before after : Memo K Digest)
    (seed : ByteKey) (layer tree target : ℕ) (out : List Randomizer × Randomizer)
    (recorded : replayProgram before (merkleBuildProgram encode seed layer tree target) = some out)
    (extension : MemoExtends before after) (bound : target < 512) :
    out.1.length = 9 ∧ ∃ leaf,
      replayProgram after (wotsLeafProgram encode seed layer tree target) = some leaf ∧
      replayProgram after (merkleRecoverProgram (fun key => encode (.inl key))
        seed layer tree leaf target out.1) = some out.2 := by
  exact replay_merkle_build_recovery encode after seed layer tree target out
    (replay_program_extends _ before after out extension recorded) bound

theorem fors_returned_recovery_extends (encode : WotsQuery → K) (before after : Memo K Digest)
    (seed : ByteKey) (ht tree target : ℕ) (out : Randomizer × List Randomizer)
    (recorded : replayProgram before (forsTreeProgram encode seed ht tree target) = some out)
    (extension : MemoExtends before after) (bound : target < 2048) :
    out.2.length = 11 ∧ ∃ secret digest,
      after (encode (.inr (forsPrivateTail ht tree target))) = some secret ∧
      after (encode (.inl (forsLeafInput seed ht tree target (randomizerOfDigest secret)))) = some digest ∧
      replayProgram after (forsRecoverProgram (fun key => encode (.inl key))
        seed ht tree target (randomizerOfDigest secret) out.2) = some out.1 := by
  exact replay_fors_tree_recovery encode after seed ht tree target out
    (replay_program_extends _ before after out extension recorded) bound

end
end C10Probability

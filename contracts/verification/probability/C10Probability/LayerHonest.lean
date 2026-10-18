import C10Probability.WotsHonestSign
import C10Probability.LayerSigningReplay
import C10Probability.ReturnedAuthRecovery

/-! A successful actual layer signature reconstructs the builder's root. The
builder and recovery remain distinct executed procedures; their equality is
derived from the returned path, actual WOTS chains and one consistent cache. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem replay_layer_sign_correct (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree target : ℕ) (message : Randomizer) (shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) (sig : LayerSignature) (root : Randomizer)
    (signed : replayProgram table (layerSignProgram encode seed layer tree target
      message shuffle n bound) = some (some (sig, root))) (targetBound : target < 512) :
    sig.count < n ∧ sig.auth.length = 9 ∧
      replayProgram table (merkleBuildProgram encode seed layer tree target) = some (sig.auth, root) ∧
      MerkleTreeCertificate encode table seed layer tree root := by
  obtain ⟨built, subseed, builtReplay, _, wots, auth, recovered⟩ :=
    replay_layer_sign_witness encode table seed layer tree target message shuffle n bound sig root signed
  obtain ⟨length, leaf, generated, path⟩ :=
    replay_merkle_build_recovery encode table seed layer tree target built builtReplay targetBound
  obtain ⟨count, wotsRecovery⟩ := replay_wots_sign_recovery encode table seed layer tree target
    (nodeValueBytes message) subseed n bound sig.sigma sig.count leaf wots generated
  have builtRecovery : replayProgram table (layerRecoverProgram (fun key => encode (.inl key))
      seed layer tree target message sig) = some built.2 := by
    rw [layerRecoverProgram, replay_program_bind, wotsRecovery, Option.bind_some, auth]
    exact path
  have same := replay_program_unique _ table root built.2 recovered builtRecovery
  refine ⟨count, ?_, ?_, ?_⟩
  · simpa only [auth] using length
  · simpa only [auth, same] using builtReplay
  · simpa only [same] using
      replay_merkle_build_certificate encode table seed layer tree target built builtReplay

theorem replay_layer_sign_subtree_root (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree target : ℕ) (message : Randomizer) (shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) (sig : LayerSignature) (root reference : Randomizer)
    (signed : replayProgram table (layerSignProgram encode seed layer tree target
      message shuffle n bound) = some (some (sig, root))) (targetBound : target < 512)
    (generated : replayProgram table (subtreeRootProgram encode seed layer tree) = some reference) :
    root = reference := by
  have actual := (replay_layer_sign_correct encode table seed layer tree target
    message shuffle n bound sig root signed targetBound).2.2.2
  have referenceCertificate := replay_subtree_root_certificate encode table seed layer tree reference generated
  exact recorded_tree_node_unique table _ _ randomizerOfDigest actual referenceCertificate

theorem layer_sign_correct_support [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree target : ℕ)
    (message : Randomizer) (shuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32)
    (sig : LayerSignature) (root : Randomizer) (after : Memo K Digest)
    (supported : (some (sig, root), after) ∈
      (layerSign encode table seed layer tree target message shuffle n bound).support)
    (targetBound : target < 512) :
    sig.count < n ∧ sig.auth.length = 9 ∧
      replayProgram after (merkleBuildProgram encode seed layer tree target) = some (sig.auth, root) ∧
      MerkleTreeCertificate encode after seed layer tree root := by
  exact replay_layer_sign_correct encode after seed layer tree target message shuffle n bound sig root
    (eval_program_replay digestDraw _ table (some (sig, root), after)
      (by rwa [layer_sign_eval])) targetBound

end
end C10Probability

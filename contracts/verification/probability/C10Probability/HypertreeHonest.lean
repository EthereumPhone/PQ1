import C10Probability.LayerHonest
import C10Probability.HypertreeSigningReplay
import C10Probability.HypertreeRecover

/-! Both actual returned layers replay in order, and the top recovered value
equals an independently recorded layer-one/tree-zero key-generation root. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem replay_hypertree_sign_recovery (encode : WotsQuery → K) (table : Memo K Digest)
    (seed shuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32) (index : ℕ)
    (current top : Randomizer) (signatures : List LayerSignature)
    (signed : replayProgram table (hypertreeSignProgram encode seed shuffle n bound
      2 0 index current []) = some (some (signatures, top))) :
    replayProgram table (hypertreeRecoverProgram (fun key => encode (.inl key))
      seed signatures 2 0 index current) = some top := by
  obtain ⟨lower, upper, middle, layers, lowerSigned, upperSigned⟩ :=
    replay_hypertree_sign_two encode table seed shuffle n bound index current top signatures signed
  obtain ⟨_, _, _, _, _, _, lowerRecovery⟩ := replay_layer_sign_witness encode table seed 0
    (hypertreeParent index) (hypertreeLeaf index) current shuffle n bound lower middle lowerSigned
  obtain ⟨_, _, _, _, _, _, upperRecovery⟩ := replay_layer_sign_witness encode table seed 1
    (hypertreeParent (hypertreeParent index)) (hypertreeLeaf (hypertreeParent index))
    middle shuffle n bound upper top upperSigned
  subst signatures
  simp only [hypertreeRecoverProgram, replay_program_cast, replay_program_bind,
    List.getElem?_cons_zero, List.getElem?_cons_succ, Option.getD_some, Nat.reduceAdd,
    lowerRecovery, upperRecovery, Option.bind_some, replay_program_done]

theorem replay_hypertree_sign_keygen_root (encode : WotsQuery → K) (table : Memo K Digest)
    (seed shuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32) (digest : Digest)
    (current top reference : Randomizer) (signatures : List LayerSignature)
    (signed : replayProgram table (hypertreeSignProgram encode seed shuffle n bound
      2 0 (hypertreeIndex digest) current []) = some (some (signatures, top)))
    (generated : replayProgram table (subtreeRootProgram encode seed 1 0) = some reference) :
    top = reference := by
  obtain ⟨_, upper, middle, _, _, upperSigned⟩ := replay_hypertree_sign_two encode table seed
    shuffle n bound (hypertreeIndex digest) current top signatures signed
  rw [hypertree_second_parent_zero] at upperSigned
  exact replay_layer_sign_subtree_root encode table seed 1 0
    (hypertreeLeaf (hypertreeParent (hypertreeIndex digest))) middle shuffle n bound upper top
    reference upperSigned (hypertree_leaf_bound _) generated

end
end C10Probability

import C10Probability.BuilderRecoveryBinding
import C10Probability.ObservedOutput

/-! The actual winning output reaches an actual keygen WOTS leaf, unless the
same final public cache contains a selected-node collision or a zero node.
This is a structural opening, not a new-message WOTS attack or its numerical
charge. All digest, forest, layer and signature witnesses remain linked. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

def TopTreeOpening (encode : WotsQuery → K) (table : Memo K Digest)
    (seed root message : ByteKey) (sig : C10Signature) : Prop :=
  ∃ digest forest middle top leaf countDigest,
    table (encode (.inl (hmsgRandomizerInput seed root message sig.randomizer))) = some digest ∧
    forsAccept (forsOfDigest digest) = true ∧
    replayProgram table (forestRecoverProgram (fun key => encode (.inl key)) seed
      (hypertreeIndex digest) digest sig.secrets sig.auths) = some forest ∧
    replayProgram table (layerRecoverProgram (fun key => encode (.inl key)) seed 0
      (hypertreeParent (hypertreeIndex digest)) (hypertreeLeaf (hypertreeIndex digest))
      forest ((sig.layers[0]?).getD emptyLayerSignature)) = some middle ∧
    replayProgram table (wotsRecoveryUnderProgram (fun key => encode (.inl key)) seed 1 0
      (hypertreeLeaf (hypertreeParent (hypertreeIndex digest))) (nodeValueBytes middle)
      ((sig.layers[1]?).getD emptyLayerSignature).sigma
      ((sig.layers[1]?).getD emptyLayerSignature).count) = some leaf ∧
    replayProgram table (merkleRecoverProgram (fun key => encode (.inl key)) seed 1 0 leaf
      (hypertreeLeaf (hypertreeParent (hypertreeIndex digest)))
      ((sig.layers[1]?).getD emptyLayerSignature).auth) = some top ∧
    replayProgram table (wotsLeafProgram encode seed 1 0
      (hypertreeLeaf (hypertreeParent (hypertreeIndex digest)))) = some leaf ∧
    table (encode (.inl (wotsRecoverCountInput seed 1 0
      (hypertreeLeaf (hypertreeParent (hypertreeIndex digest))) (nodeValueBytes middle)
      ((sig.layers[1]?).getD emptyLayerSignature).count))) = some countDigest ∧
    wotsAccept (wotsOfDigest countDigest) = true ∧ nodeBlock top = root

theorem verifier_top_tree_opening (encode : WotsQuery → K) (table : Memo K Digest)
    (seed root message : ByteKey) (sig : C10Signature) (width : seed.length = 32)
    (reference : ∃ value, MerkleTreeCertificate encode table seed 1 0 value ∧ nodeBlock value = root)
    (free : PublicNodeCollisionFree (fun key => encode (.inl key)) table)
    (nozero : ¬ PublicNodeZero (fun key => table (encode (.inl key))))
    (verified : VerificationWitness (fun key => encode (.inl key)) table seed root message sig) :
    TopTreeOpening encode table seed root message sig := by
  obtain ⟨digest, forest, top, hd, ha, hf, ht, he⟩ := verified
  obtain ⟨original, certificate, originalRoot⟩ := reference
  have sameRoot : original = top := node_block_injective (originalRoot.trans he.symm)
  subst original
  obtain ⟨middle, hm, upper⟩ := replay_hypertree_two (fun key => encode (.inl key))
    table seed sig.layers (hypertreeIndex digest) forest top ht
  rw [hypertree_second_parent_zero] at upper
  obtain ⟨leaf, hw, hp⟩ := replay_layer_witness (fun key => encode (.inl key)) table seed 1 0
    (hypertreeLeaf (hypertreeParent (hypertreeIndex digest))) middle top
    ((sig.layers[1]?).getD emptyLayerSignature) upper
  have hl := merkle_recovery_matches_certificate encode table seed 1 0
    (hypertreeLeaf (hypertreeParent (hypertreeIndex digest))) width (hypertree_leaf_bound _)
    top leaf ((sig.layers[1]?).getD emptyLayerSignature).auth certificate free hp
  have nonzero := replay_wots_leaf_nonzero encode table seed 1 0
    (hypertreeLeaf (hypertreeParent (hypertreeIndex digest))) leaf hl nozero
  obtain ⟨countDigest, hc, branch⟩ := replay_wots_witness (fun key => encode (.inl key)) table seed 1 0
    (hypertreeLeaf (hypertreeParent (hypertreeIndex digest))) (nodeValueBytes middle)
    ((sig.layers[1]?).getD emptyLayerSignature).sigma
    ((sig.layers[1]?).getD emptyLayerSignature).count leaf hw
  rcases branch with ⟨_, zero⟩ | ⟨accepted, _, _, _⟩
  · exact False.elim (nonzero zero)
  · exact ⟨digest, forest, middle, top, leaf, countDigest, hd, ha, hf, hm, hw, hp, hl, hc, accepted, he⟩

theorem observed_output_top_tree_cases (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (publicSeed : Digest) (qr qs : ℕ) (out : C10ObservedGame × Memo K Digest)
    (witness : ObservedOutputWitness encode cfg publicSeed qr qs out) :
    ¬ PublicNodeCollisionFree (fun key => encode (.inl key)) out.2 ∨
      PublicNodeZero (fun key => out.2 (encode (.inl key))) ∨
      TopTreeOpening encode out.2 out.1.key.1 out.1.key.2
        out.1.driver.session.session.value.1 out.1.driver.session.session.value.2 := by
  by_cases free : PublicNodeCollisionFree (fun key => encode (.inl key)) out.2
  · by_cases zero : PublicNodeZero (fun key => out.2 (encode (.inl key)))
    · exact Or.inr (Or.inl zero)
    · right; right
      apply verifier_top_tree_opening encode out.2 out.1.key.1 out.1.key.2
        out.1.driver.session.session.value.1 out.1.driver.session.session.value.2
        witness.seed_width _ free zero witness.verification
      obtain ⟨root, recorded, equal⟩ := witness.keygen_root
      exact ⟨root, replay_subtree_root_certificate encode out.2 out.1.key.1 1 0 root recorded, equal⟩
  · exact Or.inl free

theorem c10_observed_game_top_tree_cases [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) (table : Memo K Digest)
    (out : C10ObservedGame × Memo K Digest)
    (ho : out ∈ (c10ObservedGame encode cfg publicSeed adversary qr qs table).support)
    (win : out.1.driver.accepted = true) :
    ¬ PublicNodeCollisionFree (fun key => encode (.inl key)) out.2 ∨
      PublicNodeZero (fun key => out.2 (encode (.inl key))) ∨
      TopTreeOpening encode out.2 out.1.key.1 out.1.key.2
        out.1.driver.session.session.value.1 out.1.driver.session.session.value.2 := by
  exact observed_output_top_tree_cases encode cfg publicSeed qr qs out
    (c10_observed_output_witness encode cfg publicSeed adversary qr qs table out ho win)

theorem c10_observed_initialized_independent_top_tree_cases (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ)
    (out : C10ObservedGame × Memo WotsQuery Digest)
    (ho : out ∈ (c10ObservedInitializedIndependent cfg sampler qr qs).support)
    (win : out.1.driver.accepted = true) :
    ¬ PublicNodeCollisionFree Sum.inl out.2 ∨ PublicNodeZero (fun key => out.2 (.inl key)) ∨
      TopTreeOpening id out.2 out.1.key.1 out.1.key.2
        out.1.driver.session.session.value.1 out.1.driver.session.session.value.2 := by
  obtain ⟨input, _, _, witness⟩ := c10_observed_initialized_independent_witness cfg sampler qr qs out ho win
  exact observed_output_top_tree_cases id cfg input.1 qr qs out witness

end
end C10Probability

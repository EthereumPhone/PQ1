import C10Probability.TopTreeOpening
import C10Probability.WotsLeafBinding

/-! The actual winning top-layer witness retains all 43 private-seeded chain
prefixes of the submitted signature. Disclosure and numerical charging remain
separate obligations; an honest signature also satisfies this opening. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

def TopChainOpening (encode : WotsQuery → K) (table : Memo K Digest)
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
    wotsAccept (wotsOfDigest countDigest) = true ∧ nodeBlock top = root ∧
    ∀ i, replayProgram table (wotsSeedChainProgram encode seed 1 0
      (hypertreeLeaf (hypertreeParent (hypertreeIndex digest))) i.val
      (wotsOfDigest countDigest i).val) =
        some (((sig.layers[1]?).getD emptyLayerSignature).sigma i)

theorem top_tree_chain_opening (encode : WotsQuery → K) (table : Memo K Digest)
    (seed root message : ByteKey) (sig : C10Signature) (width : seed.length = 32)
    (free : PublicNodeCollisionFree (fun key => encode (.inl key)) table)
    (opening : TopTreeOpening encode table seed root message sig) :
    TopChainOpening encode table seed root message sig := by
  obtain ⟨digest, forest, middle, top, leaf, countDigest, hd, ha, hf, hm, hw, hp, hl, hc, accepted, he⟩ := opening
  refine ⟨digest, forest, middle, top, leaf, countDigest, hd, ha, hf, hm, hw, hp, hl, hc, accepted, he, ?_⟩
  exact replay_wots_accepted_reference encode table seed 1 0
    (hypertreeLeaf (hypertreeParent (hypertreeIndex digest))) (nodeValueBytes middle)
    ((sig.layers[1]?).getD emptyLayerSignature).sigma
    ((sig.layers[1]?).getD emptyLayerSignature).count leaf countDigest width free hc accepted hl hw

theorem observed_output_top_chain_cases (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (publicSeed : Digest) (qr qs : ℕ) (out : C10ObservedGame × Memo K Digest)
    (witness : ObservedOutputWitness encode cfg publicSeed qr qs out) :
    ¬ PublicNodeCollisionFree (fun key => encode (.inl key)) out.2 ∨
      PublicNodeZero (fun key => out.2 (encode (.inl key))) ∨
      TopChainOpening encode out.2 out.1.key.1 out.1.key.2
        out.1.driver.session.session.value.1 out.1.driver.session.session.value.2 := by
  by_cases free : PublicNodeCollisionFree (fun key => encode (.inl key)) out.2
  · rcases observed_output_top_tree_cases encode cfg publicSeed qr qs out witness with collision | zero | opening
    · exact False.elim (collision free)
    · exact Or.inr (Or.inl zero)
    · exact Or.inr (Or.inr (top_tree_chain_opening encode out.2 out.1.key.1 out.1.key.2
        out.1.driver.session.session.value.1 out.1.driver.session.session.value.2
        witness.seed_width free opening))
  · exact Or.inl free

theorem c10_observed_game_top_chain_cases [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) (table : Memo K Digest)
    (out : C10ObservedGame × Memo K Digest)
    (ho : out ∈ (c10ObservedGame encode cfg publicSeed adversary qr qs table).support)
    (win : out.1.driver.accepted = true) :
    ¬ PublicNodeCollisionFree (fun key => encode (.inl key)) out.2 ∨
      PublicNodeZero (fun key => out.2 (encode (.inl key))) ∨
      TopChainOpening encode out.2 out.1.key.1 out.1.key.2
        out.1.driver.session.session.value.1 out.1.driver.session.session.value.2 := by
  exact observed_output_top_chain_cases encode cfg publicSeed qr qs out
    (c10_observed_output_witness encode cfg publicSeed adversary qr qs table out ho win)

theorem c10_observed_initialized_independent_top_chain_cases (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ)
    (out : C10ObservedGame × Memo WotsQuery Digest)
    (ho : out ∈ (c10ObservedInitializedIndependent cfg sampler qr qs).support)
    (win : out.1.driver.accepted = true) :
    ¬ PublicNodeCollisionFree Sum.inl out.2 ∨ PublicNodeZero (fun key => out.2 (.inl key)) ∨
      TopChainOpening id out.2 out.1.key.1 out.1.key.2
        out.1.driver.session.session.value.1 out.1.driver.session.session.value.2 := by
  obtain ⟨input, _, _, witness⟩ := c10_observed_initialized_independent_witness cfg sampler qr qs out ho win
  exact observed_output_top_chain_cases id cfg input.1 qr qs out witness

end
end C10Probability

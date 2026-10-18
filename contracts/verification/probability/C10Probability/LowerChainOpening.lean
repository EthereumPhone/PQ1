import C10Probability.RepeatedUpperBinding
import C10Probability.LayerHonest

/-! Descend through a repeated upper word into an actual previously built
lower tree. The submitted lower leaf and all private-seeded prefixes are
derived from that certificate, public-node binding and the nonzero branch. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

def TopChainRecord.lowerTree (record : TopChainRecord) : ℕ :=
  hypertreeParent (hypertreeIndex record.digest)

def TopChainRecord.lowerKp (record : TopChainRecord) : ℕ :=
  hypertreeLeaf (hypertreeIndex record.digest)

structure LowerChainRecord where
  leaf : Randomizer
  countDigest : Digest

def LowerChainRecord.word (record : LowerChainRecord) : WotsWord :=
  wotsOfDigest record.countDigest

structure LowerChainRecordValid (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (sig : C10Signature) (top : TopChainRecord) (lower : LowerChainRecord) : Prop where
  certificate : MerkleTreeCertificate encode table seed 0 top.lowerTree top.middle
  wots : replayProgram table (wotsRecoveryUnderProgram (fun key => encode (.inl key)) seed 0
    top.lowerTree top.lowerKp (nodeValueBytes top.forest)
    ((sig.layers[0]?).getD emptyLayerSignature).sigma
    ((sig.layers[0]?).getD emptyLayerSignature).count) = some lower.leaf
  tree : replayProgram table (merkleRecoverProgram (fun key => encode (.inl key)) seed 0
    top.lowerTree lower.leaf top.lowerKp ((sig.layers[0]?).getD emptyLayerSignature).auth) = some top.middle
  generated_leaf : replayProgram table (wotsLeafProgram encode seed 0 top.lowerTree top.lowerKp) = some lower.leaf
  count : table (encode (.inl (wotsRecoverCountInput seed 0 top.lowerTree top.lowerKp
    (nodeValueBytes top.forest) ((sig.layers[0]?).getD emptyLayerSignature).count))) = some lower.countDigest
  accepted : wotsAccept lower.word = true
  prefixes : ∀ i, replayProgram table (wotsSeedChainProgram encode seed 0 top.lowerTree top.lowerKp
    i.val (lower.word i).val) = some (((sig.layers[0]?).getD emptyLayerSignature).sigma i)

theorem repeated_upper_lower_certificate (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entry : C10Exposure) (prior : C10SigningRecord)
    (signed : C10SigningRecordValid encode table cfg entry prior) (top : TopChainRecord)
    (address : hypertreeLeaf (hypertreeParent (hypertreeIndex prior.digest)) = top.kp)
    (same : top.middle = prior.middle) :
    MerkleTreeCertificate encode table cfg.seed 0 top.lowerTree top.middle := by
  have cert := (replay_layer_sign_correct encode table cfg.seed 0
    (hypertreeParent (hypertreeIndex prior.digest)) (hypertreeLeaf (hypertreeIndex prior.digest))
    prior.forest.pk entry.request.shuffle cfg.wTrials cfg.wBound prior.lower prior.middle
    signed.lower (hypertree_leaf_bound _)).2.2.2
  rw [repeated_upper_lower_tree_eq prior top address, ← same] at cert
  exact cert

theorem lower_chain_opening_of_certificate (encode : WotsQuery → K) (table : Memo K Digest)
    (seed root message : ByteKey) (sig : C10Signature) (top : TopChainRecord)
    (valid : TopChainRecordValid encode table seed root message sig top) (width : seed.length = 32)
    (certificate : MerkleTreeCertificate encode table seed 0 top.lowerTree top.middle)
    (free : PublicNodeCollisionFree (fun key => encode (.inl key)) table)
    (nozero : ¬ PublicNodeZero (fun key => table (encode (.inl key)))) :
    ∃ lower, LowerChainRecordValid encode table seed sig top lower := by
  obtain ⟨leaf, wots, tree⟩ := replay_layer_witness (fun key => encode (.inl key)) table seed 0
    top.lowerTree top.lowerKp top.forest top.middle ((sig.layers[0]?).getD emptyLayerSignature) valid.middle
  have generated := merkle_recovery_matches_certificate encode table seed 0 top.lowerTree top.lowerKp
    width (hypertree_leaf_bound _) top.middle leaf ((sig.layers[0]?).getD emptyLayerSignature).auth
    certificate free tree
  have nonzero := replay_wots_leaf_nonzero encode table seed 0 top.lowerTree top.lowerKp leaf generated nozero
  obtain ⟨digest, lookup, branch⟩ := replay_wots_witness (fun key => encode (.inl key)) table seed 0
    top.lowerTree top.lowerKp (nodeValueBytes top.forest) ((sig.layers[0]?).getD emptyLayerSignature).sigma
    ((sig.layers[0]?).getD emptyLayerSignature).count leaf wots
  rcases branch with ⟨_, zero⟩ | ⟨accepted, _, _, _⟩
  · exact False.elim (nonzero zero)
  · refine ⟨⟨leaf, digest⟩, certificate, wots, tree, generated, lookup, accepted, ?_⟩
    exact replay_wots_accepted_reference encode table seed 0 top.lowerTree top.lowerKp
      (nodeValueBytes top.forest) ((sig.layers[0]?).getD emptyLayerSignature).sigma
      ((sig.layers[0]?).getD emptyLayerSignature).count leaf digest width free lookup accepted generated wots

theorem repeated_upper_lower_opening (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entry : C10Exposure) (prior : C10SigningRecord)
    (signed : C10SigningRecordValid encode table cfg entry prior)
    (message : ByteKey) (sig : C10Signature) (top : TopChainRecord)
    (valid : TopChainRecordValid encode table cfg.seed cfg.root message sig top)
    (width : cfg.seed.length = 32)
    (address : hypertreeLeaf (hypertreeParent (hypertreeIndex prior.digest)) = top.kp)
    (word : top.word = wotsOfDigest prior.upperDigest)
    (free : PublicNodeCollisionFree (fun key => encode (.inl key)) table)
    (nozero : ¬ PublicNodeZero (fun key => table (encode (.inl key)))) :
    AcceptedWotsCollision (fun key => table (encode (.inl key))) ∨
      (top.middle = prior.middle ∧ ∃ lower, LowerChainRecordValid encode table cfg.seed sig top lower) := by
  rcases repeated_upper_message_cases encode table cfg entry prior signed message sig top valid address word with
    same | collision
  · exact Or.inr ⟨same, lower_chain_opening_of_certificate encode table cfg.seed cfg.root message sig top
      valid width (repeated_upper_lower_certificate encode table cfg entry prior signed top address same) free nozero⟩
  · exact Or.inl collision

end
end C10Probability

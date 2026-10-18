import C10Probability.TopChainOpening

/-! A named record of every witness in the existing top-chain opening.
Both directions below preserve the exact executed-program relation. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

structure TopChainRecord where
  digest : Digest
  forest : Randomizer
  middle : Randomizer
  top : Randomizer
  leaf : Randomizer
  countDigest : Digest

def TopChainRecord.kp (record : TopChainRecord) : ℕ :=
  hypertreeLeaf (hypertreeParent (hypertreeIndex record.digest))

def TopChainRecord.word (record : TopChainRecord) : WotsWord :=
  wotsOfDigest record.countDigest

structure TopChainRecordValid (encode : WotsQuery → K) (table : Memo K Digest)
    (seed root message : ByteKey) (sig : C10Signature) (record : TopChainRecord) : Prop where
  digest : table (encode (.inl (hmsgRandomizerInput seed root message sig.randomizer))) = some record.digest
  forest_accepted : forsAccept (forsOfDigest record.digest) = true
  forest : replayProgram table (forestRecoverProgram (fun key => encode (.inl key)) seed
    (hypertreeIndex record.digest) record.digest sig.secrets sig.auths) = some record.forest
  middle : replayProgram table (layerRecoverProgram (fun key => encode (.inl key)) seed 0
    (hypertreeParent (hypertreeIndex record.digest)) (hypertreeLeaf (hypertreeIndex record.digest))
    record.forest ((sig.layers[0]?).getD emptyLayerSignature)) = some record.middle
  wots : replayProgram table (wotsRecoveryUnderProgram (fun key => encode (.inl key)) seed 1 0
    record.kp (nodeValueBytes record.middle) ((sig.layers[1]?).getD emptyLayerSignature).sigma
    ((sig.layers[1]?).getD emptyLayerSignature).count) = some record.leaf
  tree : replayProgram table (merkleRecoverProgram (fun key => encode (.inl key)) seed 1 0
    record.leaf record.kp ((sig.layers[1]?).getD emptyLayerSignature).auth) = some record.top
  generated_leaf : replayProgram table (wotsLeafProgram encode seed 1 0 record.kp) = some record.leaf
  count : table (encode (.inl (wotsRecoverCountInput seed 1 0 record.kp (nodeValueBytes record.middle)
    ((sig.layers[1]?).getD emptyLayerSignature).count))) = some record.countDigest
  accepted : wotsAccept record.word = true
  root : nodeBlock record.top = root
  prefixes : ∀ i, replayProgram table (wotsSeedChainProgram encode seed 1 0 record.kp i.val
    (record.word i).val) = some (((sig.layers[1]?).getD emptyLayerSignature).sigma i)

theorem top_chain_opening_record (encode : WotsQuery → K) (table : Memo K Digest)
    (seed root message : ByteKey) (sig : C10Signature)
    (opening : TopChainOpening encode table seed root message sig) :
    ∃ record, TopChainRecordValid encode table seed root message sig record := by
  obtain ⟨digest, forest, middle, top, leaf, countDigest,
    hd, ha, hf, hm, hw, hp, hl, hc, accepted, he, prefixes⟩ := opening
  exact ⟨⟨digest, forest, middle, top, leaf, countDigest⟩,
    hd, ha, hf, hm, hw, hp, hl, hc, accepted, he, prefixes⟩

theorem top_chain_record_opening (encode : WotsQuery → K) (table : Memo K Digest)
    (seed root message : ByteKey) (sig : C10Signature) (record : TopChainRecord)
    (valid : TopChainRecordValid encode table seed root message sig record) :
    TopChainOpening encode table seed root message sig := by
  exact ⟨record.digest, record.forest, record.middle, record.top, record.leaf, record.countDigest,
    valid.digest, valid.forest_accepted, valid.forest, valid.middle, valid.wots, valid.tree,
    valid.generated_leaf, valid.count, valid.accepted, valid.root, valid.prefixes⟩

end
end C10Probability

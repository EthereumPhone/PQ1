import C10Probability.ObservedChains

/-! Explicit records retain both actual WOTS components of a successful C10
signature. The validity predicate is derived from the executed program; it
does not assume stable messages, exposure completeness or undisclosed values. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

structure C10SigningRecord where
  trial : ℕ
  digest : Digest
  forest : ForestOutput
  lower : LayerSignature
  upper : LayerSignature
  middle : Randomizer
  top : Randomizer
  lowerDigest : Digest
  upperDigest : Digest

structure C10SigningRecordValid (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entry : C10Exposure) (record : C10SigningRecord) : Prop where
  signing : replayProgram table (exposureProgram encode cfg entry) = some (some entry.signature)
  randomizer : replayProgram table (randomizerUnderProgram encode entry.request.random
    entry.request.message cfg.seed cfg.root cfg.rTrials cfg.rBound) =
      some (some (record.trial, entry.signature.randomizer, record.digest))
  forest : replayProgram table (forestSignProgram encode cfg.seed
    (hypertreeIndex record.digest) record.digest entry.request.shuffle) = some record.forest
  secrets : entry.signature.secrets = record.forest.secrets
  auths : entry.signature.auths = record.forest.auths
  layers : entry.signature.layers = [record.lower, record.upper]
  lower : replayProgram table (layerSignProgram encode cfg.seed 0
    (hypertreeParent (hypertreeIndex record.digest)) (hypertreeLeaf (hypertreeIndex record.digest))
    record.forest.pk entry.request.shuffle cfg.wTrials cfg.wBound) = some (some (record.lower, record.middle))
  upper : replayProgram table (layerSignProgram encode cfg.seed 1 0
    (hypertreeLeaf (hypertreeParent (hypertreeIndex record.digest)))
    record.middle entry.request.shuffle cfg.wTrials cfg.wBound) = some (some (record.upper, record.top))
  lower_count : replayProgram table (mapProgram (fun key => encode (.inl key))
    (wotsCountProgram cfg.seed 0 (hypertreeParent (hypertreeIndex record.digest))
      (hypertreeLeaf (hypertreeIndex record.digest)) (nodeValueBytes record.forest.pk)
      0 cfg.wTrials (by simpa using cfg.wBound))) = some (some (record.lower.count, record.lowerDigest))
  upper_count : replayProgram table (mapProgram (fun key => encode (.inl key))
    (wotsCountProgram cfg.seed 1 0 (hypertreeLeaf (hypertreeParent (hypertreeIndex record.digest)))
      (nodeValueBytes record.middle) 0 cfg.wTrials (by simpa using cfg.wBound))) =
        some (some (record.upper.count, record.upperDigest))
  lower_accepted : wotsAccept (wotsOfDigest record.lowerDigest) = true
  upper_accepted : wotsAccept (wotsOfDigest record.upperDigest) = true
  lower_prefixes : ∀ i, replayProgram table (wotsSeedChainProgram encode cfg.seed 0
    (hypertreeParent (hypertreeIndex record.digest)) (hypertreeLeaf (hypertreeIndex record.digest))
    i.val (wotsOfDigest record.lowerDigest i).val) = some (record.lower.sigma i)
  upper_prefixes : ∀ i, replayProgram table (wotsSeedChainProgram encode cfg.seed 1 0
    (hypertreeLeaf (hypertreeParent (hypertreeIndex record.digest)))
    i.val (wotsOfDigest record.upperDigest i).val) = some (record.upper.sigma i)

theorem replay_c10_signing_record (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entry : C10Exposure)
    (signed : replayProgram table (exposureProgram encode cfg entry) = some (some entry.signature)) :
    ∃ record, C10SigningRecordValid encode table cfg entry record := by
  obtain ⟨trial, digest, forest, lower, upper, middle, top, randomizer, forestReplay,
    secrets, auths, layers, lowerWitness, upperWitness⟩ := replay_c10_chain_witness encode table
      entry.request.random entry.request.message cfg.seed cfg.root entry.request.shuffle
      cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound entry.signature signed
  obtain ⟨lowerSigned, _, lowerDigest, _, _, lowerCount, lowerAccepted, lowerPrefixes⟩ := lowerWitness
  obtain ⟨upperSigned, _, upperDigest, _, _, upperCount, upperAccepted, upperPrefixes⟩ := upperWitness
  exact ⟨⟨trial, digest, forest, lower, upper, middle, top, lowerDigest, upperDigest⟩,
    signed, randomizer, forestReplay, secrets, auths, layers, lowerSigned, upperSigned,
    lowerCount, upperCount, lowerAccepted, upperAccepted, lowerPrefixes, upperPrefixes⟩

theorem exposure_supported_signing_record (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entry : C10Exposure)
    (supported : ExposureSupported encode cfg table entry) :
    ∃ record, C10SigningRecordValid encode table cfg entry record := by
  exact replay_c10_signing_record encode table cfg entry supported.2.2.2.2

end
end C10Probability

import C10Probability.VerifierWitness
import C10Probability.C10Keygen

/-! Lookup witnesses expose the ordered reconstruction actually used by the
verifier. A WOTS count may reject and return zero; successful root equality
does not silently exclude that branch. Every lookup uses the supplied cache. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem replay_hypertree_step (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (signatures : List LayerSignature) (steps layer index : ℕ)
    (current top : Randomizer)
    (recorded : replayProgram table
      (hypertreeRecoverProgram encode seed signatures (steps + 1) layer index current) = some top) :
    ∃ root, replayProgram table (layerRecoverProgram encode seed layer (hypertreeParent index)
      (hypertreeLeaf index) current ((signatures[layer]?).getD emptyLayerSignature)) = some root ∧
      replayProgram table (hypertreeRecoverProgram encode seed signatures steps
        (layer + 1) (hypertreeParent index) root) = some top := by
  rw [hypertreeRecoverProgram, replay_program_cast, replay_program_bind] at recorded
  cases h : replayProgram table (layerRecoverProgram encode seed layer (hypertreeParent index)
      (hypertreeLeaf index) current ((signatures[layer]?).getD emptyLayerSignature)) with
  | none => simp only [h, Option.bind_none] at recorded; cases recorded
  | some root =>
    simp only [h, Option.bind_some] at recorded
    exact ⟨root, rfl, recorded⟩

theorem replay_hypertree_two (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (signatures : List LayerSignature) (index : ℕ)
    (current top : Randomizer)
    (recorded : replayProgram table
      (hypertreeRecoverProgram encode seed signatures 2 0 index current) = some top) :
    ∃ middle,
      replayProgram table (layerRecoverProgram encode seed 0 (hypertreeParent index)
        (hypertreeLeaf index) current ((signatures[0]?).getD emptyLayerSignature)) = some middle ∧
      replayProgram table (layerRecoverProgram encode seed 1
        (hypertreeParent (hypertreeParent index)) (hypertreeLeaf (hypertreeParent index))
        middle ((signatures[1]?).getD emptyLayerSignature)) = some top := by
  obtain ⟨middle, hm, rest⟩ := replay_hypertree_step encode table seed signatures 1 0 index current top recorded
  obtain ⟨last, hl, done⟩ := replay_hypertree_step encode table seed signatures 0 1
    (hypertreeParent index) middle top rest
  have he : last = top := by
    simpa only [hypertreeRecoverProgram, replayProgram, Option.some.injEq] using done
  exact ⟨middle, hm, he ▸ hl⟩

theorem replay_layer_witness (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree leaf : ℕ) (message root : Randomizer) (sig : LayerSignature)
    (recorded : replayProgram table (layerRecoverProgram encode seed layer tree leaf message sig) = some root) :
    ∃ pk, replayProgram table (wotsRecoveryUnderProgram encode seed layer tree leaf
      (nodeValueBytes message) sig.sigma sig.count) = some pk ∧
      replayProgram table (merkleRecoverProgram encode seed layer tree pk leaf sig.auth) = some root := by
  rw [layerRecoverProgram, replay_program_bind] at recorded
  cases h : replayProgram table (wotsRecoveryUnderProgram encode seed layer tree leaf
      (nodeValueBytes message) sig.sigma sig.count) with
  | none => simp only [h, Option.bind_none] at recorded; cases recorded
  | some pk =>
    simp only [h, Option.bind_some] at recorded
    exact ⟨pk, rfl, recorded⟩

def WotsRecoveryWitness (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (message : ByteKey) (sigma : WotsSigma)
    (count : ℕ) (pk : Randomizer) : Prop :=
  ∃ digest, table (encode (wotsRecoverCountInput seed layer tree kp message count)) = some digest ∧
    ((wotsAccept (wotsOfDigest digest) = false ∧ pk = 0) ∨
      ∃ ha : wotsAccept (wotsOfDigest digest) = true, ∃ values,
        replayProgram table (mapProgram encode
          (wotsAcceptedChainsProgram seed layer tree kp (wotsOfDigest digest) ha sigma)) = some values ∧
        replayProgram table (mapProgram encode (wotsCompressProgram seed layer tree kp values)) = some pk)

theorem replay_wots_witness (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (message : ByteKey) (sigma : WotsSigma)
    (count : ℕ) (pk : Randomizer)
    (recorded : replayProgram table
      (wotsRecoveryUnderProgram encode seed layer tree kp message sigma count) = some pk) :
    WotsRecoveryWitness encode table seed layer tree kp message sigma count pk := by
  unfold wotsRecoveryUnderProgram at recorded
  cases hd : table (encode (wotsRecoverCountInput seed layer tree kp message count)) with
  | none => simp only [replayProgram, hd, Option.bind_none] at recorded; cases recorded
  | some digest =>
    rw [replay_program_cached table _ _ digest hd] at recorded
    refine ⟨digest, hd, ?_⟩
    by_cases ha : wotsAccept (wotsOfDigest digest) = true
    · right
      refine ⟨ha, ?_⟩
      simp only [wotsRecoveryAfter, ha, ↓reduceDIte, mapProgram_bind,
        replay_program_bind] at recorded
      cases hv : replayProgram table (mapProgram encode
          (wotsAcceptedChainsProgram seed layer tree kp (wotsOfDigest digest) ha sigma)) with
      | none => simp only [hv, Option.bind_none] at recorded; cases recorded
      | some values =>
        simp only [hv, Option.bind_some] at recorded
        exact ⟨values, rfl, recorded⟩
    · left
      simp only [wotsRecoveryAfter, ha, Bool.false_eq_true, ↓reduceDIte,
        mapProgram, replayProgram, Option.some.injEq] at recorded
      exact ⟨Bool.eq_false_iff.mpr ha, recorded.symm⟩

theorem wots_witness_replay (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (message : ByteKey) (sigma : WotsSigma)
    (count : ℕ) (pk : Randomizer)
    (witness : WotsRecoveryWitness encode table seed layer tree kp message sigma count pk) :
    replayProgram table (wotsRecoveryUnderProgram encode seed layer tree kp message sigma count) = some pk := by
  obtain ⟨digest, hd, branch⟩ := witness
  rw [wotsRecoveryUnderProgram, replay_program_cached table _ _ digest hd]
  rcases branch with ⟨ha, rfl⟩ | ⟨ha, values, hv, hp⟩
  · simp only [wotsRecoveryAfter, ha, Bool.false_eq_true, ↓reduceDIte, mapProgram, replayProgram]
  · simp only [wotsRecoveryAfter, ha, ↓reduceDIte, mapProgram_bind, replay_program_bind,
      hv, Option.bind_some, hp]

theorem replay_keygen_witness (encode : WotsQuery → K) (table : Memo K Digest)
    (publicSeed : Digest) (key : ByteKey × ByteKey)
    (recorded : replayProgram table (c10KeygenProgram encode publicSeed) = some key) :
    key.1 = nodeBlock (randomizerOfDigest publicSeed) ∧
      ∃ root, replayProgram table (subtreeRootProgram encode key.1 1 0) = some root ∧
        nodeBlock root = key.2 := by
  rw [c10KeygenProgram, replay_program_map_return] at recorded
  cases h : replayProgram table
      (subtreeRootProgram encode (nodeBlock (randomizerOfDigest publicSeed)) 1 0) with
  | none => simp only [h, Option.map_none] at recorded; cases recorded
  | some root =>
    simp only [h, Option.map_some, Option.some.injEq] at recorded
    subst key
    exact ⟨rfl, root, h, rfl⟩

end
end C10Probability

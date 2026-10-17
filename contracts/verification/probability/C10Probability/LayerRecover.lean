import C10Probability.WotsRecoveryUnder
import C10Probability.MerkleRecover

/-! Actual hypertree layer recovery: WOTS public-key recovery followed by all
nine authentication calls. A rejected WOTS count returns zero, which is still
passed into the Merkle path, matching the caller's control flow. -/
namespace C10Probability
noncomputable section

variable {K L : Type*}

def layerRecoverProgram (encode : ByteKey → K) (seed : ByteKey)
    (layer tree leaf : ℕ) (message : Randomizer) (sig : LayerSignature) :
    QueryProgram K Digest Randomizer 107 :=
  bindProgram
    (wotsRecoveryUnderProgram encode seed layer tree leaf (nodeValueBytes message) sig.sigma sig.count)
    (fun pk => merkleRecoverProgram encode seed layer tree pk leaf sig.auth)

def layerRecover [DecidableEq K] (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree leaf : ℕ) (message : Randomizer) (sig : LayerSignature) :
    PMF (Randomizer × Memo K Digest) :=
  (wotsRecoveryUnder encode table seed layer tree leaf (nodeValueBytes message) sig.sigma sig.count).bind
    (fun pk => merkleRecover encode pk.2 seed layer tree pk.1 leaf sig.auth)

theorem layer_recover_eval [DecidableEq K] (encode : ByteKey → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree leaf : ℕ)
    (message : Randomizer) (sig : LayerSignature) :
    evalProgram digestDraw (layerRecoverProgram encode seed layer tree leaf message sig) table =
      layerRecover encode table seed layer tree leaf message sig := by
  simp only [layerRecoverProgram, evalProgram_bind, wots_recovery_under_eval,
    merkle_recover_eval, layerRecover]

theorem layer_recover_map (encode : K → L) (labels : ByteKey → K)
    (seed : ByteKey) (layer tree leaf : ℕ) (message : Randomizer) (sig : LayerSignature) :
    mapProgram encode (layerRecoverProgram labels seed layer tree leaf message sig) =
      layerRecoverProgram (encode ∘ labels) seed layer tree leaf message sig := by
  simp only [layerRecoverProgram, mapProgram_bind, wots_recovery_under_map,
    merkle_recover_map]

theorem layer_recover_selected (seed : ByteKey) (layer tree leaf : ℕ)
    (message : Randomizer) (sig : LayerSignature) (hs : seed.length = 32) :
    SelectedBudget nodeQuery (layerRecoverProgram id seed layer tree leaf message sig) 106 := by
  exact selectedBudget_bind _ _ _ 97 9
    (wots_recovery_under_selected _ _ _ _ _ _ _ hs (node_value_bytes_length message))
    (fun _ => selectedBudget_total _ _)

end
end C10Probability

import C10Probability.LayerRecover

/-! Ordered two-coordinate recovery, including the original default signature
for a missing layer. Zero returned by WOTS is still consumed by its path and by
the following layer; there is no invented early refusal in this client. -/
namespace C10Probability
noncomputable section

variable {K L : Type*}

def hypertreeRecoverProgram (encode : ByteKey → K) (seed : ByteKey)
    (signatures : List LayerSignature) : (steps layer index : ℕ) → Randomizer →
    QueryProgram K Digest Randomizer (steps * 107)
  | 0, _, _, current => .done current
  | steps + 1, layer, index, current =>
      castProgram (Nat.succ_mul steps 107).symm
        (bindProgram (layerRecoverProgram encode seed layer (hypertreeParent index)
          (hypertreeLeaf index) current ((signatures[layer]?).getD emptyLayerSignature))
          (fun root => hypertreeRecoverProgram encode seed signatures steps
            (layer + 1) (hypertreeParent index) root))

attribute [irreducible] hypertreeRecoverProgram

def hypertreeRecover [DecidableEq K] (encode : ByteKey → K) (seed : ByteKey)
    (signatures : List LayerSignature) : (steps layer index : ℕ) → Randomizer →
    Memo K Digest → PMF (Randomizer × Memo K Digest)
  | 0, _, _, current, table => PMF.pure (current, table)
  | steps + 1, layer, index, current, table =>
      (layerRecover encode table seed layer (hypertreeParent index) (hypertreeLeaf index)
        current ((signatures[layer]?).getD emptyLayerSignature)).bind
          (fun root => hypertreeRecover encode seed signatures steps
            (layer + 1) (hypertreeParent index) root.1 root.2)

theorem hypertree_recover_eval [DecidableEq K] (encode : ByteKey → K)
    (seed : ByteKey) (signatures : List LayerSignature) (steps layer index : ℕ)
    (current : Randomizer) (table : Memo K Digest) :
    evalProgram digestDraw
      (hypertreeRecoverProgram encode seed signatures steps layer index current) table =
      hypertreeRecover encode seed signatures steps layer index current table := by
  induction steps generalizing layer index current table with
  | zero => simp only [hypertreeRecoverProgram, hypertreeRecover, evalProgram]
  | succ steps ih =>
    simp only [hypertreeRecoverProgram, evalProgram_cast, evalProgram_bind,
      layer_recover_eval, ih, hypertreeRecover]

theorem hypertree_recover_map (encode : K → L) (labels : ByteKey → K)
    (seed : ByteKey) (signatures : List LayerSignature) (steps layer index : ℕ)
    (current : Randomizer) :
    mapProgram encode (hypertreeRecoverProgram labels seed signatures steps layer index current) =
      hypertreeRecoverProgram (encode ∘ labels) seed signatures steps layer index current := by
  induction steps generalizing layer index current with
  | zero => simp only [hypertreeRecoverProgram, mapProgram]
  | succ steps ih =>
    simp only [hypertreeRecoverProgram, mapProgram_cast, mapProgram_bind, layer_recover_map, ih]

theorem hypertree_recover_selected (seed : ByteKey) (signatures : List LayerSignature)
    (steps layer index : ℕ) (current : Randomizer) (hs : seed.length = 32) :
    SelectedBudget nodeQuery (hypertreeRecoverProgram id seed signatures steps layer index current)
      (steps * 106) := by
  induction steps generalizing layer index current with
  | zero => simp only [hypertreeRecoverProgram, SelectedBudget]
  | succ steps ih =>
    rw [hypertreeRecoverProgram, selectedBudget_cast, Nat.succ_mul, Nat.add_comm (steps * 106)]
    exact selectedBudget_bind _ _ _ 106 (steps * 106)
      (layer_recover_selected _ _ _ _ _ _ hs) (fun root => ih _ _ root)

end
end C10Probability

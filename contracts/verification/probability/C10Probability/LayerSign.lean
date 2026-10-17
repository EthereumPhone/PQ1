import C10Probability.LayerRecover
import C10Probability.MerkleBuild
import C10Probability.WotsSigningCharges

/-! One actual layer: build the authentication path, derive its WOTS shuffle
sub-seed, sign, and reconstruct the root from the returned signature. The root
returned by the builder is deliberately unused, as in RawLayer.sign. Exhaustion
keeps the accumulated table and omits the recovery calls. -/
namespace C10Probability
noncomputable section

variable {K L : Type*}

abbrev LayerSigned := Option (LayerSignature × Randomizer)

def layerSignAfterProgram (encode : WotsQuery → K) (seed : ByteKey)
    (layer tree leaf : ℕ) (message : Randomizer) (auth : List Randomizer)
    (signed : WotsSignature) : QueryProgram K Digest LayerSigned 107 :=
  match signed with
  | none => .done none
  | some (sigma, count) =>
    let sig : LayerSignature := ⟨sigma, count, auth⟩
    mapReturnProgram (fun root => some (sig, root))
      (layerRecoverProgram (fun key => encode (.inl key)) seed layer tree leaf message sig)

def layerSignAfter [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree leaf : ℕ) (message : Randomizer)
    (auth : List Randomizer) (signed : WotsSignature) : PMF (LayerSigned × Memo K Digest) :=
  match signed with
  | none => PMF.pure (none, table)
  | some (sigma, count) =>
    let sig : LayerSignature := ⟨sigma, count, auth⟩
    (layerRecover (fun key => encode (.inl key)) table seed layer tree leaf message sig).map
      (fun root => (some (sig, root.1), root.2))

theorem layer_sign_after_eval [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree leaf : ℕ)
    (message : Randomizer) (auth : List Randomizer) (signed : WotsSignature) :
    evalProgram digestDraw (layerSignAfterProgram encode seed layer tree leaf message auth signed)
      table = layerSignAfter encode table seed layer tree leaf message auth signed := by
  cases signed with
  | none => rfl
  | some value =>
    rcases value with ⟨sigma, count⟩
    simp only [layerSignAfterProgram, evalProgram_mapReturn, layer_recover_eval,
      layerSignAfter]

theorem layer_sign_after_map (encode : K → L) (labels : WotsQuery → K)
    (seed : ByteKey) (layer tree leaf : ℕ) (message : Randomizer)
    (auth : List Randomizer) (signed : WotsSignature) :
    mapProgram encode (layerSignAfterProgram labels seed layer tree leaf message auth signed) =
      layerSignAfterProgram (encode ∘ labels) seed layer tree leaf message auth signed := by
  cases signed with
  | none => rfl
  | some value =>
    rcases value with ⟨sigma, count⟩
    simp only [layerSignAfterProgram, mapProgram_mapReturn, layer_recover_map, Function.comp_def]

def layerSignProgram (encode : WotsQuery → K) (seed : ByteKey) (layer tree leaf : ℕ)
    (message : Randomizer) (shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32) :
    QueryProgram K Digest LayerSigned (n + 177511) :=
  castProgram (by omega)
    (bindProgram (merkleBuildProgram encode seed layer tree leaf) (fun built =>
      bindProgram (shuffleDeriveProgram (fun key => encode (.inl key)) shuffle (layerShuffleLabel layer))
        (fun subseed => bindProgram
          (wotsSignProgram encode seed layer tree leaf (nodeValueBytes message) subseed n hb)
          (layerSignAfterProgram encode seed layer tree leaf message built.1))))

attribute [irreducible] layerSignProgram

def layerSign [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree leaf : ℕ) (message : Randomizer) (shuffle : ByteKey)
    (n : ℕ) (hb : n ≤ 2 ^ 32) : PMF (LayerSigned × Memo K Digest) :=
  (merkleBuild encode table seed layer tree leaf).bind (fun built =>
    (shuffleDerive (fun key => encode (.inl key)) shuffle (layerShuffleLabel layer) built.2).bind
      (fun subseed => (wotsSign encode subseed.2 seed layer tree leaf
        (nodeValueBytes message) subseed.1 n hb).bind
          (fun signed => layerSignAfter encode signed.2 seed layer tree leaf message built.1.1 signed.1)))

theorem layer_sign_eval [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree leaf : ℕ)
    (message : Randomizer) (shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32) :
    evalProgram digestDraw (layerSignProgram encode seed layer tree leaf message shuffle n hb) table =
      layerSign encode table seed layer tree leaf message shuffle n hb := by
  simp only [layerSignProgram, evalProgram_cast, evalProgram_bind,
    merkle_build_eval, shuffle_derive_eval, wots_sign_eval, layer_sign_after_eval, layerSign]

theorem layer_sign_map (encode : K → L) (labels : WotsQuery → K)
    (seed : ByteKey) (layer tree leaf : ℕ) (message : Randomizer)
    (shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32) :
    mapProgram encode (layerSignProgram labels seed layer tree leaf message shuffle n hb) =
      layerSignProgram (encode ∘ labels) seed layer tree leaf message shuffle n hb := by
  simp only [layerSignProgram, mapProgram_cast, mapProgram_bind, merkle_build_map,
    shuffle_derive_map, wots_sign_map, layer_sign_after_map, Function.comp_def]

theorem layer_sign_public (seed : ByteKey) (layer tree leaf : ℕ)
    (message : Randomizer) (shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32) :
    PublicBudget (layerSignProgram id seed layer tree leaf message shuffle n hb) (n + 155452) := by
  rw [layerSignProgram, publicBudget_cast]
  rw [show n + 155452 = 155135 + (1 + ((n + 209) + 107)) by omega]
  apply publicBudget_bind _ _ 155135 (1 + ((n + 209) + 107))
    (merkle_build_public seed layer tree leaf)
  intro built
  apply publicBudget_bind _ _ 1 ((n + 209) + 107) (publicBudget_total _)
  intro subseed
  exact publicBudget_bind _ _ (n + 209) 107
    (wots_sign_public seed layer tree leaf (nodeValueBytes message) subseed n hb)
    (fun _ => publicBudget_total _)

theorem layer_sign_after_exhausted [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree leaf : ℕ)
    (message : Randomizer) (auth : List Randomizer) :
    layerSignAfter encode table seed layer tree leaf message auth none = PMF.pure (none, table) := by rfl

end
end C10Probability

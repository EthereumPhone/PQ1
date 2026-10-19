import C10Probability.WotsLayerOpening

/-! The concrete two-layer coordinate split and an exact expansion of the
existing hypertree loop. Both failures keep their accumulated cache and the
upper layer consumes the lower layer's returned root. -/
namespace C10Probability
noncomputable section

def wotsLowerAddress (index : Fin (2 ^ 18)) : WotsLogicalAddress :=
  .inl (⟨hypertreeParent index.val, by have := index.isLt; unfold hypertreeParent; omega⟩,
    ⟨hypertreeLeaf index.val, hypertree_leaf_bound index.val⟩)

def wotsUpperAddress (index : Fin (2 ^ 18)) : WotsLogicalAddress :=
  .inr ⟨hypertreeLeaf (hypertreeParent index.val), hypertree_leaf_bound _⟩

theorem wots_two_layer_coordinates (index : Fin (2 ^ 18)) :
    wotsTargetLayer (wotsLowerAddress index, 0) = 0 ∧
      wotsTargetTree (wotsLowerAddress index, 0) = hypertreeParent index.val ∧
      wotsTargetKp (wotsLowerAddress index, 0) = hypertreeLeaf index.val ∧
      wotsTargetLayer (wotsUpperAddress index, 0) = 1 ∧
      wotsTargetTree (wotsUpperAddress index, 0) = 0 ∧
      wotsTargetKp (wotsUpperAddress index, 0) = hypertreeLeaf (hypertreeParent index.val) ∧
      hypertreeParent (hypertreeParent index.val) = 0 := by
  refine ⟨rfl, rfl, rfl, rfl, rfl, rfl, ?_⟩
  have := index.isLt
  unfold hypertreeParent
  omega

def wotsTwoLayerOutput (lower : LayerSignature) (upper : LayerSigned) : HypertreeSigned :=
  upper.map (fun value => ([lower, value.1], value.2))

def wotsTwoLayerProgram (seed shuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32)
    (index : Fin (2 ^ 18)) (current : Randomizer) :
    QueryProgram WotsQuery Digest HypertreeSigned (2 * (n + 177511)) :=
  castProgram (by omega)
    (bindProgram (layerSignProgram id seed 0 (hypertreeParent index.val)
      (hypertreeLeaf index.val) current shuffle n bound) (fun lower =>
        match lower with
        | none => .done none
        | some (sig, root) => mapReturnProgram (wotsTwoLayerOutput sig)
            (layerSignProgram id seed 1 0 (hypertreeLeaf (hypertreeParent index.val)) root shuffle n bound)))

attribute [irreducible] wotsTwoLayerProgram

theorem wots_two_layer_eval (seed shuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32)
    (index : Fin (2 ^ 18)) (current : Randomizer) (table : Memo WotsQuery Digest) :
    evalProgram digestDraw (hypertreeSignProgram id seed shuffle n bound 2 0 index.val current []) table =
      evalProgram digestDraw (wotsTwoLayerProgram seed shuffle n bound index current) table := by
  rw [hypertreeSignProgram, wotsTwoLayerProgram, evalProgram_cast, evalProgram_cast,
    evalProgram_bind, evalProgram_bind]
  apply bind_eq_of_support
  intro lower _
  rcases lower with ⟨lower, cache⟩
  cases lower with
  | none => simp only [evalProgram]
  | some value =>
    obtain ⟨sig, root⟩ := value
    dsimp only
    rw [hypertreeSignProgram, evalProgram_cast, evalProgram_bind, evalProgram_mapReturn,
      (wots_two_layer_coordinates index).2.2.2.2.2.2, PMF.map]
    congr 1
    funext upper
    rcases upper with ⟨upper, after⟩
    cases upper with
    | none => simp only [evalProgram, wotsTwoLayerOutput, Function.comp_def, Option.map_none]
    | some value =>
      obtain ⟨sig', root'⟩ := value
      dsimp only
      rw [hypertreeSignProgram]
      simp only [evalProgram, wotsTwoLayerOutput, Function.comp_def, Option.map_some,
        List.nil_append, List.cons_append]

end
end C10Probability

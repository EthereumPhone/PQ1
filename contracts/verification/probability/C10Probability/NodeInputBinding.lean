import C10Probability.ForsInputs

/-! Fixed-width node serialization binds the ordered children. These facts
do not assume injectivity of the hash or of truncated address coordinates. -/
namespace C10Probability
noncomputable section

theorem node_block_injective : Function.Injective nodeBlock := by
  intro first second equal
  apply randomizerBytesEquiv.symm.injective
  exact List.ofFn_injective (List.append_cancel_right equal)

theorem node_pair_blocks_injective (left right left' right' : Randomizer)
    (equal : nodeBlock left ++ nodeBlock right = nodeBlock left' ++ nodeBlock right') :
    left = left' ∧ right = right' := by
  have widths : (nodeBlock left).length = (nodeBlock left').length := by rw [node_block_length, node_block_length]
  exact ⟨node_block_injective (List.append_inj_left equal widths),
    node_block_injective (List.append_inj_right equal widths)⟩

theorem merkle_pair_children (seed : ByteKey) (layer tree height parent : ℕ)
    (left right left' right' : Randomizer)
    (equal : merklePairInput seed layer tree height parent left right =
      merklePairInput seed layer tree height parent left' right') :
    left = left' ∧ right = right' := by
  simp only [merklePairInput, List.append_assoc] at equal
  exact node_pair_blocks_injective _ _ _ _ (List.append_cancel_left (List.append_cancel_left equal))

theorem fors_pair_children (seed : ByteKey) (ht tree height parent : ℕ)
    (left right left' right' : Randomizer)
    (equal : forsPairInput seed ht tree height parent left right =
      forsPairInput seed ht tree height parent left' right') :
    left = left' ∧ right = right' := by
  simp only [forsPairInput, List.append_assoc] at equal
  exact node_pair_blocks_injective _ _ _ _ (List.append_cancel_left (List.append_cancel_left equal))

theorem fors_leaf_input_injective (seed : ByteKey) (ht tree index : ℕ) :
    Function.Injective (forsLeafInput seed ht tree index) := by
  intro first second equal
  exact node_block_injective (List.append_cancel_left equal)

end
end C10Probability

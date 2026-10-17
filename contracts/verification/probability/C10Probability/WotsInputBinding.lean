import C10Probability.NodeInputBinding
import C10Probability.WotsLeaf

/-! WOTS compression binds the ordered fixed-width nodes. Chain inputs bind
their node at a common coordinate; truncated addresses need not be globally
injective for either statement. -/
namespace C10Probability
noncomputable section

theorem wots_chain_input_injective (seed : ByteKey) (layer tree kp index position : ℕ) :
    Function.Injective (wotsChainInput seed layer tree kp index position) := by
  intro first second equal
  apply node_block_injective
  simp only [wotsChainInput, List.append_assoc] at equal
  exact List.append_cancel_left (List.append_cancel_left equal)

theorem node_blocks_injective : Function.Injective (List.flatMap nodeBlock) := by
  intro first
  induction first with
  | nil =>
    intro second equal
    have widths := congrArg List.length equal
    rw [node_blocks_length, node_blocks_length] at widths
    have empty : second.length = 0 := by simp only [List.length_nil, Nat.mul_zero] at widths; omega
    exact (List.length_eq_zero_iff.mp empty).symm
  | cons value rest ih =>
    intro second equal
    cases second with
    | nil =>
      have widths := congrArg List.length equal
      rw [node_blocks_length, node_blocks_length] at widths
      simp only [List.length_nil, List.length_cons, Nat.mul_zero] at widths
      omega
    | cons value' rest' =>
      simp only [List.flatMap_cons] at equal
      have widths : (nodeBlock value).length = (nodeBlock value').length := by
        rw [node_block_length, node_block_length]
      have head := node_block_injective (List.append_inj_left equal widths)
      have tail := ih (List.append_inj_right equal widths)
      exact congrArg₂ List.cons head tail

theorem wots_pk_input_injective (seed : ByteKey) (layer tree kp : ℕ) :
    Function.Injective (wotsPkInput seed layer tree kp) := by
  intro first second equal
  exact node_blocks_injective (List.append_cancel_left equal)

end
end C10Probability

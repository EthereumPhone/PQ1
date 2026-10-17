import C10Probability.WotsLeaf
import C10Probability.TreeRun

/-! Merkle pair inputs use kind2, height+1, and the actual parent coordinate.
Both children retain their 16-byte value followed by16 zero bytes. -/
namespace C10Probability
noncomputable section

def merklePairInput (seed : ByteKey) (layer tree height parent : ℕ)
    (left right : Randomizer) : ByteKey :=
  seed ++ c10Address layer tree 2 0 0 (height + 1) parent ++ nodeBlock left ++ nodeBlock right

def treePairInput (seed : ByteKey) (layer tree kp height : ℕ)
    (left right : Randomizer) : ByteKey :=
  merklePairInput seed layer tree height (kp / 2 ^ (height + 1)) left right

theorem merkle_pair_length (seed : ByteKey) (layer tree height parent : ℕ)
    (left right : Randomizer) (hs : seed.length = 32) :
    (merklePairInput seed layer tree height parent left right).length = 128 := by
  simp [merklePairInput, c10_address_length, node_block_length, hs]

theorem merkle_pair_selected (seed : ByteKey) (layer tree height parent : ℕ)
    (left right : Randomizer) (hs : seed.length = 32) :
    nodeQuery (merklePairInput seed layer tree height parent left right) = true := by
  unfold merklePairInput nodeBlock
  simp only [← List.append_assoc]
  apply node_query_pair _ _ _ _ hs (c10_address_length _ _ _ _ _ _ _)
    (by simp) (by simp)
  rw [c10_address_kind]
  decide +kernel

def treeRoot (stack : List (Randomizer × ℕ)) : Randomizer :=
  (stack.headD (0, 0)).1

def siblingIndex (index : ℕ) : ℕ := if index % 2 = 0 then index + 1 else index - 1

end
end C10Probability

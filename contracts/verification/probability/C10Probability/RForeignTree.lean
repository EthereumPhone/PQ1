import C10Probability.RForeignWots
import C10Probability.C10Keygen
import C10Probability.MerkleBuild

/-! Every private call in the actual WOTS tree/keygen execution is foreign to
valid R contexts. This includes the initialized keygen cache. -/
namespace C10Probability
noncomputable section

variable {S : Type*}

attribute [local irreducible] treeProgram

theorem subtree_r_zero (seed : ByteKey) (layer tree : ℕ)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S) :
    SelectedBudget rPrivateQuery (subtreeProgram id seed layer tree remember initial) 0 := by
  rw [subtreeProgram, selectedBudget_cast, selectedBudget_mapReturn]
  have step (count : ℕ) := selected_zero_tree
    (K := WotsQuery) (α := Digest) (N := Randomizer) (S := S)
    rPrivateQuery 345 (wotsLeafProgram id seed layer tree) (wots_leaf_r_zero seed layer tree)
    (fun kp h l r => id (.inl (treePairInput seed layer tree kp h l r)))
    randomizerOfDigest (fun _ _ _ _ => rfl) remember count 0 [] PUnit.unit initial
  exact step 512

theorem subtree_root_r_zero (seed : ByteKey) (layer tree : ℕ) :
    SelectedBudget rPrivateQuery (subtreeRootProgram id seed layer tree) 0 := by
  rw [subtreeRootProgram, selectedBudget_mapReturn]
  exact subtree_r_zero _ _ _ _ _

theorem merkle_build_r_zero (seed : ByteKey) (layer tree target : ℕ) :
    SelectedBudget rPrivateQuery (merkleBuildProgram id seed layer tree target) 0 := by
  rw [merkleBuildProgram, selectedBudget_mapReturn]
  exact subtree_r_zero _ _ _ _ _

theorem c10_keygen_r_zero (publicSeed : Digest) :
    SelectedBudget rPrivateQuery (c10KeygenProgram id publicSeed) 0 := by
  rw [c10KeygenProgram, selectedBudget_mapReturn]
  exact subtree_root_r_zero _ _ _

theorem c10_keygen_r_history (publicSeed : Digest)
    (out : (ByteKey × ByteKey) × Memo WotsQuery Digest)
    (supported : out ∈ (c10Keygen id (fun _ => none) publicSeed).support) :
    RContextHistory ∅ out.2 := by
  apply r_context_history_foreign (c10KeygenProgram id publicSeed)
    (c10_keygen_r_zero publicSeed) ∅ (fun _ => none) r_context_history_empty out
  rwa [c10_keygen_eval]

end
end C10Probability

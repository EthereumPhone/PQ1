import C10Probability.MerkleInputs

/-! All512 WOTS leaves followed by the actual511 merges. The generic remembered
state supports both root-only and authentication-building clients. -/
namespace C10Probability
noncomputable section

variable {K L S : Type*}

def subtreeProgram (encode : WotsQuery → K) (seed : ByteKey) (layer tree : ℕ)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S) :
    QueryProgram K Digest (List (Randomizer × ℕ) × S) 177151 :=
  castProgram subtree_raw_calls (mapReturnProgram (eraseTreeState (runShape 512 []))
    (treeProgram 345 (wotsLeafProgram encode seed layer tree)
      (fun kp h l r => encode (.inl (treePairInput seed layer tree kp h l r)))
      randomizerOfDigest remember 512 0 [] PUnit.unit initial))

attribute [irreducible] subtreeProgram

def subtreeLoop [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree : ℕ)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S) :
    PMF ((List (Randomizer × ℕ) × S) × Memo K Digest) :=
  treeLoop digestDraw (fun kp memo => wotsLeaf encode memo seed layer tree kp)
    (fun kp h l r => encode (.inl (treePairInput seed layer tree kp h l r)))
    randomizerOfDigest remember 512 0 [] initial table

theorem subtree_program_eval [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree : ℕ)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S) :
    evalProgram digestDraw (subtreeProgram encode seed layer tree remember initial) table =
      subtreeLoop encode table seed layer tree remember initial := by
  rw [subtreeProgram, evalProgram_cast, evalProgram_mapReturn]
  change (evalProgram digestDraw _ table).map (eraseTreeOutput (runShape 512 [])) = _
  rw [tree_program_eval]
  simp only [wots_leaf_eval, eraseStack, subtreeLoop]

theorem subtree_program_map (encode : K → L) (labels : WotsQuery → K)
    (seed : ByteKey) (layer tree : ℕ)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S) :
    mapProgram encode (subtreeProgram labels seed layer tree remember initial) =
      subtreeProgram (encode ∘ labels) seed layer tree remember initial := by
  simp only [subtreeProgram, mapProgram_cast, mapProgram_mapReturn,
    tree_program_map, wots_leaf_map, Function.comp_def]

set_option maxRecDepth 20000 in
theorem subtree_program_public (seed : ByteKey) (layer tree : ℕ)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S) :
    PublicBudget (subtreeProgram id seed layer tree remember initial) 155135 := by
  rw [subtreeProgram, publicBudget_cast, publicBudget_mapReturn, ← subtree_public_calls]
  exact tree_program_public 345 302 _ (wots_leaf_public seed layer tree) _ _ _ _ _ _ _ _

def subtreeRootProgram (encode : WotsQuery → K) (seed : ByteKey) (layer tree : ℕ) :
    QueryProgram K Digest Randomizer 177151 :=
  mapReturnProgram (fun out => treeRoot out.1)
    (subtreeProgram encode seed layer tree (fun _ _ _ _ (_ : Unit) => ()) ())

def subtreeRoot [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree : ℕ) : PMF (Randomizer × Memo K Digest) :=
  (subtreeLoop encode table seed layer tree (fun _ _ _ _ (_ : Unit) => ()) ()).map
    (fun out => (treeRoot out.1.1, out.2))

theorem subtree_root_eval [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree : ℕ) :
    evalProgram digestDraw (subtreeRootProgram encode seed layer tree) table =
      subtreeRoot encode table seed layer tree := by
  rw [subtreeRootProgram, evalProgram_mapReturn, subtree_program_eval]
  rfl

theorem subtree_root_map (encode : K → L) (labels : WotsQuery → K)
    (seed : ByteKey) (layer tree : ℕ) :
    mapProgram encode (subtreeRootProgram labels seed layer tree) =
      subtreeRootProgram (encode ∘ labels) seed layer tree := by
  simp only [subtreeRootProgram, mapProgram_mapReturn, subtree_program_map]

theorem subtree_root_public (seed : ByteKey) (layer tree : ℕ) :
    PublicBudget (subtreeRootProgram id seed layer tree) 155135 := by
  rw [subtreeRootProgram, publicBudget_mapReturn]
  exact subtree_program_public _ _ _ _ _

end
end C10Probability

import C10Probability.WotsTreeOpening

/-! All512 WOTS leaves and511 Merkle merges keep the actual remembered state.
This supports both the key-generation root and the signing authentication path,
without exposing any selected WOTS node at positions0through6. -/
namespace C10Probability
noncomputable section
variable {S : Type*}

def wotsSubtreeOpening (seed : ByteKey) (target : WotsCutTarget) (previous : Randomizer)
    (address : WotsLogicalAddress)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S) :
    OpeningProgram WotsQuery Unit Digest Digest (List (Randomizer × ℕ) × S) 177151 :=
  castOpening subtree_raw_calls (mapOpeningReturn (eraseTreeState (runShape 512 []))
    (openingTreeProgram 345 (wotsTreeLeafOpening seed target previous address)
      (fun kp height left right => .inl (treePairInput seed (wotsTargetLayer (address, 0))
        (wotsTargetTree (address, 0)) kp height left right))
      randomizerOfDigest remember 512 0 [] PUnit.unit initial))

attribute [irreducible] wotsSubtreeOpening

set_option maxRecDepth 20000 in
theorem wots_subtree_opening_refines (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S) (secret : Digest) :
    OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret id
      (wotsSubtreeOpening seed target previous address remember initial)
      (subtreeProgram id seed (wotsTargetLayer (address, 0)) (wotsTargetTree (address, 0)) remember initial) := by
  rw [wotsSubtreeOpening, subtreeProgram]
  apply opening_refines_cast
  exact opening_refines_map digestDraw (wotsCutCommit seed target) randomizerOfDigest
    (wotsCutIncoming seed target previous) secret id id
    (eraseTreeState (runShape 512 [])) (eraseTreeState (runShape 512 [])) (fun _ => rfl) _ _
    (opening_tree_refines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret 345 _ _
      (fun kp => wots_tree_leaf_opening_refines seed target previous address kp secret)
      _ _ remember 512 0 [] PUnit.unit initial)

set_option maxRecDepth 20000 in
theorem wots_subtree_opening_sealed (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S) :
    OpeningSealed (wotsCutIncoming seed target previous)
      (wotsSubtreeOpening seed target previous address remember initial) := by
  rw [wotsSubtreeOpening, opening_sealed_cast, opening_sealed_map]
  exact opening_tree_sealed_bounded (wotsCutIncoming seed target previous) 345 512 _
    (wots_tree_leaf_opening_sealed seed target previous address) _
    (fun kp height left right => merkle_pair_ne_wots_incoming seed target previous
      _ _ height _ left right) _ remember 512 0 (by omega) [] PUnit.unit initial

set_option maxRecDepth 20000 in
theorem wots_subtree_opening_budget (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsSubtreeOpening seed target previous address remember initial)) 155135 := by
  rw [wotsSubtreeOpening, redact_opening_cast, selectedBudget_cast,
    redact_opening_mapReturn, selectedBudget_mapReturn, ← subtree_public_calls]
  exact opening_tree_budget_bounded _ 345 302 512 _
    (wots_tree_leaf_opening_budget seed target previous address) _ _ remember
    512 0 (by omega) [] PUnit.unit initial

def wotsMerkleBuildOpening (seed : ByteKey) (target : WotsCutTarget) (previous : Randomizer)
    (address : WotsLogicalAddress) (leaf : ℕ) :
    OpeningProgram WotsQuery Unit Digest Digest (List Randomizer × Randomizer) 177151 :=
  mapOpeningReturn (fun out => (out.2.nodes, treeRoot out.1))
    (wotsSubtreeOpening seed target previous address (authRemember leaf) emptyAuthKeep)

theorem wots_merkle_build_opening_refines (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (leaf : ℕ) (secret : Digest) :
    OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret id
      (wotsMerkleBuildOpening seed target previous address leaf)
      (merkleBuildProgram id seed (wotsTargetLayer (address, 0)) (wotsTargetTree (address, 0)) leaf) := by
  exact opening_refines_map digestDraw (wotsCutCommit seed target) randomizerOfDigest
    (wotsCutIncoming seed target previous) secret id id
    (fun out : List (Randomizer × ℕ) × AuthKeep => (out.2.nodes, treeRoot out.1))
    (fun out : List (Randomizer × ℕ) × AuthKeep => (out.2.nodes, treeRoot out.1))
    (fun _ => rfl) _ _ (wots_subtree_opening_refines seed target previous address _ _ secret)

theorem wots_merkle_build_opening_sealed (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (leaf : ℕ) :
    OpeningSealed (wotsCutIncoming seed target previous)
      (wotsMerkleBuildOpening seed target previous address leaf) := by
  rw [wotsMerkleBuildOpening, opening_sealed_map]
  exact wots_subtree_opening_sealed seed target previous address _ _

theorem wots_merkle_build_opening_budget (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (leaf : ℕ) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsMerkleBuildOpening seed target previous address leaf)) 155135 := by
  rw [wotsMerkleBuildOpening, redact_opening_mapReturn, selectedBudget_mapReturn]
  exact wots_subtree_opening_budget seed target previous address _ _

def wotsSubtreeRootOpening (seed : ByteKey) (target : WotsCutTarget) (previous : Randomizer)
    (address : WotsLogicalAddress) : OpeningProgram WotsQuery Unit Digest Digest Randomizer 177151 :=
  mapOpeningReturn (fun out => treeRoot out.1)
    (wotsSubtreeOpening seed target previous address (fun _ _ _ _ (_ : Unit) => ()) ())

theorem wots_subtree_root_opening_refines (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (secret : Digest) :
    OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret id
      (wotsSubtreeRootOpening seed target previous address)
      (subtreeRootProgram id seed (wotsTargetLayer (address, 0)) (wotsTargetTree (address, 0))) := by
  exact opening_refines_map digestDraw (wotsCutCommit seed target) randomizerOfDigest
    (wotsCutIncoming seed target previous) secret id id
    (fun out : List (Randomizer × ℕ) × Unit => treeRoot out.1)
    (fun out : List (Randomizer × ℕ) × Unit => treeRoot out.1) (fun _ => rfl) _ _
    (wots_subtree_opening_refines seed target previous address _ _ secret)

theorem wots_subtree_root_opening_sealed (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) :
    OpeningSealed (wotsCutIncoming seed target previous) (wotsSubtreeRootOpening seed target previous address) := by
  rw [wotsSubtreeRootOpening, opening_sealed_map]
  exact wots_subtree_opening_sealed seed target previous address _ _

theorem wots_subtree_root_opening_budget (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsSubtreeRootOpening seed target previous address)) 155135 := by
  rw [wotsSubtreeRootOpening, redact_opening_mapReturn, selectedBudget_mapReturn]
  exact wots_subtree_opening_budget seed target previous address _ _

end
end C10Probability

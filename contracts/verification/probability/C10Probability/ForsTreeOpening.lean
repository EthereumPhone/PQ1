import C10Probability.OpeningTree
import C10Probability.ForsLeafOpening
import C10Probability.ForsTree

/-! Exact hidden-node counterparts of the ordinary FORS tree and signing
programs. The symbolic signature secret is not disclosed during tree building.
Every merge and authentication-path update uses the existing tree schedule. -/
namespace C10Probability
noncomputable section
variable {S : Type*}

def forsTreeStateOpening (target : ForsTarget) (seed : ByteKey) (ht tree : ℕ)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S) :
    OpeningProgram WotsQuery ByteKey Digest Digest (List (Randomizer × ℕ) × S) 6143 :=
  castOpening fors_tree_raw_calls (mapOpeningReturn (eraseTreeState (runShape 2048 []))
    (openingTreeProgram 2 (forsLeafOpening target seed ht tree)
      (fun leaf h l r => .inl (forsTreePairInput seed ht tree leaf h l r))
      randomizerOfDigest remember 2048 0 [] PUnit.unit initial))

attribute [irreducible] forsTreeStateOpening

def forsTreeOpening (target : ForsTarget) (seed : ByteKey) (ht tree leaf : ℕ) :
    OpeningProgram WotsQuery ByteKey Digest Digest (Randomizer × List Randomizer) 6143 :=
  mapOpeningReturn (fun out => (treeRoot out.1, out.2))
    (forsTreeStateOpening target seed ht tree (forsRemember leaf) (List.replicate 11 0))

def forsRootOpening (target : ForsTarget) (seed : ByteKey) (ht tree : ℕ) :
    OpeningProgram WotsQuery ByteKey Digest Digest Randomizer 6143 :=
  mapOpeningReturn Prod.fst (forsTreeOpening target seed ht tree 0)

def forsSignOpening (target : ForsTarget) (seed : ByteKey) (ht tree leaf : ℕ) :
    OpeningProgram WotsQuery ByteKey Digest Digest (Option Randomizer × List Randomizer) 6144 :=
  bindOpening (forsSecretOpening target ht tree leaf) (fun secret =>
    mapOpeningReturn (fun out => (secret, out.2)) (forsTreeOpening target seed ht tree leaf))

set_option maxRecDepth 80000 in
theorem fors_tree_state_opening_refines (target : ForsTarget) (secret : Digest)
    (seed : ByteKey) (ht tree : ℕ)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S) :
    OpeningRefines digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret id
      (forsTreeStateOpening target seed ht tree remember initial)
      (forsTreeStateProgram id seed ht tree remember initial) := by
  rw [forsTreeStateOpening, forsTreeStateProgram]
  apply opening_refines_cast
  exact opening_refines_map digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target)
    secret id id (eraseTreeState (runShape 2048 [])) (eraseTreeState (runShape 2048 []))
    (fun _ => rfl) _ _
    (opening_tree_refines digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target)
      secret 2 _ _ (fors_leaf_opening_refines target secret seed ht tree)
      _ _ remember 2048 0 [] PUnit.unit initial)

theorem fors_tree_opening_refines (target : ForsTarget) (secret : Digest)
    (seed : ByteKey) (ht tree leaf : ℕ) :
    OpeningRefines digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret id
      (forsTreeOpening target seed ht tree leaf) (forsTreeProgram id seed ht tree leaf) := by
  exact opening_refines_map digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target)
    secret id id
    (fun out : List (Randomizer × ℕ) × List Randomizer => (treeRoot out.1, out.2))
    (fun out : List (Randomizer × ℕ) × List Randomizer => (treeRoot out.1, out.2))
    (fun _ => rfl) _ _
    (fors_tree_state_opening_refines target secret seed ht tree _ _)

theorem fors_root_opening_refines (target : ForsTarget) (secret : Digest)
    (seed : ByteKey) (ht tree : ℕ) :
    OpeningRefines digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret id
      (forsRootOpening target seed ht tree) (forsRootProgram id seed ht tree) := by
  exact opening_refines_map digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target)
    secret id id Prod.fst Prod.fst (fun _ => rfl) _ _ (fors_tree_opening_refines target secret seed ht tree 0)

theorem fors_sign_opening_refines (target : ForsTarget) (secret : Digest)
    (seed : ByteKey) (ht tree leaf : ℕ) :
    OpeningRefines digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret
      (fun out => (deferredNode secret out.1, out.2))
      (forsSignOpening target seed ht tree leaf) (forsSignProgram id seed ht tree leaf) := by
  have correspondence := opening_refines_bind digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target)
    secret (deferredNode secret)
    (fun out : Option Randomizer × List Randomizer => (deferredNode secret out.1, out.2))
    (forsSecretOpening target ht tree leaf) (forsSecretProgram ht tree leaf)
    (fun node => mapOpeningReturn (fun out => (node, out.2))
      (forsTreeOpening target seed ht tree leaf))
    (fun node => mapReturnProgram (fun out => (node, out.2))
      (forsTreeProgram id seed ht tree leaf)) (fors_secret_opening_refines target secret ht tree leaf)
    (fun node => opening_refines_map digestDraw nodeCommitEncode randomizerOfDigest
      (forsTargetKey target) secret id _
      (fun out : Randomizer × List Randomizer => (node, out.2))
      (fun out : Randomizer × List Randomizer => (deferredNode secret node, out.2))
      (fun _ => rfl) _ _
      (fors_tree_opening_refines target secret seed ht tree leaf))
  intro table opened cached
  simpa only [evalProgram_bind, forsSecretProgram, forsSignProgram, evalProgram,
    PMF.pure_bind, PMF.bind_bind] using correspondence table opened cached

set_option maxRecDepth 80000 in
theorem fors_tree_state_opening_sealed (target : ForsTarget) (seed : ByteKey) (ht tree : ℕ)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S) :
    OpeningSealed (forsTargetKey target) (forsTreeStateOpening target seed ht tree remember initial) := by
  rw [forsTreeStateOpening, opening_sealed_cast, opening_sealed_map]
  exact opening_tree_sealed (forsTargetKey target) 2 _ (fors_leaf_opening_sealed target seed ht tree)
    _ (fun _ _ _ _ => fors_target_not_public target _) _ remember 2048 0 [] PUnit.unit initial

theorem fors_tree_opening_sealed (target : ForsTarget) (seed : ByteKey) (ht tree leaf : ℕ) :
    OpeningSealed (forsTargetKey target) (forsTreeOpening target seed ht tree leaf) := by
  rw [forsTreeOpening, opening_sealed_map]
  exact fors_tree_state_opening_sealed target seed ht tree _ _

theorem fors_root_opening_sealed (target : ForsTarget) (seed : ByteKey) (ht tree : ℕ) :
    OpeningSealed (forsTargetKey target) (forsRootOpening target seed ht tree) := by
  rw [forsRootOpening, opening_sealed_map]
  exact fors_tree_opening_sealed target seed ht tree 0

theorem fors_sign_opening_sealed (target : ForsTarget) (seed : ByteKey) (ht tree leaf : ℕ) :
    OpeningSealed (forsTargetKey target) (forsSignOpening target seed ht tree leaf) := by
  apply opening_sealed_bind (forsTargetKey target) _ _ (fors_secret_opening_sealed target ht tree leaf)
  intro node
  rw [opening_sealed_map]
  exact fors_tree_opening_sealed target seed ht tree leaf

set_option maxRecDepth 80000 in
theorem fors_tree_state_opening_budget (target : ForsTarget) (seed : ByteKey) (ht tree : ℕ)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (forsTreeStateOpening target seed ht tree remember initial)) 4095 := by
  rw [forsTreeStateOpening, redact_opening_cast, selectedBudget_cast,
    redact_opening_mapReturn, selectedBudget_mapReturn, ← fors_tree_public_calls]
  exact opening_tree_budget _ 2 1 _ (fors_leaf_opening_budget target seed ht tree)
    _ _ remember 2048 0 [] PUnit.unit initial

theorem fors_tree_opening_budget (target : ForsTarget) (seed : ByteKey) (ht tree leaf : ℕ) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (forsTreeOpening target seed ht tree leaf)) 4095 := by
  rw [forsTreeOpening, redact_opening_mapReturn, selectedBudget_mapReturn]
  exact fors_tree_state_opening_budget target seed ht tree _ _

theorem fors_root_opening_budget (target : ForsTarget) (seed : ByteKey) (ht tree : ℕ) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (forsRootOpening target seed ht tree)) 4095 := by
  rw [forsRootOpening, redact_opening_mapReturn, selectedBudget_mapReturn]
  exact fors_tree_opening_budget target seed ht tree 0

theorem fors_sign_opening_budget (target : ForsTarget) (seed : ByteKey) (ht tree leaf : ℕ) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (forsSignOpening target seed ht tree leaf)) 4095 := by
  apply opening_selected_bind _ _ _ 0 4095 (fors_secret_opening_budget target ht tree leaf)
  intro node
  rw [redact_opening_mapReturn, selectedBudget_mapReturn]
  exact fors_tree_opening_budget target seed ht tree leaf

end
end C10Probability

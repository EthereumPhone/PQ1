import C10Probability.OpeningSealed
import C10Probability.ForsTarget
import C10Probability.ForsLeaf

/-! The selected private node is represented by none until an actual public
disclosure. Internal leaf hashes use a commitment, preserving the public memo
entry without exposing the node. Every other private derivation stays a query. -/
namespace C10Probability
noncomputable section

def deferredNode (secret : Digest) (node : Option Randomizer) : Randomizer :=
  node.getD (randomizerOfDigest secret)

def forsSecretProgram (ht tree leaf : ℕ) : QueryProgram WotsQuery Digest Randomizer 1 :=
  .query (.inr (forsPrivateTail ht tree leaf)) (fun value => .done (randomizerOfDigest value))

def forsSecretOpening (target : ForsTarget) (ht tree leaf : ℕ) :
    OpeningProgram WotsQuery ByteKey Digest Digest (Option Randomizer) 1 :=
  if (.inr (forsPrivateTail ht tree leaf) : WotsQuery) = forsTargetKey target then .done none
  else .query (.inr (forsPrivateTail ht tree leaf))
    (fun value => .done (some (randomizerOfDigest value)))

def nodeHashOpening (label : ByteKey) : Option Randomizer →
    OpeningProgram WotsQuery ByteKey Digest Digest Randomizer 1
  | none => .commit label (fun reply => .done (randomizerOfDigest reply))
  | some node => .query (.inl (label ++ nodeBlock node))
      (fun reply => .done (randomizerOfDigest reply))

def forsLeafOpening (target : ForsTarget) (seed : ByteKey) (ht tree leaf : ℕ) :
    OpeningProgram WotsQuery ByteKey Digest Digest Randomizer 2 :=
  bindOpening (forsSecretOpening target ht tree leaf)
    (nodeHashOpening (seed ++ c10Address 0 ht 3 tree 0 0 leaf))

theorem fors_secret_opening_refines (target : ForsTarget) (secret : Digest) (ht tree leaf : ℕ) :
    OpeningRefines digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret
      (deferredNode secret) (forsSecretOpening target ht tree leaf) (forsSecretProgram ht tree leaf) := by
  intro table opened cached
  unfold forsSecretOpening
  split
  next equal =>
    rw [forsSecretProgram, evalProgram_cached digestDraw _ _ table secret (equal ▸ cached)]
    simp only [evalOpening, PMF.pure_map, openingProject, deferredNode, Option.getD_none, evalProgram]
  next different =>
    simp only [forsSecretProgram, evalOpening, PMF.map_bind, evalProgram]
    congr 1
    funext reply
    simp only [PMF.pure_map, openingProject, deferredNode, Option.getD_some]

theorem node_hash_opening_refines (target : ForsTarget) (secret : Digest)
    (label : ByteKey) (node : Option Randomizer) :
    OpeningRefines digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret id
      (nodeHashOpening label node)
      (.query (.inl (label ++ nodeBlock (deferredNode secret node)))
        (fun reply => .done (n := 0) (randomizerOfDigest reply))) := by
  intro table opened _
  cases node <;> simp only [nodeHashOpening, deferredNode, Option.getD_none, Option.getD_some,
    evalOpening, nodeCommitEncode, PMF.map_bind, PMF.pure_map, openingProject, id_eq, evalProgram]

theorem fors_leaf_opening_refines (target : ForsTarget) (secret : Digest)
    (seed : ByteKey) (ht tree leaf : ℕ) :
    OpeningRefines digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret id
      (forsLeafOpening target seed ht tree leaf) (forsLeafProgram id seed ht tree leaf) := by
  have bound := opening_refines_bind digestDraw nodeCommitEncode randomizerOfDigest
    (forsTargetKey target) secret (deferredNode secret) id
    (forsSecretOpening target ht tree leaf) (forsSecretProgram ht tree leaf)
    (nodeHashOpening (seed ++ c10Address 0 ht 3 tree 0 0 leaf))
    (fun node => .query (.inl (forsLeafInput seed ht tree leaf node))
      (fun reply => .done (n := 0) (randomizerOfDigest reply)))
    (fors_secret_opening_refines target secret ht tree leaf)
    (fun node => node_hash_opening_refines target secret _ node)
  exact bound

theorem fors_secret_opening_sealed (target : ForsTarget) (ht tree leaf : ℕ) :
    OpeningSealed (forsTargetKey target) (forsSecretOpening target ht tree leaf) := by
  unfold forsSecretOpening
  split
  · trivial
  next different => exact ⟨different, fun _ => trivial⟩

theorem node_hash_opening_sealed (target : ForsTarget) (label : ByteKey) (node : Option Randomizer) :
    OpeningSealed (forsTargetKey target) (nodeHashOpening label node) := by
  cases node with
  | none => exact fun _ => trivial
  | some value => exact ⟨fors_target_not_public target _, fun _ => trivial⟩

theorem fors_leaf_opening_sealed (target : ForsTarget) (seed : ByteKey) (ht tree leaf : ℕ) :
    OpeningSealed (forsTargetKey target) (forsLeafOpening target seed ht tree leaf) := by
  exact opening_sealed_bind (forsTargetKey target) _ _
    (fors_secret_opening_sealed target ht tree leaf) (node_hash_opening_sealed target _)

theorem fors_secret_opening_budget (target : ForsTarget) (ht tree leaf : ℕ) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (forsSecretOpening target ht tree leaf)) 0 := by
  unfold forsSecretOpening
  split <;> simp [redactOpening, SelectedBudget, variableCandidate, publicDecode, nodeQueryDecode]

theorem fors_leaf_opening_budget (target : ForsTarget) (seed : ByteKey) (ht tree leaf : ℕ) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (forsLeafOpening target seed ht tree leaf)) 1 := by
  exact opening_selected_bind _ _ _ 0 1 (fors_secret_opening_budget target ht tree leaf)
    (fun node => selectedBudget_total _ _)

end
end C10Probability

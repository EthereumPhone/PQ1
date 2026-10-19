import C10Probability.ForsTreeOpening
import C10Probability.ForestOne

/-! Recovery of a deferred selected node hashes it through the same hidden
commitment interface. All eleven sibling steps remain the original public
queries, including defaults, malformed paths, repeated keys and cache hits. -/
namespace C10Probability
noncomputable section

def forsRecoverOpening (seed : ByteKey) (ht tree leaf : ℕ)
    (node : Option Randomizer) (auth : List Randomizer) :
    OpeningProgram WotsQuery ByteKey Digest Digest Randomizer 12 :=
  bindOpening (nodeHashOpening (seed ++ c10Address 0 ht 3 tree 0 0 leaf) node)
    (fun current => liftOpening (forsRecoveryProgram Sum.inl seed ht tree auth 11 0 leaf current))

structure DeferredForestTree where
  secret : Option Randomizer
  auth : List Randomizer
  root : Randomizer

def deferredForestTree (secret : Digest) (out : DeferredForestTree) : ForestTreeResult :=
  ⟨deferredNode secret out.secret, out.auth, out.root⟩

def forestOneOpening (target : ForsTarget) (seed : ByteKey) (ht tree leaf : ℕ) :
    OpeningProgram WotsQuery ByteKey Digest Digest DeferredForestTree 6156 :=
  bindOpening (forsSignOpening target seed ht tree leaf) (fun sig =>
    mapOpeningReturn (fun root => ⟨sig.1, sig.2, root⟩)
      (forsRecoverOpening seed ht tree leaf sig.1 sig.2))

theorem fors_recover_opening_refines (target : ForsTarget) (secret : Digest)
    (seed : ByteKey) (ht tree leaf : ℕ) (node : Option Randomizer) (auth : List Randomizer) :
    OpeningRefines digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret id
      (forsRecoverOpening seed ht tree leaf node auth)
      (forsRecoverProgram Sum.inl seed ht tree leaf (deferredNode secret node) auth) := by
  exact opening_refines_bind digestDraw nodeCommitEncode randomizerOfDigest
    (forsTargetKey target) secret id id _ _ _ _
    (node_hash_opening_refines target secret (seed ++ c10Address 0 ht 3 tree 0 0 leaf) node)
    (fun current => opening_refines_lift digestDraw nodeCommitEncode randomizerOfDigest
      (forsTargetKey target) secret (forsRecoveryProgram Sum.inl seed ht tree auth 11 0 leaf current))

theorem fors_recover_opening_sealed (target : ForsTarget) (seed : ByteKey)
    (ht tree leaf : ℕ) (node : Option Randomizer) (auth : List Randomizer) :
    OpeningSealed (forsTargetKey target) (forsRecoverOpening seed ht tree leaf node auth) := by
  apply opening_sealed_bind (forsTargetKey target) _ _ (node_hash_opening_sealed target _ node)
  intro current
  have sealed := opening_sealed_lift_mapped (P := ByteKey) (H := Digest) (forsTargetKey target)
    Sum.inl (fors_target_not_public target)
    (forsRecoveryProgram id seed ht tree auth 11 0 leaf current)
  simpa only [fors_recovery_program_map, Function.comp_id] using sealed

theorem fors_recover_opening_budget (seed : ByteKey) (ht tree leaf : ℕ)
    (node : Option Randomizer) (auth : List Randomizer) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (forsRecoverOpening seed ht tree leaf node auth)) 12 := by
  exact selectedBudget_total _ _

theorem forest_one_opening_refines (target : ForsTarget) (secret : Digest)
    (seed : ByteKey) (ht tree leaf : ℕ) :
    OpeningRefines digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret
      (deferredForestTree secret) (forestOneOpening target seed ht tree leaf)
      (forestOneProgram id seed ht tree leaf) := by
  apply opening_refines_bind digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target)
    secret (fun out : Option Randomizer × List Randomizer => (deferredNode secret out.1, out.2))
    (deferredForestTree secret) _ _ _ _ (fors_sign_opening_refines target secret seed ht tree leaf)
  intro sig
  exact opening_refines_map digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target)
    secret id (deferredForestTree secret) (fun root => ⟨sig.1, sig.2, root⟩)
    (fun root => ⟨deferredNode secret sig.1, sig.2, root⟩) (fun _ => rfl) _ _
    (fors_recover_opening_refines target secret seed ht tree leaf sig.1 sig.2)

theorem forest_one_opening_sealed (target : ForsTarget) (seed : ByteKey) (ht tree leaf : ℕ) :
    OpeningSealed (forsTargetKey target) (forestOneOpening target seed ht tree leaf) := by
  apply opening_sealed_bind (forsTargetKey target) _ _ (fors_sign_opening_sealed target seed ht tree leaf)
  intro sig
  rw [opening_sealed_map]
  exact fors_recover_opening_sealed target seed ht tree leaf sig.1 sig.2

theorem forest_one_opening_budget (target : ForsTarget) (seed : ByteKey) (ht tree leaf : ℕ) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (forestOneOpening target seed ht tree leaf)) 4107 := by
  apply opening_selected_bind _ _ _ 4095 12 (fors_sign_opening_budget target seed ht tree leaf)
  intro sig
  rw [redact_opening_mapReturn, selectedBudget_mapReturn]
  exact fors_recover_opening_budget seed ht tree leaf sig.1 sig.2

end
end C10Probability

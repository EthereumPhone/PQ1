import C10Probability.ForsRecoverOpening
import C10Probability.ForestFill

/-! The shuffled twelve-tree fill keeps a symbolic selected secret in its
original array position. Authentication paths and recovered roots stay concrete;
the complete memo cache is threaded in the original order. -/
namespace C10Probability
noncomputable section
variable {I K P α H U S T : Type*}

def openingStateFold (cost : I → ℕ)
    (step : (i : I) → S → OpeningProgram K P α H S (cost i)) :
    (indices : List I) → S → OpeningProgram K P α H S (collectionSteps cost indices)
  | [], state => .done state
  | i :: rest, state => castOpening (by simp [collectionSteps, Nat.add_comm])
      (bindOpening (step i state) (openingStateFold cost step rest))

theorem opening_fold_refines [DecidableEq K] (p : PMF α) (encode : U → P → K)
    (project : α → U) (target : K) (secret : α) (interpret : S → T) (cost : I → ℕ)
    (step : (i : I) → S → OpeningProgram K P α α S (cost i))
    (ordinary : (i : I) → T → QueryProgram K α T (cost i))
    (each : ∀ i state, OpeningRefines p encode project target secret interpret
      (step i state) (ordinary i (interpret state))) (indices : List I) (state : S) :
    OpeningRefines p encode project target secret interpret (openingStateFold cost step indices state)
      (stateFoldProgram cost ordinary indices (interpret state)) := by
  induction indices generalizing state with
  | nil => exact opening_refines_done p encode project target secret interpret _ _ _
  | cons i rest ih =>
    rw [openingStateFold, stateFoldProgram]
    apply opening_refines_cast
    exact opening_refines_bind p encode project target secret interpret interpret _ _ _ _ (each i state) ih

theorem opening_fold_sealed (target : K) (cost : I → ℕ)
    (step : (i : I) → S → OpeningProgram K P α H S (cost i))
    (each : ∀ i state, OpeningSealed target (step i state)) (indices : List I) (state : S) :
    OpeningSealed target (openingStateFold cost step indices state) := by
  induction indices generalizing state with
  | nil => trivial
  | cons i rest ih =>
    rw [openingStateFold, opening_sealed_cast]
    exact opening_sealed_bind target _ _ (each i state) ih

theorem opening_fold_budget (select : Sum K P → Bool) (cost charge : I → ℕ)
    (step : (i : I) → S → OpeningProgram K P α H S (cost i))
    (each : ∀ i state, SelectedBudget select (redactOpening (step i state)) (charge i))
    (indices : List I) (state : S) :
    SelectedBudget select (redactOpening (openingStateFold cost step indices state))
      (collectionSteps charge indices) := by
  induction indices generalizing state with
  | nil => trivial
  | cons i rest ih =>
    rw [openingStateFold, redact_opening_cast, selectedBudget_cast]
    exact opening_selected_bind select _ _ (charge i) (collectionSteps charge rest) (each i state) ih

structure DeferredForestState where
  secrets : List (Option Randomizer)
  auths : List (List Randomizer)
  roots : List Randomizer

def deferredForestState (secret : Digest) (state : DeferredForestState) : ForestState :=
  ⟨state.secrets.map (deferredNode secret), state.auths, state.roots⟩

def emptyDeferredForest : DeferredForestState :=
  ⟨List.replicate 13 (some 0), List.replicate 12 (List.replicate 11 0), List.replicate 13 0⟩

def deferredForestWrite (state : DeferredForestState) (tree : ℕ) (out : DeferredForestTree) :
    DeferredForestState :=
  ⟨state.secrets.set tree out.secret, state.auths.set tree out.auth, state.roots.set tree out.root⟩

def forestFillStepOpening (target : ForsTarget) (seed : ByteKey) (ht : ℕ)
    (digest : Digest) (tree : Fin 12) (state : DeferredForestState) :
    OpeningProgram WotsQuery ByteKey Digest Digest DeferredForestState 6156 :=
  mapOpeningReturn (deferredForestWrite state tree.val)
    (forestOneOpening target seed ht tree.val (forestIndex digest tree.val))

def forestFillOpening (target : ForsTarget) (seed : ByteKey) (ht : ℕ) (digest : Digest)
    (order : List (Fin 12)) (state : DeferredForestState) :
    OpeningProgram WotsQuery ByteKey Digest Digest DeferredForestState
      (collectionSteps (fun _ => 6156) order) :=
  openingStateFold (fun _ => 6156) (forestFillStepOpening target seed ht digest) order state

def forestOrderedOpening (target : ForsTarget) (seed : ByteKey) (ht : ℕ) (digest : Digest)
    (order : ForestOrder) : OpeningProgram WotsQuery ByteKey Digest Digest DeferredForestState 73872 :=
  castOpening (forest_fill_raw_calls order) (forestFillOpening target seed ht digest order.val emptyDeferredForest)

attribute [irreducible] forestOrderedOpening

theorem deferred_forest_write (secret : Digest) (state : DeferredForestState)
    (tree : ℕ) (out : DeferredForestTree) :
    deferredForestState secret (deferredForestWrite state tree out) =
      forestWrite (deferredForestState secret state) tree (deferredForestTree secret out) := by
  simp only [deferredForestState, deferredForestWrite, forestWrite, deferredForestTree, List.map_set]

theorem forest_fill_step_opening_refines (target : ForsTarget) (secret : Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (tree : Fin 12) (state : DeferredForestState) :
    OpeningRefines digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret
      (deferredForestState secret) (forestFillStepOpening target seed ht digest tree state)
      (forestFillStep id seed ht digest tree (deferredForestState secret state)) := by
  exact opening_refines_map digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target)
    secret (deferredForestTree secret) (deferredForestState secret)
    (deferredForestWrite state tree.val) (forestWrite (deferredForestState secret state) tree.val)
    (deferred_forest_write secret state tree.val) _ _
    (forest_one_opening_refines target secret seed ht tree.val (forestIndex digest tree.val))

theorem forest_fill_opening_refines (target : ForsTarget) (secret : Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (order : List (Fin 12)) (state : DeferredForestState) :
    OpeningRefines digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret
      (deferredForestState secret) (forestFillOpening target seed ht digest order state)
      (forestFillProgram id seed ht digest order (deferredForestState secret state)) := by
  exact opening_fold_refines digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target)
    secret (deferredForestState secret) (fun _ => 6156) _ _
    (forest_fill_step_opening_refines target secret seed ht digest) order state

theorem forest_ordered_opening_refines (target : ForsTarget) (secret : Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (order : ForestOrder) :
    OpeningRefines digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret
      (deferredForestState secret) (forestOrderedOpening target seed ht digest order)
      (forestOrderedProgram id seed ht digest order) := by
  rw [forestOrderedOpening, forestOrderedProgram]
  apply opening_refines_cast
  have correspondence := forest_fill_opening_refines target secret seed ht digest order.val emptyDeferredForest
  simpa only [deferredForestState, emptyDeferredForest, List.map_replicate,
    deferredNode, Option.getD_some, emptyForestState] using correspondence

theorem forest_fill_opening_sealed (target : ForsTarget) (seed : ByteKey) (ht : ℕ)
    (digest : Digest) (order : List (Fin 12)) (state : DeferredForestState) :
    OpeningSealed (forsTargetKey target) (forestFillOpening target seed ht digest order state) := by
  apply opening_fold_sealed
  intro tree state
  rw [forestFillStepOpening, opening_sealed_map]
  exact forest_one_opening_sealed target seed ht tree.val (forestIndex digest tree.val)

theorem forest_ordered_opening_sealed (target : ForsTarget) (seed : ByteKey) (ht : ℕ)
    (digest : Digest) (order : ForestOrder) :
    OpeningSealed (forsTargetKey target) (forestOrderedOpening target seed ht digest order) := by
  rw [forestOrderedOpening, opening_sealed_cast]
  exact forest_fill_opening_sealed target seed ht digest order.val emptyDeferredForest

theorem forest_fill_opening_budget (target : ForsTarget) (seed : ByteKey) (ht : ℕ)
    (digest : Digest) (order : List (Fin 12)) (state : DeferredForestState) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (forestFillOpening target seed ht digest order state))
      (collectionSteps (fun _ => 4107) order) := by
  apply opening_fold_budget
  intro tree state
  rw [forestFillStepOpening, redact_opening_mapReturn, selectedBudget_mapReturn]
  exact forest_one_opening_budget target seed ht tree.val (forestIndex digest tree.val)

theorem forest_ordered_opening_budget (target : ForsTarget) (seed : ByteKey) (ht : ℕ)
    (digest : Digest) (order : ForestOrder) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (forestOrderedOpening target seed ht digest order)) 49284 := by
  rw [forestOrderedOpening, redact_opening_cast, selectedBudget_cast, ← forest_fill_public_calls order]
  exact forest_fill_opening_budget target seed ht digest order.val emptyDeferredForest

end
end C10Probability

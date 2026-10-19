import C10Probability.WotsChainOpening
import C10Probability.ForestFillOpening

/-! All43 chain positions are retained in the original ordered fill. Each
array entry has the position prescribed by the caller, including duplicate
indices in an arbitrary fill order. No independent-chain premise is used. -/
namespace C10Probability
noncomputable section

abbrev WotsDeferredSigma (target : WotsCutTarget) (address : WotsLogicalAddress)
    (steps : Fin 43 → ℕ) := (i : Fin 43) → WotsDeferredNode target (address, i) (steps i)

def wotsDeferredSigmaValue (secret : Digest) {target : WotsCutTarget}
    {address : WotsLogicalAddress} {steps : Fin 43 → ℕ}
    (sigma : WotsDeferredSigma target address steps) : WotsSigma :=
  fun i => wotsDeferredValue secret (sigma i)

def wotsZeroDeferredSigma (target : WotsCutTarget) (address : WotsLogicalAddress)
    (steps : Fin 43 → ℕ) : WotsDeferredSigma target address steps :=
  fun i => knownWotsNode target (address, i) (steps i) 0

theorem wots_deferred_sigma_update (secret : Digest) {target : WotsCutTarget}
    {address : WotsLogicalAddress} {steps : Fin 43 → ℕ}
    (sigma : WotsDeferredSigma target address steps) (i : Fin 43)
    (node : WotsDeferredNode target (address, i) (steps i)) :
    wotsDeferredSigmaValue secret (Function.update sigma i node) =
      Function.update (wotsDeferredSigmaValue secret sigma) i (wotsDeferredValue secret node) := by
  funext j
  by_cases equal : j = i
  · subst j
    simp [wotsDeferredSigmaValue]
  · simp only [wotsDeferredSigmaValue, Function.update_of_ne equal]

theorem wots_zero_deferred_sigma (secret : Digest) (target : WotsCutTarget)
    (address : WotsLogicalAddress) (steps : Fin 43 → ℕ) :
    wotsDeferredSigmaValue secret (wotsZeroDeferredSigma target address steps) = wotsZeroSigma := by rfl

def wotsFillStepOpening (seed : ByteKey) (target : WotsCutTarget) (previous : Randomizer)
    (address : WotsLogicalAddress) (steps : Fin 43 → ℕ) (limits : ∀ i, steps i ≤ 7)
    (i : Fin 43) (sigma : WotsDeferredSigma target address steps) :
    OpeningProgram WotsQuery Unit Digest Digest (WotsDeferredSigma target address steps) (steps i + 1) :=
  mapOpeningReturn (Function.update sigma i)
    (wotsSeedChainOpening seed target previous (address, i) (steps i) (limits i))

def wotsFillOpening (seed : ByteKey) (target : WotsCutTarget) (previous : Randomizer)
    (address : WotsLogicalAddress) (steps : Fin 43 → ℕ) (limits : ∀ i, steps i ≤ 7)
    (order : List (Fin 43)) (sigma : WotsDeferredSigma target address steps) :
    OpeningProgram WotsQuery Unit Digest Digest (WotsDeferredSigma target address steps)
      (collectionSteps (fun i => steps i + 1) order) :=
  openingStateFold (fun i => steps i + 1)
    (wotsFillStepOpening seed target previous address steps limits) order sigma

theorem wots_fill_step_opening_refines (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (steps : Fin 43 → ℕ)
    (limits : ∀ i, steps i ≤ 7) (i : Fin 43) (sigma : WotsDeferredSigma target address steps)
    (secret : Digest) :
    OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret (wotsDeferredSigmaValue secret)
      (wotsFillStepOpening seed target previous address steps limits i sigma)
      (wotsFillStep id seed (wotsTargetLayer (address, 0)) (wotsTargetTree (address, 0))
        (wotsTargetKp (address, 0)) steps i (wotsDeferredSigmaValue secret sigma)) := by
  exact opening_refines_map digestDraw (wotsCutCommit seed target) randomizerOfDigest
    (wotsCutIncoming seed target previous) secret (wotsDeferredValue secret)
    (wotsDeferredSigmaValue secret) (Function.update sigma i)
    (Function.update (wotsDeferredSigmaValue secret sigma) i)
    (wots_deferred_sigma_update secret sigma i) _ _
    (wots_seed_chain_opening_refines seed target previous (address, i) (steps i) (limits i) secret)

theorem wots_fill_opening_refines (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (steps : Fin 43 → ℕ)
    (limits : ∀ i, steps i ≤ 7) (order : List (Fin 43))
    (sigma : WotsDeferredSigma target address steps) (secret : Digest) :
    OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret (wotsDeferredSigmaValue secret)
      (wotsFillOpening seed target previous address steps limits order sigma)
      (wotsFillProgram id seed (wotsTargetLayer (address, 0)) (wotsTargetTree (address, 0))
        (wotsTargetKp (address, 0)) steps order (wotsDeferredSigmaValue secret sigma)) := by
  exact opening_fold_refines digestDraw (wotsCutCommit seed target) randomizerOfDigest
    (wotsCutIncoming seed target previous) secret (wotsDeferredSigmaValue secret)
    (fun i => steps i + 1) _ _
    (fun i sigma => wots_fill_step_opening_refines seed target previous address steps limits i sigma secret)
    order sigma

theorem wots_fill_opening_sealed (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (steps : Fin 43 → ℕ)
    (limits : ∀ i, steps i ≤ 7) (order : List (Fin 43))
    (sigma : WotsDeferredSigma target address steps) :
    OpeningSealed (wotsCutIncoming seed target previous)
      (wotsFillOpening seed target previous address steps limits order sigma) := by
  apply opening_fold_sealed
  intro i state
  rw [wotsFillStepOpening, opening_sealed_map]
  exact wots_seed_chain_opening_sealed seed target previous (address, i) (steps i) (limits i)

theorem wots_fill_opening_budget (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (address : WotsLogicalAddress) (steps : Fin 43 → ℕ)
    (limits : ∀ i, steps i ≤ 7) (order : List (Fin 43))
    (sigma : WotsDeferredSigma target address steps) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsFillOpening seed target previous address steps limits order sigma))
      (collectionSteps steps order) := by
  apply opening_fold_budget
  intro i state
  rw [wotsFillStepOpening, redact_opening_mapReturn, selectedBudget_mapReturn]
  exact wots_seed_chain_opening_budget seed target previous (address, i) (steps i) (limits i)

end
end C10Probability

import C10Probability.WotsCoordinateBinding
import C10Probability.ForsLeafOpening

/-! The deferred value carries its actual chain coordinate and position. A
hidden value is permitted only at the selected cut; all other positions carry
ordinary known nodes. This invariant applies to every possible continuation. -/
namespace C10Probability
noncomputable section

def WotsDeferredNode (target : WotsCutTarget) (source : WotsTarget) (position : ℕ) :=
  {node : Option Randomizer // node = none → source = target.1 ∧ position = target.2.val}

def knownWotsNode (target : WotsCutTarget) (source : WotsTarget) (position : ℕ)
    (node : Randomizer) : WotsDeferredNode target source position :=
  ⟨some node, by simp⟩

def hiddenWotsNode (target : WotsCutTarget) (source : WotsTarget) (position : ℕ)
    (selected : source = target.1 ∧ position = target.2.val) :
    WotsDeferredNode target source position := ⟨none, fun _ => selected⟩

def wotsDeferredValue (secret : Digest) {target : WotsCutTarget} {source : WotsTarget}
    {position : ℕ} (node : WotsDeferredNode target source position) : Randomizer :=
  deferredNode secret node.val

def wotsKnownValue {target : WotsCutTarget} {source : WotsTarget} {position : ℕ}
    (node : WotsDeferredNode target source position) : Randomizer := node.val.getD 0

theorem wots_deferred_known (secret : Digest) (target : WotsCutTarget)
    (source : WotsTarget) (position : ℕ) (node : Randomizer) :
    wotsDeferredValue secret (knownWotsNode target source position node) = node := by rfl

theorem wots_deferred_hidden (secret : Digest) (target : WotsCutTarget)
    (source : WotsTarget) (position : ℕ)
    (selected : source = target.1 ∧ position = target.2.val) :
    wotsDeferredValue secret (hiddenWotsNode target source position selected) =
      randomizerOfDigest secret := by rfl

theorem wots_deferred_none {target : WotsCutTarget} {source : WotsTarget} {position : ℕ}
    (node : WotsDeferredNode target source position) (hidden : node.val = none) :
    source = target.1 ∧ position = target.2.val := node.property hidden

theorem wots_deferred_known_value (secret : Digest) {target : WotsCutTarget}
    {source : WotsTarget} {position : ℕ} (node : WotsDeferredNode target source position)
    (different : source ≠ target.1 ∨ position ≠ target.2.val) :
    wotsKnownValue node = wotsDeferredValue secret node := by
  cases hidden : node.val with
  | none =>
    have selected := node.property hidden
    exact (different.elim (fun h => h selected.1) (fun h => h selected.2)).elim
  | some value => simp only [wotsKnownValue, wotsDeferredValue, deferredNode, hidden, Option.getD_some]

theorem wots_deferred_endpoint (secret : Digest) {target : WotsCutTarget}
    {source : WotsTarget} (node : WotsDeferredNode target source 7) :
    wotsKnownValue node = wotsDeferredValue secret node := by
  exact wots_deferred_known_value secret node (Or.inr (by have := target.2.isLt; omega))

end
end C10Probability

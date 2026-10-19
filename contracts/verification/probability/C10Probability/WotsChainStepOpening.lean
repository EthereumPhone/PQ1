import C10Probability.WotsSeedOpening

/-! One honest chain step preserves the entire memo table. A known input equal
to the selected incoming key returns its cached value symbolically. A hidden
input can occur only at the selected outgoing position, where a commitment
performs the identical public query without revealing the node. -/
namespace C10Probability
noncomputable section

def wotsChainStepOpening (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (source : WotsTarget) (position : ℕ)
    (bound : position < 2 ^ 32) (node : WotsDeferredNode target source position) :
    OpeningProgram WotsQuery Unit Digest Digest
      (WotsDeferredNode target source (position + 1)) 1 :=
  match node.val with
  | none => .commit () (fun reply =>
      .done (knownWotsNode target source (position + 1) (randomizerOfDigest reply)))
  | some value =>
    if equal : wotsTargetInput seed source position value = wotsCutIncoming seed target previous then
      .done (hiddenWotsNode target source (position + 1)
        (let binding := wots_target_input_incoming seed target previous source position value bound equal
         ⟨binding.1, binding.2.1⟩))
    else .query (wotsTargetInput seed source position value) (fun reply =>
      .done (knownWotsNode target source (position + 1) (randomizerOfDigest reply)))

theorem wots_chain_step_opening_refines (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (source : WotsTarget) (position : ℕ)
    (bound : position < 2 ^ 32) (node : WotsDeferredNode target source position)
    (secret : Digest) :
    OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret (wotsDeferredValue secret)
      (wotsChainStepOpening seed target previous source position bound node)
      (.query (wotsTargetInput seed source position (wotsDeferredValue secret node))
        (fun reply => .done (n := 0) (randomizerOfDigest reply))) := by
  intro table opened cached
  unfold wotsChainStepOpening
  cases hidden : node.val with
  | none =>
    have selected := node.property hidden
    have interpreted : wotsDeferredValue secret node = randomizerOfDigest secret := by
      simp only [wotsDeferredValue, deferredNode, hidden, Option.getD_none]
    simp only [evalOpening, PMF.map_bind, evalProgram, interpreted, wotsCutCommit,
      wotsTargetInput, selected.1, selected.2]
    congr 1
    funext reply
    simp only [PMF.pure_map, openingProject, wots_deferred_known]
  | some value =>
    dsimp only
    have interpreted : wotsDeferredValue secret node = value := by
      simp only [wotsDeferredValue, deferredNode, hidden, Option.getD_some]
    rw [interpreted]
    split
    next equal =>
      rw [evalProgram_cached digestDraw _ _ table secret (equal ▸ cached)]
      simp only [evalOpening, PMF.pure_map, openingProject, wots_deferred_hidden, evalProgram]
    next different =>
      simp only [evalOpening, PMF.map_bind, evalProgram]
      congr 1
      funext reply
      simp only [PMF.pure_map, openingProject, wots_deferred_known]

theorem wots_chain_step_opening_sealed (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (source : WotsTarget) (position : ℕ)
    (bound : position < 2 ^ 32) (node : WotsDeferredNode target source position) :
    OpeningSealed (wotsCutIncoming seed target previous)
      (wotsChainStepOpening seed target previous source position bound node) := by
  unfold wotsChainStepOpening
  cases node.val with
  | none => exact fun _ => trivial
  | some value =>
    dsimp only
    split
    · trivial
    next different => exact ⟨different, fun _ => trivial⟩

theorem wots_chain_step_opening_budget (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (source : WotsTarget) (position : ℕ)
    (bound : position < 2 ^ 32) (node : WotsDeferredNode target source position) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsChainStepOpening seed target previous source position bound node)) 1 := by
  exact selectedBudget_total _ _

end
end C10Probability

import C10Probability.WotsChainStepOpening

/-! The complete bounded honest chain is an exact composition of the symbolic
steps. Its result carries the selected-cut invariant, and no honest internal
step reveals the node. Equality is of the result and complete memo table. -/
namespace C10Probability
noncomputable section

def wotsChainOpening (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (source : WotsTarget) (stop : ℕ) :
    (steps start : ℕ) → start + steps = stop → stop ≤ 7 →
      WotsDeferredNode target source start →
        OpeningProgram WotsQuery Unit Digest Digest (WotsDeferredNode target source stop) steps
  | 0, _, finish, _, node => .done ⟨node.val, fun hidden =>
      ⟨(node.property hidden).1, by have := (node.property hidden).2; omega⟩⟩
  | steps + 1, start, finish, limit, node =>
    bindOpening (wotsChainStepOpening seed target previous source start (by omega) node)
      (fun next => wotsChainOpening seed target previous source stop steps (start + 1)
        (by omega) limit next)

theorem wots_chain_opening_refines (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (source : WotsTarget) (stop steps start : ℕ)
    (finish : start + steps = stop) (limit : stop ≤ 7)
    (node : WotsDeferredNode target source start) (secret : Digest) :
    OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret (wotsDeferredValue secret)
      (wotsChainOpening seed target previous source stop steps start finish limit node)
      (chainProgram (wotsTargetInput seed source) randomizerOfDigest start steps
        (wotsDeferredValue secret node)) := by
  induction steps generalizing start with
  | zero =>
    intro table opened _
    simp only [wotsChainOpening, chainProgram, evalOpening, evalProgram, PMF.pure_map,
      openingProject, wotsDeferredValue]
  | succ steps ih =>
    have combined := opening_refines_bind digestDraw (wotsCutCommit seed target)
      randomizerOfDigest (wotsCutIncoming seed target previous) secret
      (wotsDeferredValue secret) (wotsDeferredValue secret)
      (wotsChainStepOpening seed target previous source start (by omega) node)
      (.query (wotsTargetInput seed source start (wotsDeferredValue secret node))
        (fun reply => .done (n := 0) (randomizerOfDigest reply)))
      (fun next => wotsChainOpening seed target previous source stop steps (start + 1)
        (by omega) limit next)
      (fun value => chainProgram (wotsTargetInput seed source) randomizerOfDigest
        (start + 1) steps value)
      (wots_chain_step_opening_refines seed target previous source start (by omega) node secret)
      (fun next => ih (start + 1) (by omega) next)
    intro table opened cached
    simpa only [wotsChainOpening, chainProgram, evalProgram_bind, evalProgram,
      PMF.bind_bind, PMF.pure_bind] using combined table opened cached

theorem wots_chain_opening_sealed (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (source : WotsTarget) (stop steps start : ℕ)
    (finish : start + steps = stop) (limit : stop ≤ 7)
    (node : WotsDeferredNode target source start) :
    OpeningSealed (wotsCutIncoming seed target previous)
      (wotsChainOpening seed target previous source stop steps start finish limit node) := by
  induction steps generalizing start with
  | zero => trivial
  | succ steps ih =>
    exact opening_sealed_bind _ _ _
      (wots_chain_step_opening_sealed seed target previous source start (by omega) node)
      (fun next => ih (start + 1) (by omega) next)

theorem wots_chain_opening_budget (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (source : WotsTarget) (stop steps start : ℕ)
    (finish : start + steps = stop) (limit : stop ≤ 7)
    (node : WotsDeferredNode target source start) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsChainOpening seed target previous source stop steps start finish limit node))
      steps := by
  exact selectedBudget_total _ _

def wotsSeedChainOpening (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (source : WotsTarget) (steps : ℕ) (limit : steps ≤ 7) :
    OpeningProgram WotsQuery Unit Digest Digest (WotsDeferredNode target source steps) (steps + 1) :=
  bindOpening (wotsSeedOpening seed target previous source)
    (fun node => wotsChainOpening seed target previous source steps steps 0 (by omega) limit node)

theorem wots_seed_chain_opening_refines (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (source : WotsTarget) (steps : ℕ) (limit : steps ≤ 7)
    (secret : Digest) :
    OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret (wotsDeferredValue secret)
      (wotsSeedChainOpening seed target previous source steps limit)
      (wotsSeedChainProgram id seed (wotsTargetLayer source) (wotsTargetTree source)
        (wotsTargetKp source) source.2.val steps) := by
  have combined := opening_refines_bind digestDraw (wotsCutCommit seed target)
    randomizerOfDigest (wotsCutIncoming seed target previous) secret
    (wotsDeferredValue secret) (wotsDeferredValue secret)
    (wotsSeedOpening seed target previous source)
    (.query (wotsTargetKey source) (fun reply => .done (n := 0) (randomizerOfDigest reply)))
    (fun node => wotsChainOpening seed target previous source steps steps 0 (by omega) limit node)
    (fun value => chainProgram (wotsTargetInput seed source) randomizerOfDigest 0 steps value)
    (wots_seed_opening_refines seed target previous source secret)
    (fun node => wots_chain_opening_refines seed target previous source steps steps 0
      (by omega) limit node secret)
  intro table opened cached
  simpa only [wotsSeedChainOpening, wotsSeedChainProgram, wotsTargetKey, wotsTargetInput,
    id_eq, evalProgram_bind, evalProgram, PMF.bind_bind, PMF.pure_bind] using combined table opened cached

theorem wots_seed_chain_opening_sealed (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (source : WotsTarget) (steps : ℕ) (limit : steps ≤ 7) :
    OpeningSealed (wotsCutIncoming seed target previous)
      (wotsSeedChainOpening seed target previous source steps limit) := by
  exact opening_sealed_bind _ _ _ (wots_seed_opening_sealed seed target previous source)
    (fun node => wots_chain_opening_sealed seed target previous source steps steps 0 (by omega) limit node)

theorem wots_seed_chain_opening_budget (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (source : WotsTarget) (steps : ℕ) (limit : steps ≤ 7) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsSeedChainOpening seed target previous source steps limit)) steps := by
  simpa only [Nat.zero_add] using opening_selected_bind _ _ _ 0 steps
    (wots_seed_opening_budget seed target previous source)
    (fun node => wots_chain_opening_budget seed target previous source steps steps 0 (by omega) limit node)

end
end C10Probability

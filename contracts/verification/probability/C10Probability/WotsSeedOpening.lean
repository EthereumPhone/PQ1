import C10Probability.WotsDeferredNode

/-! Exact symbolic private derivation. Only the selected incoming private
entry at cut zero becomes a deferred node; every other private query retains
its full digest and ordinary memo behavior. -/
namespace C10Probability
noncomputable section

def wotsSeedOpening (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (source : WotsTarget) :
    OpeningProgram WotsQuery Unit Digest Digest (WotsDeferredNode target source 0) 1 :=
  if equal : wotsTargetKey source = wotsCutIncoming seed target previous then
    .done (hiddenWotsNode target source 0
      (let binding := wots_target_private_incoming seed target previous source equal
       ⟨binding.1, binding.2.symm⟩))
  else .query (wotsTargetKey source)
    (fun reply => .done (knownWotsNode target source 0 (randomizerOfDigest reply)))

theorem wots_seed_opening_refines (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (source : WotsTarget) (secret : Digest) :
    OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret (wotsDeferredValue secret)
      (wotsSeedOpening seed target previous source)
      (.query (wotsTargetKey source) (fun reply => .done (n := 0) (randomizerOfDigest reply))) := by
  intro table opened cached
  unfold wotsSeedOpening
  split
  next equal =>
    rw [evalProgram_cached digestDraw _ _ table secret (equal ▸ cached)]
    simp only [evalOpening, PMF.pure_map, openingProject, wots_deferred_hidden, evalProgram]
  next different =>
    simp only [evalOpening, PMF.map_bind, evalProgram]
    congr 1
    funext reply
    simp only [PMF.pure_map, openingProject, wots_deferred_known]

theorem wots_seed_opening_sealed (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (source : WotsTarget) :
    OpeningSealed (wotsCutIncoming seed target previous)
      (wotsSeedOpening seed target previous source) := by
  unfold wotsSeedOpening
  split
  · trivial
  next different => exact ⟨different, fun _ => trivial⟩

theorem wots_seed_opening_budget (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (source : WotsTarget) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsSeedOpening seed target previous source)) 0 := by
  unfold wotsSeedOpening
  split <;> simp [redactOpening, SelectedBudget, variableCandidate, publicDecode,
    nodeQueryDecode, wotsTargetKey]

end
end C10Probability

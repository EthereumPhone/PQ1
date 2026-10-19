import C10Probability.ForestFillOpening
import C10Probability.ForestSign

/-! Complete deferred forest signing, including its actual shuffle, special
thirteenth tree and ordered thirteen-root compression. Only ordinary secret
slots may contain the selected-node placeholder. -/
namespace C10Probability
noncomputable section

structure DeferredForestOutput where
  secrets : List (Option Randomizer)
  auths : List (List Randomizer)
  pk : Randomizer

def deferredForestOutput (secret : Digest) (out : DeferredForestOutput) : ForestOutput :=
  ⟨out.secrets.map (deferredNode secret), out.auths, out.pk⟩

def forestLastOpening (seed : ByteKey) (ht : ℕ) (state : DeferredForestState) (last : Randomizer) :
    OpeningProgram WotsQuery ByteKey Digest Digest DeferredForestOutput 2 :=
  .query (.inl (forsLeafInput seed ht 12 0 last)) (fun leaf =>
    .query (.inl (forsPkInput seed ht (state.roots.set 12 (randomizerOfDigest leaf))))
      (fun reply => .done ⟨state.secrets.set 12 (some last), state.auths, randomizerOfDigest reply⟩))

def forestFinishOpening (target : ForsTarget) (seed : ByteKey) (ht : ℕ)
    (state : DeferredForestState) :
    OpeningProgram WotsQuery ByteKey Digest Digest DeferredForestOutput 6145 :=
  bindOpening (forsRootOpening target seed ht 12) (forestLastOpening seed ht state)

def forestSignOpening (target : ForsTarget) (seed : ByteKey) (ht : ℕ)
    (digest : Digest) (shuffle : ByteKey) :
    OpeningProgram WotsQuery ByteKey Digest Digest DeferredForestOutput 80022 :=
  bindOpening (liftOpening (forestShuffleProgram Sum.inl shuffle)) (fun order =>
    bindOpening (forestOrderedOpening target seed ht digest order) (forestFinishOpening target seed ht))

attribute [irreducible] forestSignOpening

theorem forest_last_opening_refines (target : ForsTarget) (secret : Digest)
    (seed : ByteKey) (ht : ℕ) (state : DeferredForestState) (last : Randomizer) :
    OpeningRefines digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret
      (deferredForestOutput secret) (forestLastOpening seed ht state last)
      (forestLastProgram id seed ht (deferredForestState secret state) last) := by
  intro table opened _
  simp only [forestLastOpening, forestLastProgram, evalOpening, PMF.map_bind,
    PMF.pure_map, openingProject, deferredForestOutput, deferredForestState,
    evalProgram, id_eq, List.map_set, deferredNode, Option.getD_some]

theorem forest_finish_opening_refines (target : ForsTarget) (secret : Digest)
    (seed : ByteKey) (ht : ℕ) (state : DeferredForestState) :
    OpeningRefines digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret
      (deferredForestOutput secret) (forestFinishOpening target seed ht state)
      (forestFinishProgram id seed ht (deferredForestState secret state)) := by
  exact opening_refines_bind digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target)
    secret id (deferredForestOutput secret) _ _ _ _ (fors_root_opening_refines target secret seed ht 12)
    (forest_last_opening_refines target secret seed ht state)

theorem forest_sign_opening_refines (target : ForsTarget) (secret : Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (shuffle : ByteKey) :
    OpeningRefines digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret
      (deferredForestOutput secret) (forestSignOpening target seed ht digest shuffle)
      (forestSignProgram id seed ht digest shuffle) := by
  rw [forestSignOpening, forestSignProgram]
  apply opening_refines_bind digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target)
    secret id (deferredForestOutput secret) _ _ _ _
    (opening_refines_lift digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret _)
  intro order
  exact opening_refines_bind digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target)
    secret (deferredForestState secret) (deferredForestOutput secret) _ _ _ _
    (forest_ordered_opening_refines target secret seed ht digest order)
    (forest_finish_opening_refines target secret seed ht)

theorem forest_last_opening_sealed (target : ForsTarget) (seed : ByteKey) (ht : ℕ)
    (state : DeferredForestState) (last : Randomizer) :
    OpeningSealed (forsTargetKey target) (forestLastOpening seed ht state last) := by
  exact ⟨fors_target_not_public target _, fun _ => ⟨fors_target_not_public target _, fun _ => trivial⟩⟩

theorem forest_finish_opening_sealed (target : ForsTarget) (seed : ByteKey) (ht : ℕ)
    (state : DeferredForestState) :
    OpeningSealed (forsTargetKey target) (forestFinishOpening target seed ht state) := by
  exact opening_sealed_bind (forsTargetKey target) _ _ (fors_root_opening_sealed target seed ht 12)
    (forest_last_opening_sealed target seed ht state)

theorem forest_sign_opening_sealed (target : ForsTarget) (seed : ByteKey) (ht : ℕ)
    (digest : Digest) (shuffle : ByteKey) :
    OpeningSealed (forsTargetKey target) (forestSignOpening target seed ht digest shuffle) := by
  rw [forestSignOpening]
  apply opening_sealed_bind
  · have sealed := opening_sealed_lift_mapped (P := ByteKey) (H := Digest) (forsTargetKey target)
      Sum.inl (fors_target_not_public target) (forestShuffleProgram id shuffle)
    simpa only [forest_shuffle_map, Function.comp_id] using sealed
  · intro order
    exact opening_sealed_bind (forsTargetKey target) _ _
      (forest_ordered_opening_sealed target seed ht digest order)
      (forest_finish_opening_sealed target seed ht)

theorem forest_finish_opening_budget (target : ForsTarget) (seed : ByteKey) (ht : ℕ)
    (state : DeferredForestState) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (forestFinishOpening target seed ht state)) 4097 := by
  exact opening_selected_bind _ _ _ 4095 2 (fors_root_opening_budget target seed ht 12)
    (fun _ => selectedBudget_total _ _)

theorem forest_sign_opening_budget (target : ForsTarget) (seed : ByteKey) (ht : ℕ)
    (digest : Digest) (shuffle : ByteKey) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (forestSignOpening target seed ht digest shuffle)) 53386 := by
  rw [forestSignOpening]
  exact opening_selected_bind _ _ _ 5 53381 (selectedBudget_total _ _) (fun order =>
    opening_selected_bind _ _ _ 49284 4097 (forest_ordered_opening_budget target seed ht digest order)
      (forest_finish_opening_budget target seed ht))

end
end C10Probability

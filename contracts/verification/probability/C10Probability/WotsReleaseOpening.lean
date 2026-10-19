import C10Probability.WotsHypertreeOpening

/-! A legitimate signature at or before the protected cut excludes an earlier
opening, including concrete nodes at strictly earlier positions. Disclosure
depends on complete success of both layers, not merely on a hidden placeholder
or on the lower layer having returned internally. -/
namespace C10Probability
noncomputable section

def WotsResultExposes {target : WotsCutTarget} {address : WotsLogicalAddress}
    (result : WotsDeferredResult target address) : Prop :=
  address = target.1.1 ∧ (wotsOfDigest result.digest target.1.2).val ≤ target.2.val

def WotsHypertreeExposes {target : WotsCutTarget} {index : Fin (2 ^ 18)}
    (result : WotsDeferredHypertree target index) : Prop :=
  WotsResultExposes result.lower.wots ∨ WotsResultExposes result.upper.wots

local instance {target : WotsCutTarget} {address : WotsLogicalAddress}
    (result : WotsDeferredResult target address) : Decidable (WotsResultExposes result) := by
  unfold WotsResultExposes
  infer_instance

local instance {target : WotsCutTarget} {index : Fin (2 ^ 18)}
    (result : WotsDeferredHypertree target index) : Decidable (WotsHypertreeExposes result) := by
  unfold WotsHypertreeExposes
  infer_instance

theorem wots_result_unexposed_known (secret other : Digest) {target : WotsCutTarget}
    {address : WotsLogicalAddress} (result : WotsDeferredResult target address)
    (unexposed : ¬ WotsResultExposes result) :
    wotsDeferredSigmaValue secret result.sigma = wotsDeferredSigmaValue other result.sigma := by
  funext i
  cases hidden : (result.sigma i).val with
  | none =>
    have selected := (result.sigma i).property hidden
    have addressEq : address = target.1.1 := congrArg Prod.fst selected.1
    have indexEq : i = target.1.2 := congrArg Prod.snd selected.1
    have digitEq : (wotsOfDigest result.digest target.1.2).val = target.2.val := by
      simpa only [indexEq] using selected.2
    exact (unexposed ⟨addressEq, Nat.le_of_eq digitEq⟩).elim
  | some value =>
    simp only [wotsDeferredSigmaValue, wotsDeferredValue, deferredNode, hidden, Option.getD_some]

theorem wots_layer_unexposed_known (secret other : Digest) {target : WotsCutTarget}
    {address : WotsLogicalAddress} (result : WotsDeferredLayer target address)
    (unexposed : ¬ WotsResultExposes result.wots) :
    wotsDeferredLayerSignature secret result = wotsDeferredLayerSignature other result := by
  simp only [wotsDeferredLayerSignature, wots_result_unexposed_known secret other result.wots unexposed]

theorem wots_hypertree_unexposed_known (secret other : Digest) {target : WotsCutTarget}
    {index : Fin (2 ^ 18)} (result : WotsDeferredHypertree target index)
    (unexposed : ¬ WotsHypertreeExposes result) :
    wotsDeferredHypertreeSigned secret (some result) =
      wotsDeferredHypertreeSigned other (some result) := by
  have lower : ¬ WotsResultExposes result.lower.wots := fun h => unexposed (Or.inl h)
  have upper : ¬ WotsResultExposes result.upper.wots := fun h => unexposed (Or.inr h)
  simp only [wotsDeferredHypertreeSigned, Option.map_some,
    wots_layer_unexposed_known secret other result.lower lower,
    wots_layer_unexposed_known secret other result.upper upper]

def wotsReleaseHypertree {target : WotsCutTarget} {index : Fin (2 ^ 18)}
    (signed : Option (WotsDeferredHypertree target index)) :
    OpeningProgram WotsQuery Unit Digest Digest HypertreeSigned 1 :=
  match signed with
  | none => .done none
  | some result => if WotsHypertreeExposes result then
      .reveal (fun secret => .done (wotsDeferredHypertreeSigned secret (some result)))
    else .done (wotsDeferredHypertreeSigned 0 (some result))

theorem wots_release_hypertree_refines (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (index : Fin (2 ^ 18)) (secret : Digest)
    (signed : Option (WotsDeferredHypertree target index)) :
    OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret id (wotsReleaseHypertree signed)
      (.done (n := 0) (wotsDeferredHypertreeSigned secret signed)) := by
  intro table opened _
  cases signed with
  | none =>
    simp only [wotsReleaseHypertree, evalOpening, PMF.pure_map, openingProject,
      id_eq, evalProgram, wotsDeferredHypertreeSigned, Option.map_none]
  | some result =>
    by_cases exposed : WotsHypertreeExposes result
    · simp only [wotsReleaseHypertree, exposed, ↓reduceIte, evalOpening, PMF.pure_map,
        openingProject, id_eq, evalProgram]
    · simp only [wotsReleaseHypertree, exposed, ↓reduceIte, evalOpening, PMF.pure_map,
        openingProject, id_eq, evalProgram, wots_hypertree_unexposed_known secret 0 result exposed]

theorem wots_release_hypertree_avoids (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (index : Fin (2 ^ 18))
    (signed : Option (WotsDeferredHypertree target index)) :
    OpeningAvoids (wotsCutIncoming seed target previous) (wotsReleaseHypertree signed) := by
  cases signed with
  | none => trivial
  | some result =>
    by_cases exposed : WotsHypertreeExposes result
    · simp only [wotsReleaseHypertree, exposed, ↓reduceIte, OpeningAvoids]
      exact fun _ => True.intro
    · simp only [wotsReleaseHypertree, exposed, ↓reduceIte, OpeningAvoids]

theorem wots_release_hypertree_budget {target : WotsCutTarget} {index : Fin (2 ^ 18)}
    (signed : Option (WotsDeferredHypertree target index)) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsReleaseHypertree signed)) 0 := by
  cases signed with
  | none => trivial
  | some result =>
    by_cases exposed : WotsHypertreeExposes result <;>
      simp only [wotsReleaseHypertree, exposed, ↓reduceIte, redactOpening, SelectedBudget]

theorem wots_release_hypertree_disclosure (seed : ByteKey) (target : WotsCutTarget)
    (index : Fin (2 ^ 18)) (secret : Digest) (signed : Option (WotsDeferredHypertree target index))
    (table : Memo WotsQuery Digest) (out : OpeningOutput WotsQuery Digest HypertreeSigned)
    (supported : out ∈ (evalOpening digestDraw (wotsCutCommit seed target) randomizerOfDigest secret
      (wotsReleaseHypertree signed) table false).support) (opened : out.opened = true) :
    ∃ result, signed = some result ∧ WotsHypertreeExposes result ∧
      out.value = wotsDeferredHypertreeSigned secret (some result) := by
  cases signed with
  | none =>
    have equal : out = ⟨none, table, false⟩ := by
      simpa only [wotsReleaseHypertree, evalOpening, PMF.mem_support_pure_iff] using supported
    simp only [equal, Bool.false_eq_true] at opened
  | some result =>
    by_cases exposed : WotsHypertreeExposes result
    · have equal : out = ⟨wotsDeferredHypertreeSigned secret (some result), table, true⟩ := by
        simpa only [wotsReleaseHypertree, exposed, ↓reduceIte, evalOpening,
          PMF.mem_support_pure_iff] using supported
      exact ⟨result, rfl, exposed, congrArg OpeningOutput.value equal⟩
    · have equal : out = ⟨wotsDeferredHypertreeSigned 0 (some result), table, false⟩ := by
        simpa only [wotsReleaseHypertree, exposed, ↓reduceIte, evalOpening,
          PMF.mem_support_pure_iff] using supported
      simp only [equal, Bool.false_eq_true] at opened

end
end C10Probability

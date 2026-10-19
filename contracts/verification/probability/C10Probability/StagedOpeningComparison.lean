import C10Probability.OpeningTargetSetup
import C10Probability.OpeningRefinement

/-! A selected reply may follow an adaptive prefix. The prefix's generated
cache stays inside the opening game. Explicit exclusions cover legitimate
disclosures or separately charged events; a caller must prove the corresponding
disclosure implication and later account for every charged branch. -/
namespace C10Probability
open scoped ENNReal
noncomputable section
variable {K P α S R T : Type*} [DecidableEq K]

theorem opening_prefilled_candidate_le (p : PMF α) (encode : S → P → K)
    (project : α → S) (target : K) (secret : α) {n m : ℕ}
    (client : QueryProgram K α R n) (instrumented : OpeningProgram K P α α R m)
    (table : Memo K α) (candidates : R → Finset S) (excluded : R → Memo K α → Prop)
    (refines : OpeningRefines p encode project target secret id instrumented client)
    (avoids : OpeningAvoids target instrumented)
    (separate : ∀ label, encode (project secret) label ≠ target)
    (disclosure : ∀ out ∈ (evalOpening p encode project secret instrumented
      (Function.update table target (some secret)) false).support,
      out.opened = true → excluded out.value out.cache) :
    (evalProgram p client (Function.update table target (some secret))).toOuterMeasure
      {out | ¬ excluded out.1 out.2 ∧ project secret ∈ candidates out.1} ≤
        (evalOpening p encode project secret instrumented table false).toOuterMeasure
          {out | project secret ∈ openingCandidates candidates (openingRetain out)} := by
  rw [← refines (Function.update table target (some secret)) false (by simp),
    PMF.toOuterMeasure_map_apply]
  calc
    _ ≤ (evalOpening p encode project secret instrumented
        (Function.update table target (some secret)) false).toOuterMeasure
          {out | project secret ∈ openingCandidates candidates (openingRetain out)} := by
      apply PMF.toOuterMeasure_mono
      intro out member
      obtain ⟨event, supported⟩ := member
      have notExcluded : ¬ excluded out.value out.cache := event.1
      have candidate : project secret ∈ candidates out.value := event.2
      have closed : out.opened = false := by
        cases opened : out.opened
        · rfl
        · exact False.elim (notExcluded (disclosure out supported opened))
      change project secret ∈ openingCandidates candidates (openingRetain out)
      simpa only [openingRetain, closed, Bool.false_eq_true, ↓reduceIte, openingCandidates] using candidate
    _ = _ := by
      rw [eval_opening_update_avoided p encode project secret target separate instrumented
        avoids table (some secret) false, PMF.toOuterMeasure_map_apply]
      rfl

theorem staged_opening_comparison (p : PMF α) (encode : S → P → K)
    (project : α → S) {a n m : ℕ} (prelude : QueryProgram K α T a)
    (target : T → K) (client : QueryProgram K α R n)
    (after : T → OpeningProgram K P α α R m)
    (candidates : R → Finset S) (excluded : R → Memo K α → Prop)
    (fresh : ∀ before ∈ (evalProgram p prelude (fun _ => none)).support,
      before.2 (target before.1) = none)
    (refines : ∀ value secret, OpeningRefines p encode project (target value) secret id
      (after value) client)
    (avoids : ∀ value, OpeningAvoids (target value) (after value))
    (separate : ∀ secret value label, encode (project secret) label ≠ target value)
    (disclosure : ∀ before ∈ (evalProgram p prelude (fun _ => none)).support,
      ∀ secret out, out ∈ (evalOpening p encode project secret (after before.1)
        (Function.update before.2 (target before.1) (some secret)) false).support →
      out.opened = true → excluded out.value out.cache) :
    (evalProgram p client (fun _ => none)).toOuterMeasure
      (replayedOpeningEvent (openingTargetSetup prelude target project) candidates excluded) ≤
        (openingGame p p encode project (PMF.pure
          (bindOpening (liftOpening prelude) after))).toOuterMeasure
            (candidateEvent (openingCandidates candidates)) := by
  refine (replayed_opening_prepared_le p (openingTargetSetup prelude target project)
    client (fun _ => none) candidates excluded).trans ?_
  rw [prepared_opening_target_fresh p prelude target project client (fun _ => none) fresh,
    opening_game_prelude, PMF.toOuterMeasure_bind_apply, PMF.toOuterMeasure_bind_apply]
  apply ENNReal.tsum_le_tsum
  intro before
  by_cases supported : before ∈ (evalProgram p prelude (fun _ => none)).support
  · apply mul_le_mul_right
    rw [PMF.toOuterMeasure_bind_apply, PMF.toOuterMeasure_bind_apply]
    apply ENNReal.tsum_le_tsum
    intro secret
    apply mul_le_mul_right
    simp only [PMF.toOuterMeasure_map_apply, preparedOpeningEvent, candidateEvent,
      Set.preimage_setOf_eq]
    exact opening_prefilled_candidate_le p encode project (target before.1) secret
      client (after before.1) before.2 candidates excluded (refines before.1 secret)
      (avoids before.1) (separate secret before.1) (disclosure before supported secret)
  · have zero : (evalProgram p prelude (fun _ => none)) before = 0 :=
      (PMF.apply_eq_zero_iff _ before).mpr supported
    simp only [zero, zero_mul, le_refl]

end
end C10Probability

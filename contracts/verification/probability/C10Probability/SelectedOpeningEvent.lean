import C10Probability.OpeningRefinement
import C10Probability.OpeningGuess

/-! From an actual cached, unreturned private opening to the unopened
commitment experiment. An unused presampled entry cannot satisfy the original
event: restoreTarget removes it. No cache-visible distribution equality or
independence of the actual commitment transcript is assumed. -/
namespace C10Probability
open scoped ENNReal
noncomputable section
variable {K P α S R : Type*} [DecidableEq K]

def selectedOpeningEvent (target : K) (project : α → S) (candidates : R → Finset S)
    (returned : R → Memo K α → Prop) : Set (R × Memo K α) :=
  {out | ¬ returned out.1 out.2 ∧
    ∃ value, out.2 target = some value ∧ project value ∈ candidates out.1}

theorem selected_opening_presample_le (p : PMF α) (target : K) (project : α → S)
    (candidates : R → Finset S) (returned : R → Memo K α → Prop)
    {n : ℕ} (program : QueryProgram K α R n) :
    (evalProgram p program (fun _ => none)).toOuterMeasure
      (selectedOpeningEvent target project candidates returned) ≤
        ∑' secret, p secret * (evalProgram p program
          (Function.update (fun _ => none) target (some secret))).toOuterMeasure
            {out | ¬ returned out.1 out.2 ∧ project secret ∈ candidates out.1} := by
  rw [eval_program_presample p target program (fun _ => none) rfl, PMF.toOuterMeasure_bind_apply]
  apply ENNReal.tsum_le_tsum
  intro secret
  apply mul_le_mul_right
  rw [PMF.toOuterMeasure_map_apply, ← traceProgram_erases p program
    (Function.update (fun _ => none) target (some secret)), PMF.toOuterMeasure_map_apply]
  apply PMF.toOuterMeasure_mono
  intro trace member
  obtain ⟨event, supported⟩ := member
  obtain ⟨notReturned, value, cached, candidate⟩ := event
  have erasedSupport : (trace.value, trace.cache) ∈
      (evalProgram p program (Function.update (fun _ => none) target (some secret))).support := by
    rw [← traceProgram_erases, PMF.mem_support_map_iff]
    exact ⟨trace, supported, rfl⟩
  have stored := evalProgram_preserves p program (Function.update (fun _ => none) target (some secret))
    target secret (by simp) (trace.value, trace.cache) erasedSupport
  obtain ⟨queried, equal⟩ := restore_target_hit target trace secret value stored cached
  have restored : restoreTarget target trace = (trace.value, trace.cache) := by
    simp only [restoreTarget, queried, ↓reduceIte]
  exact ⟨by simpa only [restored] using notReturned, by simpa only [restored, equal] using candidate⟩

theorem selected_opening_comparison (p : PMF α) (encode : S → P → K) (project : α → S)
    (target : K) (candidates : R → Finset S) (returned : R → Memo K α → Prop)
    {n m : ℕ} (program : QueryProgram K α R n) (instrumented : OpeningProgram K P α α R m)
    (refines : ∀ secret, OpeningRefines p encode project target secret id instrumented program)
    (avoids : OpeningAvoids target instrumented)
    (separate : ∀ secret label, encode (project secret) label ≠ target)
    (disclosure : ∀ secret table out,
      out ∈ (evalOpening p encode project secret instrumented table false).support →
        out.opened = true → returned out.value out.cache) :
    (evalProgram p program (fun _ => none)).toOuterMeasure
      (selectedOpeningEvent target project candidates returned) ≤
    (openingGame p p encode project (PMF.pure instrumented)).toOuterMeasure
      (candidateEvent (openingCandidates candidates)) := by
  refine (selected_opening_presample_le p target project candidates returned program).trans ?_
  simp only [openingGame, PMF.pure_bind, PMF.toOuterMeasure_bind_apply, PMF.toOuterMeasure_map_apply]
  apply ENNReal.tsum_le_tsum
  intro secret
  apply mul_le_mul_right
  rw [← refines secret (Function.update (fun _ => none) target (some secret)) false (by simp),
    PMF.toOuterMeasure_map_apply]
  have retained : (evalOpening p encode project secret instrumented
      (Function.update (fun _ => none) target (some secret)) false).toOuterMeasure
        {out | project secret ∈ openingCandidates candidates (openingRetain out)} =
      (evalOpening p encode project secret instrumented (fun _ => none) false).toOuterMeasure
        {out | project secret ∈ openingCandidates candidates (openingRetain out)} := by
    rw [eval_opening_update_avoided p encode project secret target (separate secret)
      instrumented avoids (fun _ => none) (some secret) false, PMF.toOuterMeasure_map_apply]
    rfl
  calc
    _ ≤ (evalOpening p encode project secret instrumented
        (Function.update (fun _ => none) target (some secret)) false).toOuterMeasure
          {out | project secret ∈ openingCandidates candidates (openingRetain out)} := by
      apply PMF.toOuterMeasure_mono
      intro out member
      obtain ⟨event, supported⟩ := member
      have notReturned : ¬ returned out.value out.cache := event.1
      have candidate : project secret ∈ candidates out.value := event.2
      have closed : out.opened = false := by
        cases opened : out.opened
        · rfl
        · exact False.elim (notReturned (disclosure secret _ out supported opened))
      change project secret ∈ openingCandidates candidates (openingRetain out)
      simpa only [openingRetain, closed, Bool.false_eq_true, ↓reduceIte, openingCandidates] using candidate
    _ = _ := retained

end
end C10Probability

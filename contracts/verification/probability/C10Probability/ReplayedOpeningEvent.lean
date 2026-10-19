import C10Probability.PresampleReplay
import C10Probability.OpeningPrelude

/-! An opening backed by replay of an actual adaptive prefix may be compared
with that prefix's precomputed value. Restoration keeps the original client
cache exact; on the opening event, replay proves that the entire precomputed
cache was retained. This is a probability comparison, not an independence
assumption about the original transcript. -/
namespace C10Probability
open scoped ENNReal
noncomputable section
variable {K α S R : Type*} [DecidableEq K]

def replayedOpeningEvent {m : ℕ} (setup : QueryProgram K α S m)
    (candidates : R → Finset S) (returned : R → Memo K α → Prop) : Set (R × Memo K α) :=
  {out | ¬ returned out.1 out.2 ∧
    ∃ value, replayProgram out.2 setup = some value ∧ value ∈ candidates out.1}

theorem eval_program_precompute (p : PMF α) {m n : ℕ}
    (setup : QueryProgram K α S m) (client : QueryProgram K α R n) (table : Memo K α) :
    evalProgram p client table = (evalProgram p setup table).bind fun warm =>
      (traceProgram p client warm.2).map fun out =>
        ((restoreQueries table out).value, (restoreQueries table out).cache) := by
  rw [← traceProgram_erases, trace_program_precompute p setup client table, PMF.map_bind]
  simp only [PMF.map_comp, Function.comp_def]

theorem replayed_opening_presample_le (p : PMF α) {m n : ℕ}
    (setup : QueryProgram K α S m) (client : QueryProgram K α R n) (table : Memo K α)
    (candidates : R → Finset S) (returned : R → Memo K α → Prop) :
    (evalProgram p client table).toOuterMeasure (replayedOpeningEvent setup candidates returned) ≤
      ∑' warm, (evalProgram p setup table) warm *
        (evalProgram p client warm.2).toOuterMeasure
          {out | ¬ returned out.1 out.2 ∧ warm.1 ∈ candidates out.1} := by
  rw [eval_program_precompute p setup client table, PMF.toOuterMeasure_bind_apply]
  apply ENNReal.tsum_le_tsum
  intro warm
  by_cases hw : warm ∈ (evalProgram p setup table).support
  · apply mul_le_mul_right
    rw [PMF.toOuterMeasure_map_apply, ← traceProgram_erases p client warm.2,
      PMF.toOuterMeasure_map_apply]
    apply PMF.toOuterMeasure_mono
    intro out member
    obtain ⟨event, supported⟩ := member
    obtain ⟨notReturned, value, replayed, candidate⟩ := event
    have full := precompute_restore_replay p setup client table warm hw out supported value replayed
    have erased : (out.value, out.cache) ∈ (evalProgram p client warm.2).support := by
      rw [← traceProgram_erases, PMF.mem_support_map_iff]
      exact ⟨out, supported, rfl⟩
    have original := eval_program_replay_later p setup table warm hw out.cache
      (eval_program_extends p client warm.2 (out.value, out.cache) erased)
    have replayed' : replayProgram out.cache setup = some value := by
      simpa only [full] using replayed
    have same := replay_program_unique setup out.cache value warm.1 replayed' original
    exact ⟨by simpa only [full] using notReturned, by simpa only [full, same] using candidate⟩
  · have zero : (evalProgram p setup table) warm = 0 := (PMF.apply_eq_zero_iff _ warm).mpr hw
    simp only [zero, zero_mul, le_refl]

end
end C10Probability

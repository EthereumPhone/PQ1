import C10Probability.QueryTrace

/-! Sampling one initially absent memo entry before the client runs preserves
the complete result and cache after removing that entry if it was never queried.
The trace observer is passive; the client does not receive the pre-sampled value. -/
namespace C10Probability
noncomputable section

variable {K α R : Type*} [DecidableEq K]

def restoreTarget (target : K) (out : TraceOutput K α R) : R × Memo K α :=
  (out.value, if target ∈ out.queries then out.cache else Function.update out.cache target none)

theorem restore_target_selected (target : K) (out : TraceOutput K α R) :
    restoreTarget target ⟨out.value, out.cache, target :: out.queries⟩ =
      (out.value, out.cache) := by
  simp [restoreTarget]

theorem restore_target_other (target key : K) (different : key ≠ target)
    (out : TraceOutput K α R) :
    restoreTarget target ⟨out.value, out.cache, key :: out.queries⟩ = restoreTarget target out := by
  simp only [restoreTarget, List.mem_cons, Ne.symm different, false_or]

theorem eval_program_presample (p : PMF α) (target : K) {n : ℕ}
    (program : QueryProgram K α R n) (table : Memo K α) (fresh : table target = none) :
    evalProgram p program table = p.bind fun secret =>
      (traceProgram p program (Function.update table target (some secret))).map (restoreTarget target) := by
  induction program generalizing table with
  | done value =>
    simp only [evalProgram, traceProgram, PMF.pure_map, restoreTarget, List.not_mem_nil,
      ↓reduceIte, Function.update_idem]
    have same : Function.update table target none = table := by
      rw [← fresh, Function.update_eq_self]
    simp only [same, PMF.bind_const]
  | query key next ih =>
    by_cases selected : key = target
    · subst key
      rw [evalProgram_fresh p target next table fresh]
      congr 1
      funext secret
      rw [traceProgram, memoQuery_cached p _ target secret (by simp), PMF.pure_bind, PMF.map_comp]
      simpa only [Function.comp_def, restore_target_selected] using
        (traceProgram_erases p (next secret) (Function.update table target (some secret))).symm
    · cases cached : table key with
      | some value =>
        rw [evalProgram_cached p key next table value cached, ih value table fresh]
        congr 1
        funext secret
        rw [traceProgram, memoQuery_cached p _ key value (by simp [selected, cached]),
          PMF.pure_bind, PMF.map_comp]
        simp only [Function.comp_def, restore_target_other target key selected]
      | none =>
        rw [evalProgram_fresh p key next table cached]
        calc
          _ = p.bind (fun reply => p.bind fun secret =>
              (traceProgram p (next reply)
                (Function.update (Function.update table key (some reply)) target (some secret))).map
                  (restoreTarget target)) := by
            congr 1
            funext reply
            exact ih reply _ (by simp [Ne.symm selected, fresh])
          _ = p.bind (fun secret => p.bind fun reply =>
              (traceProgram p (next reply)
                (Function.update (Function.update table target (some secret)) key (some reply))).map
                  (restoreTarget target)) := by
            rw [PMF.bind_comm]
            congr 1
            funext secret
            congr 1
            funext reply
            rw [Function.update_comm selected]
          _ = _ := by
            congr 1
            funext secret
            rw [traceProgram, memoQuery_fresh p _ key (by simp [selected, cached]),
              PMF.bind_map, PMF.map_bind]
            congr 1
            funext reply
            simp only [Function.comp_def]
            rw [PMF.map_comp]
            simp only [Function.comp_def, restore_target_other target key selected]

theorem restore_target_hit (target : K) (out : TraceOutput K α R) (secret value : α)
    (stored : out.cache target = some secret)
    (hit : (restoreTarget target out).2 target = some value) :
    target ∈ out.queries ∧ value = secret := by
  by_cases queried : target ∈ out.queries
  · simp only [restoreTarget, queried, ↓reduceIte, stored] at hit
    exact ⟨queried, (Option.some.inj hit).symm⟩
  · simp [restoreTarget, queried] at hit

theorem eval_program_presample_support (p : PMF α) (target : K) {n : ℕ}
    (program : QueryProgram K α R n) (table : Memo K α) (fresh : table target = none)
    (out : R × Memo K α) (supported : out ∈ (evalProgram p program table).support) :
    ∃ secret ∈ p.support, ∃ trace ∈
      (traceProgram p program (Function.update table target (some secret))).support,
      restoreTarget target trace = out ∧ trace.cache target = some secret := by
  rw [eval_program_presample p target program table fresh, PMF.mem_support_bind_iff] at supported
  obtain ⟨secret, hs, supported⟩ := supported
  rw [PMF.mem_support_map_iff] at supported
  obtain ⟨trace, ht, equal⟩ := supported
  refine ⟨secret, hs, trace, ht, equal, ?_⟩
  have preserved := evalProgram_preserves p program (Function.update table target (some secret))
    target secret (by simp) (trace.value, trace.cache) ?_
  · exact preserved
  · rw [← traceProgram_erases]
    rw [PMF.mem_support_map_iff]
    exact ⟨trace, ht, rfl⟩

end
end C10Probability

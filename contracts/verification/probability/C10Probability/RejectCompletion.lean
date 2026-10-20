import C10Probability.HmsgPoolBound

/-! Completion potential for a fixed finite schedule of distinct oracle keys.
Earlier adaptive queries and cache hits are retained. A cached rejection has
factor one, a cached acceptance factor zero, and an absent key the fresh
rejection mass. The initialized bound requires no caller freshness premise. -/
namespace C10Probability
open scoped ENNReal
noncomputable section
attribute [local instance] Classical.propDecidable

variable {K α R : Type*} [DecidableEq K]

def rejectFactor (p : PMF α) (accept : α → Bool) : Option α → ℝ≥0∞
  | none => rejectMass p accept
  | some value => if accept value then 0 else 1

def rejectCompletion (p : PMF α) (accept : α → Bool)
    (keys : Finset K) (table : Memo K α) : ℝ≥0∞ :=
  ∏ key ∈ keys, rejectFactor p accept (table key)

def CompleteRejection (accept : α → Bool) (keys : Finset K) (table : Memo K α) : Prop :=
  ∀ key ∈ keys, ∃ value, table key = some value ∧ accept value = false

omit [DecidableEq K] in
theorem reject_completion_empty (p : PMF α) (accept : α → Bool) (keys : Finset K) :
    rejectCompletion p accept keys (fun _ => none) = rejectMass p accept ^ keys.card := by
  simp [rejectCompletion, rejectFactor]

theorem reject_completion_update_other (p : PMF α) (accept : α → Bool)
    (keys : Finset K) (table : Memo K α) (key : K) (value : α) (outside : key ∉ keys) :
    rejectCompletion p accept keys (Function.update table key (some value)) =
      rejectCompletion p accept keys table := by
  apply Finset.prod_congr rfl
  intro other member
  have different : other ≠ key := by
    intro equal
    exact outside (equal ▸ member)
  simp [different]

theorem reject_completion_update_member (p : PMF α) (accept : α → Bool)
    (keys : Finset K) (table : Memo K α) (key : K) (value : α) (member : key ∈ keys) :
    rejectCompletion p accept keys (Function.update table key (some value)) =
      rejectFactor p accept (some value) * rejectCompletion p accept (keys.erase key) table := by
  unfold rejectCompletion
  rw [← Finset.mul_prod_erase keys _ member]
  rw [Function.update_self]
  congr 1
  exact reject_completion_update_other p accept (keys.erase key) table key value
    (Finset.notMem_erase key keys)

theorem reject_factor_average (p : PMF α) (accept : α → Bool) :
    (∑' value, p value * rejectFactor p accept (some value)) = rejectMass p accept := by
  apply tsum_congr
  intro value
  cases accepted : accept value <;> simp [rejectFactor, accepted]

theorem reject_completion_fresh_step (p : PMF α) (accept : α → Bool)
    (keys : Finset K) (table : Memo K α) (key : K) (fresh : table key = none) :
    (∑' value, p value *
      rejectCompletion p accept keys (Function.update table key (some value))) =
        rejectCompletion p accept keys table := by
  by_cases member : key ∈ keys
  · simp only [reject_completion_update_member p accept keys table key _ member, ← mul_assoc]
    rw [ENNReal.tsum_mul_right, reject_factor_average]
    unfold rejectCompletion
    rw [← Finset.mul_prod_erase keys _ member, fresh, rejectFactor]
  · simp only [reject_completion_update_other p accept keys table key _ member]
    rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]

omit [DecidableEq K] in
theorem reject_completion_dominates (p : PMF α) (accept : α → Bool)
    (keys : Finset K) (table : Memo K α) :
    (if CompleteRejection accept keys table then 1 else 0) ≤
      rejectCompletion p accept keys table := by
  classical
  split
  · rename_i complete
    have equal : rejectCompletion p accept keys table = 1 := by
      apply Finset.prod_eq_one
      intro key member
      obtain ⟨value, stored, rejected⟩ := complete key member
      simp [stored, rejectFactor, rejected]
    rw [equal]
  · exact zero_le _

theorem eval_program_complete_rejection_bound (p : PMF α) (accept : α → Bool)
    (keys : Finset K) {n : ℕ} (program : QueryProgram K α R n) (table : Memo K α) :
    (evalProgram p program table).toOuterMeasure
      {out | CompleteRejection accept keys out.2} ≤ rejectCompletion p accept keys table := by
  classical
  induction program generalizing table with
  | done value =>
    simpa only [evalProgram, PMF.toOuterMeasure_pure_apply, Set.mem_setOf_eq] using
      reject_completion_dominates p accept keys table
  | query key next ih =>
    cases cached : table key with
    | some value =>
      rw [evalProgram_cached p key next table value cached]
      exact ih value table
    | none =>
      rw [evalProgram_fresh p key next table cached, PMF.toOuterMeasure_bind_apply]
      calc
        _ ≤ ∑' value, p value *
            rejectCompletion p accept keys (Function.update table key (some value)) :=
          pmf_weighted_bound p _ _ (fun value _ => ih value _)
        _ = _ := reject_completion_fresh_step p accept keys table key cached

theorem randomized_complete_rejection_bound (p : PMF α) (accept : α → Bool)
    (keys : Finset K) {n : ℕ} (clients : PMF (QueryProgram K α R n)) :
    (randomizedProgram p clients (fun _ => none)).toOuterMeasure
      {out | CompleteRejection accept keys out.2} ≤ rejectMass p accept ^ keys.card := by
  rw [randomizedProgram, PMF.toOuterMeasure_bind_apply]
  calc
    _ ≤ ∑' program, clients program * rejectMass p accept ^ keys.card := by
      apply pmf_weighted_bound
      intro program _
      simpa only [reject_completion_empty] using
        eval_program_complete_rejection_bound p accept keys program (fun _ => none)
    _ = _ := by rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]

omit [DecidableEq K] in
theorem complete_rejection_extends (accept : α → Bool) (keys : Finset K)
    (before after : Memo K α) (extension : MemoExtends before after)
    (complete : CompleteRejection accept keys before) : CompleteRejection accept keys after := by
  intro key member
  obtain ⟨value, stored, rejected⟩ := complete key member
  exact ⟨value, extension key value stored, rejected⟩

end
end C10Probability

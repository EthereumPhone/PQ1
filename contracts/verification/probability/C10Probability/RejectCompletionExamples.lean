import C10Probability.RejectSchedule

/-! Independent finite witnesses distinguish absent, cached-reject and
cached-accept inputs. Prefill and duplicate keys refute the tempting stronger
independent-draw claim. An empty-cache premise is load-bearing. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem rejection_factor_branches :
    rejectFactor fairReply id none = (2 : ℝ≥0∞)⁻¹ ∧
    rejectFactor fairReply id (some false) = 1 ∧
    rejectFactor fairReply id (some true) = 0 := by
  simp [rejectFactor, fair_rejection]

theorem rejection_two_unknown_keys :
    rejectCompletion fairReply id ({false, true} : Finset Bool) (fun _ => none) =
      (4 : ℝ≥0∞)⁻¹ := by
  norm_num [rejectCompletion, rejectFactor, fair_rejection]
  rw [← ENNReal.inv_pow]
  norm_num

theorem rejection_one_cached_key :
    rejectCompletion fairReply id ({false, true} : Finset Bool)
      (fun key => if key then none else some false) = (2 : ℝ≥0∞)⁻¹ := by
  simp [rejectCompletion, rejectFactor, fair_rejection]

theorem rejection_cached_acceptance_blocks :
    rejectCompletion fairReply id ({false, true} : Finset Bool)
      (fun key => if key then none else some true) = 0 := by
  simp [rejectCompletion, rejectFactor]

theorem rejection_duplicate_has_one_factor :
    rejectCompletion fairReply id ([false, false].toFinset) (fun _ => none) =
      (2 : ℝ≥0∞)⁻¹ := by
  simp [rejectCompletion, rejectFactor, fair_rejection]

theorem rejection_prefill_counterexample :
    (evalProgram fairReply (.done () : QueryProgram Bool Bool Unit 0)
      (fun _ => some false)).toOuterMeasure
        {out | CompleteRejection id ({false, true} : Finset Bool) out.2} = 1 ∧
      rejectMass fairReply id ^ ({false, true} : Finset Bool).card < 1 := by
  constructor
  · simp only [evalProgram, PMF.toOuterMeasure_pure_apply, Set.mem_setOf_eq]
    simp [CompleteRejection]
  · norm_num [fair_rejection]
    rw [← ENNReal.inv_pow, ENNReal.inv_lt_one]
    norm_num

theorem rejection_one_missing_is_incomplete :
    ¬ CompleteRejection id ({false, true} : Finset Bool)
      (fun key => if key then none else some false) := by
  simp [CompleteRejection]

theorem rejection_one_accepted_is_incomplete :
    ¬ CompleteRejection id ({false, true} : Finset Bool)
      (fun key => if key then some true else some false) := by
  simp [CompleteRejection]

theorem rejection_two_distinct_exhaustion :
    ((memoGrind fairReply id (fun _ => none) 0 [false, true]).map Prod.fst) none =
      (4 : ℝ≥0∞)⁻¹ := by
  rw [memoGrind_empty fairReply id 0 [false, true] (by decide), grind_none, fair_rejection]
  norm_num
  rw [← ENNReal.inv_pow]
  norm_num

theorem rejection_duplicate_exhaustion :
    ((memoGrind fairReply id (fun _ => none) 0 [false, false]).map Prod.fst) none =
      (2 : ℝ≥0∞)⁻¹ := by
  exact memo_repeat_two_failure false

end
end C10Probability

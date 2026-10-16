import C10Probability.NodeCharges
import C10Probability.AdaptiveExamples

/-! Finite cache-event calculations independent of the general upper bound.
They distinguish fresh draws from repeats, early returns and existing hits. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem one_entry_no_target (value : Bool) :
    NoTarget id (Function.update (fun _ : Bool => none) false (some value)) ↔
      value = false := by
  unfold NoTarget
  cases value <;> decide

theorem two_entries_no_target (first second : Bool) :
    NoTarget id (Function.update
      (Function.update (fun _ : Bool => none) false (some first)) true (some second)) ↔
        first = false ∧ second = false := by
  unfold NoTarget
  cases first <;> cases second <;> decide

theorem repeatedBool_target_mass :
    (evalProgram fairReply repeatedBool (fun _ => none)).toOuterMeasure
      {out | ¬ NoTarget id out.2} = (2 : ℝ≥0∞)⁻¹ := by
  rw [repeatedBool, evalProgram_repeated fairReply false _ rfl, PMF.toOuterMeasure_map_apply]
  simp only [PMF.toOuterMeasure_apply, Set.indicator, Set.mem_preimage,
    Set.mem_setOf_eq, one_entry_no_target]
  norm_num [fairReply, tsum_fintype]

theorem twoBool_target_mass :
    (evalProgram fairReply twoBool (fun _ => none)).toOuterMeasure
      {out | ¬ NoTarget id out.2} = (3 : ℝ≥0∞) / 4 := by
  rw [twoBool_distribution, PMF.toOuterMeasure_bind_apply]
  simp only [PMF.toOuterMeasure_map_apply]
  simp only [PMF.toOuterMeasure_apply, Set.indicator,
    Set.mem_preimage, Set.mem_setOf_eq, two_entries_no_target]
  norm_num [fairReply, tsum_fintype]

  rw [ENNReal.inv_two_add_inv_two, mul_one]
  apply (ENNReal.toReal_eq_toReal_iff' (by finiteness) (by finiteness)).mp
  rw [ENNReal.toReal_add (by finiteness) (by finiteness)]
  norm_num [ENNReal.toReal_mul]

theorem adaptiveBool_target_mass :
    (evalProgram fairReply adaptiveBool (fun _ => none)).toOuterMeasure
      {out | ¬ NoTarget id out.2} = (2 : ℝ≥0∞)⁻¹ := by
  rw [adaptiveBool, evalProgram_fresh fairReply false _ _ rfl,
    PMF.toOuterMeasure_bind_apply]
  rw [tsum_fintype, Fintype.sum_bool]
  rw [evalProgram_initial_target_mass fairReply id _ _ false true (by simp) rfl]
  rw [evalProgram_cached fairReply false _ _ false (by simp)]
  simp only [evalProgram, PMF.toOuterMeasure_pure_apply, Set.mem_setOf_eq,
    one_entry_no_target]
  norm_num [fairReply]

def earlyTarget : QueryProgram Bool Bool Bool 2 :=
  .query false (fun first => if first then .done true
    else .query true (fun second => .done second))

theorem earlyTarget_mass :
    (evalProgram fairReply earlyTarget (fun _ => none)).toOuterMeasure
      {out | ¬ NoTarget id out.2} = (3 : ℝ≥0∞) / 4 := by
  rw [earlyTarget, evalProgram_fresh fairReply false _ _ rfl,
    PMF.toOuterMeasure_bind_apply]
  rw [tsum_fintype, Fintype.sum_bool]
  simp only [Bool.false_eq_true, ↓reduceIte]
  rw [evalProgram_fresh fairReply true _ _ (by simp), PMF.toOuterMeasure_bind_apply]
  simp only [evalProgram, PMF.toOuterMeasure_pure_apply, Set.mem_setOf_eq,
    one_entry_no_target, two_entries_no_target]
  norm_num [tsum_fintype, fairReply]
  apply (ENNReal.toReal_eq_toReal_iff' (by finiteness) (by finiteness)).mp
  rw [ENNReal.toReal_add (by finiteness) (by finiteness)]
  norm_num [ENNReal.toReal_mul]

def optionalQuery (active : Bool) : QueryProgram Bool Bool Bool 1 :=
  if active then .query false (fun reply => .done reply) else .done false

theorem randomized_optional_target_mass :
    (randomizedProgram fairReply (fairReply.map optionalQuery) (fun _ => none)).toOuterMeasure
      {out | ¬ NoTarget id out.2} = (4 : ℝ≥0∞)⁻¹ := by
  rw [randomizedProgram, PMF.bind_map, PMF.toOuterMeasure_bind_apply]
  rw [tsum_fintype, Fintype.sum_bool]
  simp only [Function.comp_def, optionalQuery, Bool.false_eq_true, ↓reduceIte]
  rw [evalProgram_fresh fairReply false _ _ rfl, PMF.toOuterMeasure_bind_apply]
  simp only [evalProgram, PMF.toOuterMeasure_pure_apply, Set.mem_setOf_eq,
    one_entry_no_target, noTarget_empty]
  norm_num [tsum_fintype, fairReply]
  rw [← pow_two, ← ENNReal.inv_pow]
  norm_num

theorem zero_queries_initial_target :
    (evalProgram fairReply (.done (n := 0) ()) (fun _ : Bool => some true)).toOuterMeasure
      {out | ¬ NoTarget id out.2} = 1 := by
  rw [evalProgram, PMF.toOuterMeasure_pure_apply]
  simp [NoTarget]

theorem zero_queries_safe_history :
    (evalProgram fairReply (.done (n := 0) ()) (fun _ : Bool => some false)).toOuterMeasure
      {out | ¬ NoTarget id out.2} = 0 := by
  rw [evalProgram, PMF.toOuterMeasure_pure_apply]
  simp [NoTarget]

theorem cached_safe_query_target_mass :
    (evalProgram fairReply (.query false (fun reply => .done (n := 0) reply))
      (fun _ : Bool => some false)).toOuterMeasure {out | ¬ NoTarget id out.2} = 0 := by
  simp only [evalProgram, memoQuery, PMF.pure_bind, PMF.toOuterMeasure_pure_apply]
  simp [NoTarget]

theorem rejecting_target_safe (table : Memo Bool Bool) :
    NoTarget (fun _ => false) table := by simp [NoTarget]

theorem all_reject_target_mass :
    (evalProgram fairReply twoBool (fun _ => none)).toOuterMeasure
      {out | ¬ NoTarget (fun _ => false) out.2} = 0 := by
  simp [rejecting_target_safe]

theorem all_accept_target_mass :
    (evalProgram fairReply (.query false (fun reply => .done (n := 0) reply))
      (fun _ => none)).toOuterMeasure {out | ¬ NoTarget (fun _ => true) out.2} = 1 := by
  rw [evalProgram_one, memoQuery_fresh fairReply _ false rfl,
    PMF.toOuterMeasure_map_apply, PMF.toOuterMeasure_apply]
  norm_num [Set.indicator, NoTarget, fairReply, tsum_fintype, ENNReal.inv_two_add_inv_two]

theorem fixed_target_empty (value : Bool) : inTargets id ∅ value = false := by
  simp [inTargets]

theorem fixed_target_singleton (value : Bool) : inTargets id {true} value = value := by
  cases value <;> decide

theorem fixed_target_full (value : Bool) : inTargets id Finset.univ value = true := by
  simp [inTargets]

theorem target_membership_nonvacuous : ¬ NoTarget id (fun _ : Bool => some true) := by
  unfold NoTarget
  decide

theorem target_lookup_matters : NoTarget id (fun _ : Bool => none) := by
  unfold NoTarget
  decide

theorem singleton_zero_collision_free :
    CollisionFree randomizerOfDigest
      (Function.update (fun _ : ByteKey => none) [] (some (1 : Digest))) := by
  intro key other value reply hk ho _
  have hkey : key = [] := by
    by_contra hn
    simp [Function.update_of_ne hn] at hk
  have hother : other = [] := by
    by_contra hn
    simp [Function.update_of_ne hn] at ho
  exact hkey.trans hother.symm

theorem public_zero_alone_bad :
    PublicNodeBad (Function.update (fun _ : ByteKey => none) [] (some (1 : Digest))) := by
  apply Or.inr
  exact ⟨[], 1, Function.update_self .., node_zero_low_bit⟩

theorem constant_nonzero_has_no_zero :
    ¬ PublicNodeZero (fun _ => some (⟨2 ^ 128, by decide⟩ : Digest)) := by
  rintro ⟨key, digest, h, hz⟩
  cases Option.some.inj h
  simp only [node_zero_retained_bit, Bool.false_eq_true] at hz

theorem public_collision_alone_bad :
    PublicNodeBad (fun _ => some (⟨2 ^ 128, by decide⟩ : Digest)) := by
  apply Or.inl
  intro h
  have he := h [] [0] _ _ rfl rfl rfl
  cases he

end
end C10Probability

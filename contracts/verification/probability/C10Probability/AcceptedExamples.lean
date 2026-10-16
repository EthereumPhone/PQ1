import C10Probability.AcceptedWots
import C10Probability.AdaptiveExamples

/-! Independent finite event computations for accepted collisions. These
evaluate the interpreter or observer directly; they do not assume the new
upper bound. Rejected duplicates differ from accepted duplicates, and a cached
lookup does not create a second input. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem one_entry_accepted_collision_free (value : Bool) :
    AcceptedCollisionFree id id (Function.update (fun _ : Bool => none) false (some value)) := by
  unfold AcceptedCollisionFree
  cases value <;> decide

theorem two_entries_accepted_collision (first second : Bool) :
    (¬ AcceptedCollisionFree id id (Function.update
      (Function.update (fun _ : Bool => none) false (some first)) true (some second))) ↔
        first = true ∧ second = true := by
  unfold AcceptedCollisionFree
  cases first <;> cases second <;> decide

theorem repeatedBool_accepted_collision_mass :
    (evalProgram fairReply repeatedBool (fun _ => none)).toOuterMeasure
      {out | ¬ AcceptedCollisionFree id id out.2} = 0 := by
  rw [repeatedBool, evalProgram_repeated fairReply false _ rfl, PMF.toOuterMeasure_map_apply]
  simp [one_entry_accepted_collision_free]

theorem twoBool_accepted_collision_mass :
    (evalProgram fairReply twoBool (fun _ => none)).toOuterMeasure
      {out | ¬ AcceptedCollisionFree id id out.2} = (4 : ℝ≥0∞)⁻¹ := by
  rw [twoBool_distribution, PMF.toOuterMeasure_bind_apply]
  simp only [PMF.toOuterMeasure_map_apply]
  simp only [PMF.toOuterMeasure_apply, Set.indicator, Set.mem_preimage,
    Set.mem_setOf_eq, two_entries_accepted_collision]
  norm_num [fairReply, tsum_fintype]
  rw [← pow_two, ← ENNReal.inv_pow]
  norm_num

theorem rejected_duplicates_are_accepted_collision_free :
    AcceptedCollisionFree id id (fun _ : Bool => some false) := by
  unfold AcceptedCollisionFree
  decide

theorem zero_queries_rejected_duplicates :
    (evalProgram fairReply (.done (n := 0) ()) (fun _ : Bool => some false)).toOuterMeasure
      {out | ¬ AcceptedCollisionFree id id out.2} = 0 := by
  rw [evalProgram, PMF.toOuterMeasure_pure_apply]
  simp [rejected_duplicates_are_accepted_collision_free]

theorem accepted_prior_collision : ¬ AcceptedCollisionFree id id (fun _ : Bool => some true) := by
  intro h
  have he := h false true true true rfl rfl rfl rfl
  cases he

theorem zero_queries_accepted_prior_collision :
    (evalProgram fairReply (.done (n := 0) ()) (fun _ : Bool => some true)).toOuterMeasure
      {out | ¬ AcceptedCollisionFree id id out.2} = 1 := by
  rw [evalProgram, PMF.toOuterMeasure_pure_apply]
  simp [accepted_prior_collision]

theorem rejected_reply_stored_without_growth :
    recordAcceptedReply id id (emptyView : CollisionView Bool Bool Bool) false false =
      ⟨Function.update (fun _ => none) false (some false), ∅, false⟩ := by
  rfl

theorem rejected_reply_preserves_prior_flag :
    (recordAcceptedReply id id (⟨fun _ : Bool => none, {true}, true⟩ : CollisionView Bool Bool Bool)
      true false).bad = true := by decide

theorem twoBool_accepted_observer_mass :
    ((observeAcceptedProgram fairReply id id twoBool emptyView).map (fun out => out.2.bad)) true =
      (4 : ℝ≥0∞)⁻¹ := by
  norm_num [observeAcceptedProgram, acceptedQuery, recordAcceptedReply, emptyView, twoBool,
    PMF.map_bind, PMF.bind_map, PMF.pure_map, PMF.bind_apply,
    Function.comp_def, fairReply, tsum_fintype]
  rw [← pow_two, ← ENNReal.inv_pow]
  norm_num

theorem repeatedBool_accepted_observer :
    (observeAcceptedProgram fairReply id id repeatedBool emptyView).map (fun out => out.2.bad) =
      PMF.pure false := by
  simp [observeAcceptedProgram, acceptedQuery, recordAcceptedReply, emptyView, repeatedBool,
    PMF.map_bind, PMF.bind_map, PMF.pure_map, Function.comp_def]

theorem adaptiveBool_accepted_observer_mass :
    ((observeAcceptedProgram fairReply id id adaptiveBool emptyView).map (fun out => out.2.bad)) true =
      (4 : ℝ≥0∞)⁻¹ := by
  have h : (observeAcceptedProgram fairReply id id adaptiveBool emptyView).map (fun out => out.2.bad) =
      fairReply.bind (fun first => if first then fairReply else PMF.pure false) := by
    simp only [adaptiveBool, observeAcceptedProgram, acceptedQuery, emptyView,
      PMF.bind_map, PMF.map_bind, Function.comp_def]
    congr 1
    funext first
    cases first <;> simp [recordAcceptedReply, PMF.pure_map, Function.comp_def]
  rw [h, PMF.bind_apply]
  norm_num [fairReply, tsum_fintype]
  rw [← pow_two, ← ENNReal.inv_pow]
  norm_num

def stopAfterRejected : QueryProgram Bool Bool Bool 2 :=
  .query false (fun first => if first then .query true (fun second => .done second) else .done false)

theorem stopped_rejection_distribution : evalProgram fairReply stopAfterRejected (fun _ => none) =
    fairReply.bind (fun first => if first then fairReply.map (fun second =>
      (second, Function.update (Function.update (fun _ => none) false (some true)) true (some second)))
    else PMF.pure (false, Function.update (fun _ => none) false (some false))) := by
  rw [stopAfterRejected, evalProgram_fresh fairReply false _ (fun _ : Bool => none) rfl]
  congr 1
  funext first
  cases first <;> simp [evalProgram, memoQuery, PMF.map, Function.comp_def]

theorem stopped_rejection_collision_mass :
    (evalProgram fairReply stopAfterRejected (fun _ => none)).toOuterMeasure
      {out | ¬ AcceptedCollisionFree id id out.2} = (4 : ℝ≥0∞)⁻¹ := by
  rw [stopped_rejection_distribution, PMF.toOuterMeasure_bind_apply]
  simp only [tsum_fintype, Fintype.sum_bool, Bool.false_eq_true, ↓reduceIte,
    PMF.toOuterMeasure_pure_apply, PMF.toOuterMeasure_map_apply]
  simp only [Set.mem_setOf_eq, one_entry_accepted_collision_free, not_true_eq_false,
    ↓reduceIte, mul_zero, add_zero, PMF.toOuterMeasure_apply, Set.indicator,
    Set.mem_preimage, two_entries_accepted_collision]
  norm_num [fairReply, tsum_fintype]
  rw [← pow_two, ← ENNReal.inv_pow]
  norm_num

theorem stopped_rejection_skips_second_key :
    ((evalProgram fairReply stopAfterRejected (fun _ => none)).map
      (fun out => decide (out.2 true = none))) true = (2 : ℝ≥0∞)⁻¹ := by
  have h : (evalProgram fairReply stopAfterRejected (fun _ => none)).map
      (fun out => decide (out.2 true = none)) = fairReply.map (fun first => !first) := by
    rw [stopped_rejection_distribution, PMF.map_bind]
    change fairReply.bind _ = fairReply.bind (fun first => PMF.pure (!first))
    congr 1
    funext first
    cases first <;> simp [PMF.pure_map, PMF.map_comp, Function.comp_def]
    exact PMF.map_const fairReply false
  rw [h]
  norm_num [fairReply, PMF.map_apply, tsum_fintype]

theorem reject_all_collision_free {K α V : Type*} (project : α → V) (table : Memo K α) :
    AcceptedCollisionFree project (fun _ => false) table := by
  simp [AcceptedCollisionFree]

theorem accept_all_collision_free_iff {K α V : Type*} (project : α → V) (table : Memo K α) :
    AcceptedCollisionFree project (fun _ => true) table ↔ CollisionFree project table := by
  simp [AcceptedCollisionFree, CollisionFree]

theorem twoBool_accept_all_mass :
    (evalProgram fairReply twoBool (fun _ => none)).toOuterMeasure
      {out | ¬ AcceptedCollisionFree id (fun _ => true) out.2} = (2 : ℝ≥0∞)⁻¹ := by
  simpa only [accept_all_collision_free_iff] using twoBool_collision_mass

theorem twoBool_reject_all_mass :
    (evalProgram fairReply twoBool (fun _ => none)).toOuterMeasure
      {out | ¬ AcceptedCollisionFree id (fun _ => false) out.2} = 0 := by
  simp only [reject_all_collision_free, not_true_eq_false, Set.setOf_false]
  simp

theorem boolean_acceptance_charge_tight :
    acceptedCollisionCharge (acceptMass fairReply id) 2 0 2 = (4 : ℝ≥0∞)⁻¹ := by
  norm_num [acceptedCollisionCharge, acceptMass, fairReply, tsum_fintype, div_eq_mul_inv]
  rw [← pow_two, ← ENNReal.inv_pow]
  norm_num

theorem accepted_history_collision_mass :
    (evalProgram fairReply (.query true (fun reply => .done (n := 0) reply))
      (Function.update (fun _ : Bool => none) false (some true))).toOuterMeasure
        {out | ¬ AcceptedCollisionFree id id out.2} = (2 : ℝ≥0∞)⁻¹ := by
  rw [evalProgram_one, memoQuery_fresh fairReply _ true (by simp),
    PMF.toOuterMeasure_map_apply]
  simp only [PMF.toOuterMeasure_apply, Set.indicator, Set.mem_preimage,
    Set.mem_setOf_eq, two_entries_accepted_collision]
  norm_num [fairReply, tsum_fintype]

theorem accepted_history_charge_tight :
    acceptedCollisionCharge (acceptMass fairReply id) 2 1 1 = (2 : ℝ≥0∞)⁻¹ := by
  norm_num [acceptedCollisionCharge, div_eq_mul_inv]

end
end C10Probability

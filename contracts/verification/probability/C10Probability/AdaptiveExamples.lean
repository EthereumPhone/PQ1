import C10Probability.AdaptiveCollision

/-! Independent finite witnesses for the adaptive interpreter and its observer.
Equal replies at distinct inputs count as collisions. Repeated lookup of one
input does not. Prior collisions cannot be covered by an empty-history charge. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def twoBool : QueryProgram Bool Bool (Bool × Bool) 2 :=
  .query false (fun first => .query true (fun second => .done (first, second)))

def repeatedBool : QueryProgram Bool Bool (Bool × Bool) 2 :=
  .query false (fun first => .query false (fun second => .done (first, second)))

theorem one_entry_collision_free (value : Bool) :
    CollisionFree id (Function.update (fun _ : Bool => none) false (some value)) := by
  unfold CollisionFree
  cases value <;> decide

theorem two_entries_collision (first second : Bool) :
    (¬ CollisionFree id (Function.update
      (Function.update (fun _ : Bool => none) false (some first)) true (some second))) ↔
        first = second := by
  unfold CollisionFree
  cases first <;> cases second <;> decide

theorem twoBool_distribution : evalProgram fairReply twoBool (fun _ => none) =
    fairReply.bind (fun first => fairReply.map (fun second =>
      ((first, second), Function.update
        (Function.update (fun _ => none) false (some first)) true (some second)))) := by
  simp [evalProgram, twoBool, memoQuery, PMF.map, Function.comp_def]

theorem repeatedBool_collision_mass :
    (evalProgram fairReply repeatedBool (fun _ => none)).toOuterMeasure
      {out | ¬ CollisionFree id out.2} = 0 := by
  rw [repeatedBool, evalProgram_repeated fairReply false _ rfl, PMF.toOuterMeasure_map_apply]
  simp [one_entry_collision_free]

theorem twoBool_collision_mass :
    (evalProgram fairReply twoBool (fun _ => none)).toOuterMeasure
      {out | ¬ CollisionFree id out.2} = (2 : ℝ≥0∞)⁻¹ := by
  rw [twoBool_distribution, PMF.toOuterMeasure_bind_apply]
  simp only [PMF.toOuterMeasure_map_apply]
  simp only [PMF.toOuterMeasure_apply, Set.indicator, Set.mem_preimage,
    Set.mem_setOf_eq, two_entries_collision]
  norm_num [fairReply, tsum_fintype]
  rw [← mul_assoc, ENNReal.mul_inv_cancel (by norm_num) (by simp), one_mul]

theorem repeatedBool_observer :
    (observeProgram fairReply id repeatedBool emptyView).map (fun out => out.2.bad) =
      PMF.pure false := by
  simp [observeProgram, observedQuery, recordReply, emptyView, repeatedBool,
    PMF.map_bind, PMF.bind_map, PMF.pure_map, Function.comp_def]

theorem twoBool_observer_mass :
    ((observeProgram fairReply id twoBool emptyView).map (fun out => out.2.bad)) true =
      (2 : ℝ≥0∞)⁻¹ := by
  norm_num [observeProgram, observedQuery, recordReply, emptyView, twoBool,
    PMF.map_bind, PMF.bind_map, PMF.pure_map, PMF.bind_apply,
    Function.comp_def, fairReply, tsum_fintype]
  rw [← mul_assoc, ENNReal.mul_inv_cancel (by norm_num) (by simp), one_mul]

theorem adaptiveBool_observer_mass :
    ((observeProgram fairReply id adaptiveBool emptyView).map (fun out => out.2.bad)) true =
      (4 : ℝ≥0∞)⁻¹ := by
  have h : (observeProgram fairReply id adaptiveBool emptyView).map (fun out => out.2.bad) =
      fairReply.bind (fun first => if first then fairReply else PMF.pure false) := by
    simp only [adaptiveBool, observeProgram, observedQuery, emptyView,
      PMF.bind_map, PMF.map_bind, Function.comp_def]
    congr 1
    funext first
    cases first <;> simp [recordReply, PMF.pure_map, Function.comp_def]
  rw [h, PMF.bind_apply]
  norm_num [fairReply, tsum_fintype]
  rw [← pow_two, ← ENNReal.inv_pow]
  norm_num

theorem history_collision_mass :
    (evalProgram fairReply (.query true (fun reply => .done (n := 0) reply))
      (Function.update (fun _ : Bool => none) false (some false))).toOuterMeasure
        {out | ¬ CollisionFree id out.2} = (2 : ℝ≥0∞)⁻¹ := by
  rw [evalProgram_one, memoQuery_fresh fairReply _ true (by simp),
    PMF.toOuterMeasure_map_apply]
  simp only [PMF.toOuterMeasure_apply, Set.indicator, Set.mem_preimage,
    Set.mem_setOf_eq, two_entries_collision]
  norm_num [fairReply, tsum_fintype]

theorem prior_collision : ¬ CollisionFree id (fun _ : Bool => some false) := by
  intro h
  have he := h false true false false rfl rfl rfl
  cases he

theorem zero_queries_with_prior_collision :
    (evalProgram fairReply (.done (n := 0) ()) (fun _ : Bool => some false)).toOuterMeasure
      {out | ¬ CollisionFree id out.2} = 1 := by
  rw [evalProgram, PMF.toOuterMeasure_pure_apply]
  simp [prior_collision]

theorem observer_retains_prior_flag :
    (recordReply id (⟨fun _ : Bool => none, {false}, true⟩ : CollisionView Bool Bool Bool)
      true true).bad = true := by decide

end
end C10Probability

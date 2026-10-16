import C10Probability.DomainGrind
import C10Probability.AdaptiveExamples

/-! Finite calculations and byte boundaries independent of the general bound.
In particular an excluded reply can choose whether later selected calls repeat. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem selected_cache_membership :
    selectedCache id (fun _ : Bool => some true) true = some true ∧
      selectedCache id (fun _ : Bool => some true) false = none := by decide

theorem excluded_reply_stored :
    let out := recordSelected id id (emptyView : CollisionView Bool Bool Bool) false true
    out.cache false = some true ∧ out.seen = ∅ ∧ out.bad = false := by decide

theorem selected_reply_seen :
    (recordSelected id id (emptyView : CollisionView Bool Bool Bool) true false).seen =
      {false} := by decide

theorem selected_reply_collision :
    (recordSelected id id (⟨fun _ : Bool => none, {true}, false⟩ : CollisionView Bool Bool Bool)
      true true).bad = true := by decide

theorem selected_prior_flag :
    (recordSelected id id (⟨fun _ : Bool => none, ∅, true⟩ : CollisionView Bool Bool Bool)
      false false).bad = true := by decide

theorem excluded_cached_reply :
    selectedQuery (PMF.pure false) id id
      (⟨fun _ : Bool => some true, ∅, false⟩ : CollisionView Bool Bool Bool) false =
      PMF.pure (true, ⟨fun _ => some true, ∅, false⟩) := by rfl

theorem selected_budget_counts_repeats :
    ¬ SelectedBudget id (.query true (fun _ : Bool => .query true
      (fun _ => .done (n := 0) ()))) 1 := by
  simp [SelectedBudget]

theorem excluded_budget_zero :
    SelectedBudget id (.query false (fun _ : Bool => .query false
      (fun _ => .done (n := 0) ()))) 0 := by
  simp [SelectedBudget]

theorem selected_budget_all_branches :
    ¬ SelectedBudget id (.query false (fun reply : Bool => .query reply
      (fun _ => .done (n := 0) ()))) 0 := by
  simp [SelectedBudget]

theorem bool_selected_cache_free (table : Memo Bool Bool) :
    CollisionFree id (selectedCache id table) := by
  intro key other value reply hk ho _
  cases key <;> cases other <;> simp_all [selectedCache]

theorem twoBool_selected_mass :
    (evalProgram fairReply twoBool (fun _ => none)).toOuterMeasure
      {out | ¬ CollisionFree id (selectedCache id out.2)} = 0 := by
  simp [bool_selected_cache_free]

theorem excluded_prior_history_valid :
    ViewValid id (selectedView (fun _ : Bool => false)
      (⟨fun _ => some false, ∅, false⟩ : CollisionView Bool Bool Bool)) := by
  simp [ViewValid, SeenCovers, CollisionFree, selectedView, selectedCache]

def selectThree (key : Fin 3) : Bool := decide (key ≠ 0)

def twoThreeCache (first second : Bool) : Memo (Fin 3) Bool :=
  Function.update (Function.update (fun _ => none) 0 (some first)) 1 (some second)

def threeCache (first second third : Bool) : Memo (Fin 3) Bool :=
  Function.update (twoThreeCache first second) 2 (some third)

theorem twoThree_selected_free (first second : Bool) :
    CollisionFree id (selectedCache selectThree (twoThreeCache first second)) := by
  unfold CollisionFree selectedCache selectThree twoThreeCache
  cases first <;> cases second <;> decide

theorem three_selected_collision (first second third : Bool) :
    (¬ CollisionFree id (selectedCache selectThree (threeCache first second third))) ↔
      second = third := by
  unfold CollisionFree selectedCache selectThree threeCache twoThreeCache
  cases first <;> cases second <;> cases third <;> decide

def mixedDomainProgram : QueryProgram (Fin 3) Bool Unit 3 :=
  .query 0 (fun first => .query 1 (fun _ =>
    .query (if first then 2 else 1) (fun _ => .done ())))

theorem mixed_domain_budget : SelectedBudget selectThree mixedDomainProgram 2 := by
  simp [SelectedBudget, mixedDomainProgram, selectThree]

theorem mixed_domain_distribution :
    evalProgram fairReply mixedDomainProgram (fun _ => none) =
      fairReply.bind (fun first => fairReply.bind (fun second =>
        if first then fairReply.map (fun third => ((), threeCache first second third))
        else PMF.pure ((), twoThreeCache first second))) := by
  rw [mixedDomainProgram, evalProgram_fresh fairReply 0 _ _ rfl]
  congr 1
  funext first
  rw [evalProgram_fresh fairReply 1 _ _ (by simp)]
  congr 1
  funext second
  cases first <;>
    simp [evalProgram, memoQuery, PMF.map, twoThreeCache, threeCache, Function.comp_def]

theorem mixed_domain_collision_mass :
    (evalProgram fairReply mixedDomainProgram (fun _ => none)).toOuterMeasure
      {out | ¬ CollisionFree id (selectedCache selectThree out.2)} = (4 : ℝ≥0∞)⁻¹ := by
  rw [mixed_domain_distribution, PMF.toOuterMeasure_bind_apply, tsum_fintype,
    Fintype.sum_bool]
  simp only [Bool.false_eq_true, ↓reduceIte, PMF.toOuterMeasure_bind_apply,
    PMF.toOuterMeasure_map_apply, PMF.toOuterMeasure_pure_apply, Set.mem_setOf_eq,
    twoThree_selected_free, not_true_eq_false, ↓reduceIte, mul_zero]
  simp only [PMF.toOuterMeasure_apply, Set.indicator, Set.mem_preimage,
    Set.mem_setOf_eq, three_selected_collision]
  norm_num [fairReply, tsum_fintype]
  rw [← mul_assoc (2 : ℝ≥0∞), ENNReal.mul_inv_cancel (by norm_num) (by simp), one_mul,
    ← pow_two, ← ENNReal.inv_pow]
  norm_num

theorem selected_history_collision_mass :
    (evalProgram fairReply (.query (2 : Fin 3) (fun reply => .done (n := 0) reply))
      (twoThreeCache false false)).toOuterMeasure
      {out | ¬ CollisionFree id (selectedCache selectThree out.2)} = (2 : ℝ≥0∞)⁻¹ := by
  rw [evalProgram_one, memoQuery_fresh fairReply _ 2 (by simp [twoThreeCache]),
    PMF.toOuterMeasure_map_apply]
  change (fairReply.toOuterMeasure {third | ¬ CollisionFree id
    (selectedCache selectThree (threeCache false false third))}) = _
  simp only [PMF.toOuterMeasure_apply, Set.indicator, Set.mem_setOf_eq, three_selected_collision]
  norm_num [fairReply, tsum_fintype]

theorem selected_prior_collision_mass :
    (evalProgram fairReply (.done (n := 0) ()) (threeCache false false false)).toOuterMeasure
      {out | ¬ CollisionFree id (selectedCache selectThree out.2)} = 1 := by
  rw [evalProgram, PMF.toOuterMeasure_pure_apply]
  simp [three_selected_collision]

theorem randomized_mixed_collision_mass :
    (randomizedProgram fairReply (fairReply.map (fun active =>
      if active then mixedDomainProgram else .done ())) (fun _ => none)).toOuterMeasure
      {out | ¬ CollisionFree id (selectedCache selectThree out.2)} = (8 : ℝ≥0∞)⁻¹ := by
  rw [randomizedProgram, PMF.bind_map, PMF.toOuterMeasure_bind_apply, tsum_fintype,
    Fintype.sum_bool]
  simp only [Function.comp_def, Bool.false_eq_true, ↓reduceIte, mixed_domain_collision_mass,
    evalProgram, PMF.toOuterMeasure_pure_apply, Set.mem_setOf_eq]
  have he : CollisionFree id (selectedCache selectThree (fun _ => (none : Option Bool))) := by
    simp [selectedCache_empty, CollisionFree]
  simp only [he, not_true_eq_false, ↓reduceIte, mul_zero, add_zero]
  norm_num [fairReply]
  rw [← ENNReal.mul_inv] <;> norm_num

theorem node_domain_count_zero_kind : nodeQuery (List.replicate 128 0) = false := by
  set_option maxRecDepth 4096 in
    decide +kernel

theorem node_domain_hmsg_width : nodeQuery (List.replicate 160 1) = false := by
  set_option maxRecDepth 4096 in
    decide +kernel

theorem node_domain_kind_first_byte :
    nodeQuery (List.replicate 44 0 ++ [1] ++ List.replicate 83 0) = true := by
  set_option maxRecDepth 4096 in
    decide +kernel

theorem node_domain_kind_last_byte :
    nodeQuery (List.replicate 47 0 ++ [1] ++ List.replicate 80 0) = true := by
  set_option maxRecDepth 4096 in
    decide +kernel

theorem node_domain_before_kind :
    nodeQuery (List.replicate 43 0 ++ [1] ++ List.replicate 84 0) = false := by
  set_option maxRecDepth 4096 in
    decide +kernel

theorem node_domain_after_kind :
    nodeQuery (List.replicate 48 0 ++ [1] ++ List.replicate 79 0) = false := by
  set_option maxRecDepth 4096 in
    decide +kernel

theorem node_domain_merkle_kind :
    nodeQuery (List.replicate 47 0 ++ [2] ++ List.replicate 80 0) = true := by
  set_option maxRecDepth 4096 in
    decide +kernel

theorem node_domain_fors_kind :
    nodeQuery (List.replicate 47 0 ++ [3] ++ List.replicate 80 0) = true := by
  set_option maxRecDepth 4096 in
    decide +kernel

theorem node_domain_malformed_retained : nodeQuery [] = true ∧
    nodeQuery (List.replicate 129 0) = true ∧ nodeQuery (List.replicate 159 0) = true ∧
    nodeQuery (List.replicate 161 0) = true := by
  set_option maxRecDepth 4096 in
    decide +kernel

theorem domain_zero_from_excluded :
    DomainNodeBad (Function.update (fun _ : ByteKey => none)
      (List.replicate 160 0) (some (1 : Digest))) := by
  apply Or.inr
  exact ⟨List.replicate 160 0, 1, Function.update_self .., node_zero_low_bit⟩

theorem domain_collision_alone_bad :
    DomainNodeBad (fun _ => some (⟨2 ^ 128, by decide⟩ : Digest)) := by
  apply Or.inl
  intro h
  have he := h [] [0] (⟨2 ^ 128, by decide⟩ : Digest) (⟨2 ^ 128, by decide⟩ : Digest)
    (by decide) (by decide) rfl
  cases he

end
end C10Probability

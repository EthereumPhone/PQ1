import C10Probability.SelectedBudget
import C10Probability.SelectedObserver
import C10Probability.AdaptiveCollision

/-! Birthday accounting for a fixed input domain. The structural index still
bounds all calls; only the separately proved selected budget enters this bound.
The event is on the selected part of the actual full final memo table. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {K α V R : Type*} [DecidableEq K] [DecidableEq V] [Fintype V] [Nonempty V]

theorem observeSelected_flag_bound (p : PMF α) (select : K → Bool) (project : α → V)
    (hu : p.map project = PMF.uniformOfFintype V) {n : ℕ}
    (program : QueryProgram K α R n) (q : ℕ) (budget : SelectedBudget select program q)
    (state : CollisionView K α V) (hb : state.bad = false) :
    ((observeSelected p select project program state).map (fun out => out.2.bad)) true ≤
      (collisionPairs state.seen.card q : ℝ≥0∞) / Fintype.card V := by
  induction program generalizing state q with
  | done value => simp [observeSelected, PMF.pure_map, hb]
  | query key next ih =>
    cases hs : select key with
    | false =>
      simp only [SelectedBudget, hs, Bool.false_eq_true, ↓reduceIte] at budget
      cases ht : state.cache key with
      | some value =>
        simp only [observeSelected, selectedQuery, ht, PMF.pure_bind]
        exact ih value q (budget value) state hb
      | none =>
        simp only [observeSelected, selectedQuery, ht, PMF.bind_map, PMF.map_bind,
          PMF.bind_apply, Function.comp_def]
        calc
          _ ≤ ∑' value, p value *
              ((collisionPairs state.seen.card q : ℝ≥0∞) / Fintype.card V) := by
            apply ENNReal.tsum_le_tsum
            intro value
            apply mul_le_mul_right
            simpa [recordSelected, hs] using
              ih value q (budget value) (recordSelected select project state key value)
                (by simp [recordSelected, hs, hb])
          _ = _ := by rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]
    | true =>
      simp only [SelectedBudget, hs, ↓reduceIte] at budget
      cases q with
      | zero => omega
      | succ q =>
        simp only [Nat.succ_sub_one] at budget
        cases ht : state.cache key with
        | some value =>
          simp only [observeSelected, selectedQuery, ht, PMF.pure_bind]
          exact (ih value q (budget.2 value) state hb).trans (ENNReal.div_le_div_right
            (by exact_mod_cast collision_pairs_mono_step state.seen.card q) _)
        | none =>
          simp only [observeSelected, selectedQuery, ht, PMF.bind_map, PMF.map_bind,
            PMF.bind_apply, Function.comp_def]
          calc
            _ ≤ ∑' value, p value * ((if project value ∈ state.seen then 1 else 0) +
                (collisionPairs (state.seen.card + 1) q : ℝ≥0∞) / Fintype.card V) := by
              apply ENNReal.tsum_le_tsum
              intro value
              apply mul_le_mul_right
              by_cases hm : project value ∈ state.seen
              · simp only [hm, ↓reduceIte]
                exact (PMF.coe_le_one _ true).trans (le_add_right le_rfl)
              · simpa [hm, recordSelected, hs, recordReply, hb,
                  Finset.card_insert_of_notMem hm] using
                  ih value q (budget.2 value) (recordSelected select project state key value)
                    (by simp [recordSelected, hs, recordReply, hb, hm])
            _ = (state.seen.card : ℝ≥0∞) / Fintype.card V +
                (collisionPairs (state.seen.card + 1) q : ℝ≥0∞) / Fintype.card V := by
              simp_rw [mul_add]
              rw [ENNReal.tsum_add, projected_seen_mass p project hu,
                ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]
            _ = _ := by rw [collision_pairs_step, Nat.cast_add, ENNReal.add_div]

theorem evalProgram_selected_collision_bound (p : PMF α) (select : K → Bool)
    (project : α → V) (hu : p.map project = PMF.uniformOfFintype V) {n : ℕ}
    (program : QueryProgram K α R n) (q : ℕ) (budget : SelectedBudget select program q)
    (state : CollisionView K α V) (hv : ViewValid project (selectedView select state))
    (hb : state.bad = false) :
    (evalProgram p program state.cache).toOuterMeasure
      {out | ¬ CollisionFree project (selectedCache select out.2)} ≤
        (collisionPairs state.seen.card q : ℝ≥0∞) / Fintype.card V := by
  rw [← observeSelected_erases p select project program state, PMF.toOuterMeasure_map_apply]
  exact (supported_event_le_flag _ _ (fun out => out.2.bad)
    (fun out ho hc => observeSelected_collision_flag p select project program state hv out ho hc)).trans
      (observeSelected_flag_bound p select project hu program q budget state hb)

theorem randomizedProgram_selected_collision_bound (p : PMF α) (select : K → Bool)
    (project : α → V) (hu : p.map project = PMF.uniformOfFintype V) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (q : ℕ)
    (budget : ∀ program ∈ client.support, SelectedBudget select program q)
    (state : CollisionView K α V) (hv : ViewValid project (selectedView select state))
    (hb : state.bad = false) :
    (randomizedProgram p client state.cache).toOuterMeasure
      {out | ¬ CollisionFree project (selectedCache select out.2)} ≤
        (collisionPairs state.seen.card q : ℝ≥0∞) / Fintype.card V := by
  rw [randomizedProgram, PMF.toOuterMeasure_bind_apply]
  calc
    _ ≤ ∑' program, client program *
        ((collisionPairs state.seen.card q : ℝ≥0∞) / Fintype.card V) := by
      apply ENNReal.tsum_le_tsum
      intro program
      by_cases hp : program ∈ client.support
      · exact mul_le_mul_right
          (evalProgram_selected_collision_bound p select project hu program q
            (budget program hp) state hv hb) _
      · simp [(client.apply_eq_zero_iff program).mpr hp]
    _ = _ := by rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]

theorem randomizedProgram_selected_collision_bound_real (p : PMF α) (select : K → Bool)
    (project : α → V) (hu : p.map project = PMF.uniformOfFintype V) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (q : ℕ)
    (budget : ∀ program ∈ client.support, SelectedBudget select program q)
    (state : CollisionView K α V) (hv : ViewValid project (selectedView select state))
    (hb : state.bad = false) :
    ((randomizedProgram p client state.cache).toOuterMeasure
      {out | ¬ CollisionFree project (selectedCache select out.2)}).toReal ≤
        (collisionPairs state.seen.card q : ℝ) / Fintype.card V := by
  have h := ENNReal.toReal_mono (show
      (collisionPairs state.seen.card q : ℝ≥0∞) / Fintype.card V ≠ ⊤ by
        exact ENNReal.div_ne_top (by simp) (by simp))
    (randomizedProgram_selected_collision_bound p select project hu client q budget state hv hb)
  simpa using h

theorem randomizedProgram_selected_empty_bound (p : PMF α) (select : K → Bool)
    (project : α → V) (hu : p.map project = PMF.uniformOfFintype V) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (q : ℕ)
    (budget : ∀ program ∈ client.support, SelectedBudget select program q) :
    (randomizedProgram p client (fun _ => none)).toOuterMeasure
      {out | ¬ CollisionFree project (selectedCache select out.2)} ≤
        (q.choose 2 : ℝ≥0∞) / Fintype.card V := by
  simpa only [emptyView, Finset.card_empty, collisionPairs, Nat.mul_zero, Nat.zero_add] using
    randomizedProgram_selected_collision_bound p select project hu client q budget emptyView
      (by rw [selectedView_empty]; exact emptyView_valid project) rfl

end
end C10Probability

import C10Probability.CollisionObserver
import C10Probability.Randomizer

/-! Birthday bounds for actual adaptive memoized programs. The theorem bounds
distinct inputs with equal projected replies in the final table. Cached calls
do not draw again, and a continuation may choose its next input from the reply.
Uniformity concerns fresh reply projections, not the client's query keys. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem collision_pairs_mono_history (h k n : ℕ) (hk : h ≤ k) :
    collisionPairs h n ≤ collisionPairs k n := by
  exact Nat.add_le_add_right (Nat.mul_le_mul_left n hk) _

theorem collision_pairs_mono_step (h n : ℕ) :
    collisionPairs h n ≤ collisionPairs h (n + 1) := by
  rw [collision_pairs_step]
  have hh := collision_pairs_mono_history h (h + 1) n (Nat.le_succ h)
  omega

variable {K α V R : Type*} [DecidableEq K] [DecidableEq V] [Fintype V] [Nonempty V]

theorem projected_seen_mass (p : PMF α) (project : α → V)
    (hu : p.map project = PMF.uniformOfFintype V) (seen : Finset V) :
    (∑' value, p value * (if project value ∈ seen then 1 else 0)) =
      (seen.card : ℝ≥0∞) / Fintype.card V := by
  have h := congrArg (fun q : PMF V => (q.map (fun value => decide (value ∈ seen))) true) hu
  rw [← uniform_seen_mass seen]
  simpa [PMF.map_comp, Function.comp_def, PMF.map_apply, mul_ite] using h

theorem observeProgram_flag_bound (p : PMF α) (project : α → V)
    (hu : p.map project = PMF.uniformOfFintype V) {n : ℕ}
    (program : QueryProgram K α R n) (state : CollisionView K α V)
    (hb : state.bad = false) :
    ((observeProgram p project program state).map (fun out => out.2.bad)) true ≤
      (collisionPairs state.seen.card n : ℝ≥0∞) / Fintype.card V := by
  induction program generalizing state with
  | done value => simp [observeProgram, PMF.pure_map, hb]
  | @query n key next ih =>
    cases ht : state.cache key with
    | some value =>
      simp only [observeProgram, observedQuery, ht, PMF.pure_bind]
      exact (ih value state hb).trans (ENNReal.div_le_div_right
        (by exact_mod_cast collision_pairs_mono_step state.seen.card n) _)
    | none =>
      simp only [observeProgram, observedQuery, ht, PMF.bind_map, PMF.map_bind,
        PMF.bind_apply, Function.comp_def]
      calc
        _ ≤ ∑' value, p value * ((if project value ∈ state.seen then 1 else 0) +
            (collisionPairs (state.seen.card + 1) n : ℝ≥0∞) / Fintype.card V) := by
          apply ENNReal.tsum_le_tsum
          intro value
          apply mul_le_mul_right
          by_cases hm : project value ∈ state.seen
          · simp only [hm, ↓reduceIte]
            exact (PMF.coe_le_one _ true).trans (le_add_right le_rfl)
          · simpa [hm, recordReply, hb, Finset.card_insert_of_notMem hm] using
              ih value (recordReply project state key value) (by simp [recordReply, hb, hm])
        _ = (state.seen.card : ℝ≥0∞) / Fintype.card V +
            (collisionPairs (state.seen.card + 1) n : ℝ≥0∞) / Fintype.card V := by
          simp_rw [mul_add]
          rw [ENNReal.tsum_add, projected_seen_mass p project hu,
            ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]
        _ = _ := by rw [collision_pairs_step, Nat.cast_add, ENNReal.add_div]

theorem supported_event_le_flag (q : PMF α) (event : Set α) (flag : α → Bool)
    (h : ∀ value ∈ q.support, value ∈ event → flag value = true) :
    q.toOuterMeasure event ≤ (q.map flag) true := by
  classical
  rw [PMF.toOuterMeasure_apply, PMF.map_apply]
  apply ENNReal.tsum_le_tsum
  intro value
  by_cases hs : value ∈ q.support
  · by_cases he : value ∈ event
    · simp [he, h value hs he]
    · simp [he]
  · have hz := (q.apply_eq_zero_iff value).mpr hs
    simp [hz]

theorem evalProgram_collision_bound (p : PMF α) (project : α → V)
    (hu : p.map project = PMF.uniformOfFintype V) {n : ℕ}
    (program : QueryProgram K α R n) (state : CollisionView K α V)
    (hv : ViewValid project state) (hb : state.bad = false) :
    (evalProgram p program state.cache).toOuterMeasure
      {out | ¬ CollisionFree project out.2} ≤
        (collisionPairs state.seen.card n : ℝ≥0∞) / Fintype.card V := by
  rw [← observeProgram_erases p project program state, PMF.toOuterMeasure_map_apply]
  exact (supported_event_le_flag _ _ (fun out => out.2.bad)
    (fun out ho hc => observeProgram_collision_flag p project program state hv out ho hc)).trans
      (observeProgram_flag_bound p project hu program state hb)

theorem randomizedProgram_collision_bound (p : PMF α) (project : α → V)
    (hu : p.map project = PMF.uniformOfFintype V) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (state : CollisionView K α V)
    (hv : ViewValid project state) (hb : state.bad = false) :
    (randomizedProgram p client state.cache).toOuterMeasure
      {out | ¬ CollisionFree project out.2} ≤
        (collisionPairs state.seen.card n : ℝ≥0∞) / Fintype.card V := by
  rw [randomizedProgram, PMF.toOuterMeasure_bind_apply]
  calc
    _ ≤ ∑' program, client program *
        ((collisionPairs state.seen.card n : ℝ≥0∞) / Fintype.card V) := by
      apply ENNReal.tsum_le_tsum
      intro program
      exact mul_le_mul_right (evalProgram_collision_bound p project hu program state hv hb) _
    _ = _ := by rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]

theorem randomizedProgram_collision_bound_real (p : PMF α) (project : α → V)
    (hu : p.map project = PMF.uniformOfFintype V) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (state : CollisionView K α V)
    (hv : ViewValid project state) (hb : state.bad = false) :
    ((randomizedProgram p client state.cache).toOuterMeasure
      {out | ¬ CollisionFree project out.2}).toReal ≤
        (collisionPairs state.seen.card n : ℝ) / Fintype.card V := by
  have h := ENNReal.toReal_mono (show
      (collisionPairs state.seen.card n : ℝ≥0∞) / Fintype.card V ≠ ⊤ by
        exact ENNReal.div_ne_top (by simp) (by simp))
    (randomizedProgram_collision_bound p project hu client state hv hb)
  simpa using h

theorem digest_program_collision_bound {n : ℕ}
    (client : PMF (QueryProgram ByteKey Digest R n)) :
    ((randomizedProgram digestDraw client (fun _ => none)).toOuterMeasure
      {out | ¬ CollisionFree randomizerOfDigest out.2}).toReal ≤
        (n.choose 2 : ℝ) / (2 : ℝ) ^ 128 := by
  simpa only [emptyView, Finset.card_empty, collisionPairs, Nat.mul_zero, Nat.zero_add,
    Fintype.card_fin, Nat.cast_pow, Nat.cast_ofNat] using randomizedProgram_collision_bound_real
    digestDraw randomizerOfDigest randomizer_uniform client emptyView
      (emptyView_valid randomizerOfDigest) rfl

end
end C10Probability

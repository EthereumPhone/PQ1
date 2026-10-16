import C10Probability.AcceptedObserver
import C10Probability.AdaptiveCollision

/-! Accepted collisions in actual adaptive memoized executions. The acceptance
factor is obtained from expected growth of the observed accepted history. It is
not a premise about collision probability or independence of query keys. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def acceptedCollisionCharge (mass : ℝ≥0∞) (size history trials : ℕ) : ℝ≥0∞ :=
  ((trials : ℝ≥0∞) * history + (trials.choose 2 : ℝ≥0∞) * mass) / size

theorem accepted_charge_zero (mass : ℝ≥0∞) (size history : ℕ) :
    acceptedCollisionCharge mass size history 0 = 0 := by
  simp [acceptedCollisionCharge]

theorem accepted_charge_history (mass : ℝ≥0∞) (size h n : ℕ) :
    acceptedCollisionCharge mass size (h + 1) n =
      acceptedCollisionCharge mass size h n + (n : ℝ≥0∞) / size := by
  simp only [acceptedCollisionCharge, Nat.cast_add, Nat.cast_one, div_eq_mul_inv]
  ring

theorem accepted_charge_step (mass : ℝ≥0∞) (size h n : ℕ) :
    acceptedCollisionCharge mass size h (n + 1) =
      (h : ℝ≥0∞) / size + acceptedCollisionCharge mass size h n +
        mass * ((n : ℝ≥0∞) / size) := by
  simp only [acceptedCollisionCharge, Nat.choose_succ_succ, Nat.choose_one_right,
    Nat.cast_add, Nat.cast_one, div_eq_mul_inv]
  ring

theorem accepted_charge_mono_step (mass : ℝ≥0∞) (size h n : ℕ) :
    acceptedCollisionCharge mass size h n ≤ acceptedCollisionCharge mass size h (n + 1) := by
  rw [accepted_charge_step]
  exact (le_add_left le_rfl).trans (le_add_right le_rfl)

theorem accepted_weight_mass {α : Type*} (p : PMF α) (accept : α → Bool) (weight : ℝ≥0∞) :
    (∑' value, p value * (if accept value then weight else 0)) =
      acceptMass p accept * weight := by
  rw [acceptMass, ← ENNReal.tsum_mul_right]
  apply tsum_congr
  intro value
  cases accept value <;> simp

theorem acceptMass_map {α V : Type*} (p : PMF α) (project : α → V) (accept : V → Bool) :
    acceptMass p (fun value => accept (project value)) = acceptMass (p.map project) accept := by
  rw [acceptMass_event, acceptMass_event, PMF.toOuterMeasure_map_apply]
  rfl

variable {K α V R : Type*} [DecidableEq K] [DecidableEq V] [Fintype V] [Nonempty V]

theorem observeAcceptedProgram_flag_bound (p : PMF α) (project : α → V) (accept : V → Bool)
    (hu : p.map project = PMF.uniformOfFintype V) {n : ℕ}
    (program : QueryProgram K α R n) (state : CollisionView K α V) (hb : state.bad = false) :
    ((observeAcceptedProgram p project accept program state).map (fun out => out.2.bad)) true ≤
      acceptedCollisionCharge (acceptMass p (fun value => accept (project value)))
        (Fintype.card V) state.seen.card n := by
  induction program generalizing state with
  | done value => simp [observeAcceptedProgram, PMF.pure_map, hb]
  | @query n key next ih =>
    cases ht : state.cache key with
    | some value =>
      simp only [observeAcceptedProgram, acceptedQuery, ht, PMF.pure_bind]
      exact (ih value state hb).trans (accepted_charge_mono_step _ _ _ _)
    | none =>
      simp only [observeAcceptedProgram, acceptedQuery, ht, PMF.bind_map, PMF.map_bind,
        PMF.bind_apply, Function.comp_def]
      calc
        _ ≤ ∑' value, p value * ((if project value ∈ state.seen then 1 else 0) +
            acceptedCollisionCharge (acceptMass p (fun value => accept (project value)))
              (Fintype.card V) state.seen.card n +
            (if accept (project value) then (n : ℝ≥0∞) / Fintype.card V else 0)) := by
          apply ENNReal.tsum_le_tsum
          intro value
          apply mul_le_mul_right
          cases ha : accept (project value) with
          | false =>
            have h := ih value (recordAcceptedReply project accept state key value)
              (by simp [recordAcceptedReply, hb, ha])
            simp only [Bool.false_eq_true, ↓reduceIte, add_zero]
            apply h.trans
            simp only [recordAcceptedReply, ha, Bool.false_eq_true, ↓reduceIte]
            exact le_add_left le_rfl
          | true =>
            by_cases hm : project value ∈ state.seen
            · simp only [hm, ↓reduceIte]
              exact (PMF.coe_le_one _ true).trans
                ((le_add_right le_rfl).trans (le_add_right le_rfl))
            · simpa [ha, hm, recordAcceptedReply, hb, Finset.card_insert_of_notMem hm,
                accepted_charge_history] using
                ih value (recordAcceptedReply project accept state key value)
                  (by simp [recordAcceptedReply, hb, ha, hm])
        _ = (state.seen.card : ℝ≥0∞) / Fintype.card V +
            acceptedCollisionCharge (acceptMass p (fun value => accept (project value)))
              (Fintype.card V) state.seen.card n +
            acceptMass p (fun value => accept (project value)) *
              ((n : ℝ≥0∞) / Fintype.card V) := by
          simp_rw [mul_add]
          rw [ENNReal.tsum_add, ENNReal.tsum_add, projected_seen_mass p project hu,
            ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul, accepted_weight_mass]
        _ = _ := (accepted_charge_step _ _ _ _).symm

theorem evalProgram_accepted_collision_bound (p : PMF α) (project : α → V) (accept : V → Bool)
    (hu : p.map project = PMF.uniformOfFintype V) {n : ℕ}
    (program : QueryProgram K α R n) (state : CollisionView K α V)
    (hv : AcceptedViewValid project accept state) (hb : state.bad = false) :
    (evalProgram p program state.cache).toOuterMeasure
      {out | ¬ AcceptedCollisionFree project accept out.2} ≤
        acceptedCollisionCharge (acceptMass p (fun value => accept (project value)))
          (Fintype.card V) state.seen.card n := by
  rw [← observeAcceptedProgram_erases p project accept program state,
    PMF.toOuterMeasure_map_apply]
  exact (supported_event_le_flag _ _ (fun out => out.2.bad)
    (fun out ho hc => observeAcceptedProgram_collision_flag p project accept program
      state hv out ho hc)).trans (observeAcceptedProgram_flag_bound p project accept hu program state hb)

theorem randomizedProgram_accepted_collision_bound (p : PMF α) (project : α → V)
    (accept : V → Bool) (hu : p.map project = PMF.uniformOfFintype V) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (state : CollisionView K α V)
    (hv : AcceptedViewValid project accept state) (hb : state.bad = false) :
    (randomizedProgram p client state.cache).toOuterMeasure
      {out | ¬ AcceptedCollisionFree project accept out.2} ≤
        acceptedCollisionCharge (acceptMass p (fun value => accept (project value)))
          (Fintype.card V) state.seen.card n := by
  rw [randomizedProgram, PMF.toOuterMeasure_bind_apply]
  calc
    _ ≤ ∑' program, client program *
        acceptedCollisionCharge (acceptMass p (fun value => accept (project value)))
          (Fintype.card V) state.seen.card n := by
      apply ENNReal.tsum_le_tsum
      intro program
      exact mul_le_mul_right
        (evalProgram_accepted_collision_bound p project accept hu program state hv hb) _
    _ = _ := by rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]

theorem accepted_charge_ne_top (p : PMF α) (accept : α → Bool) (size h n : ℕ)
    (hs : size ≠ 0) : acceptedCollisionCharge (acceptMass p accept) size h n ≠ ⊤ := by
  apply ENNReal.div_ne_top
  · exact ENNReal.add_ne_top.mpr ⟨ENNReal.mul_ne_top (by simp) (by simp),
      ENNReal.mul_ne_top (by simp) (ne_top_of_le_ne_top ENNReal.one_ne_top
        (acceptMass_le_one p accept))⟩
  · exact_mod_cast hs

theorem randomizedProgram_accepted_collision_bound_real (p : PMF α) (project : α → V)
    (accept : V → Bool) (hu : p.map project = PMF.uniformOfFintype V) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (state : CollisionView K α V)
    (hv : AcceptedViewValid project accept state) (hb : state.bad = false) :
    ((randomizedProgram p client state.cache).toOuterMeasure
      {out | ¬ AcceptedCollisionFree project accept out.2}).toReal ≤
        ((n : ℝ) * state.seen.card + (n.choose 2 : ℝ) *
          (acceptMass p (fun value => accept (project value))).toReal) / Fintype.card V := by
  have h := ENNReal.toReal_mono
    (accepted_charge_ne_top p (fun value => accept (project value)) (Fintype.card V)
      state.seen.card n (Fintype.card_ne_zero))
    (randomizedProgram_accepted_collision_bound p project accept hu client state hv hb)
  have hfirst : (n : ℝ≥0∞) * state.seen.card ≠ ⊤ :=
    ENNReal.mul_ne_top (by simp) (by simp)
  have hsecond : (n.choose 2 : ℝ≥0∞) *
      acceptMass p (fun value => accept (project value)) ≠ ⊤ :=
    ENNReal.mul_ne_top (by simp) (ne_top_of_le_ne_top ENNReal.one_ne_top
      (acceptMass_le_one p (fun value => accept (project value))))
  simpa [acceptedCollisionCharge, ENNReal.toReal_add hfirst hsecond] using h

end
end C10Probability

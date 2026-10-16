import C10Probability.QueryProgram
import C10Probability.Transfer

/-! Target hits in the actual final memo cache. The predicate is fixed before
execution; query keys and early returns may depend on replies. A nonempty
initial table must be free of target hits for the new-query bound to apply. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {K α R : Type*}

def NoTarget (target : α → Bool) (table : Memo K α) : Prop :=
  ∀ (key : K) (value : α), table key = some value → target value = false

theorem noTarget_empty (target : α → Bool) :
    NoTarget target (fun _ : K => none) := by simp [NoTarget]

theorem noTarget_update [DecidableEq K] (target : α → Bool) (table : Memo K α)
    (h : NoTarget target table) (key : K) (value : α) (hv : target value = false) :
    NoTarget target (Function.update table key (some value)) := by
  intro other reply hr
  by_cases hk : other = key
  · subst other
    simp only [Function.update_self, Option.some.injEq] at hr
    simpa only [← hr] using hv
  · exact h other reply (by simpa only [Function.update_of_ne hk] using hr)

/-- The budget bounds every continuation, including cached calls and early returns. -/
theorem evalProgram_target_bound [DecidableEq K] (p : PMF α) (target : α → Bool) {n : ℕ}
    (program : QueryProgram K α R n) (table : Memo K α) (h : NoTarget target table) :
    (evalProgram p program table).toOuterMeasure {out | ¬ NoTarget target out.2} ≤
      (n : ℝ≥0∞) * acceptMass p target := by
  induction program generalizing table with
  | done result => simp [evalProgram, PMF.toOuterMeasure_pure_apply, h]
  | @query n key next ih =>
    cases ht : table key with
    | some value =>
      rw [evalProgram_cached p key next table value ht]
      exact (ih value table h).trans (mul_le_mul_left
        (show (n : ℝ≥0∞) ≤ ((n + 1 : ℕ) : ℝ≥0∞) by exact_mod_cast Nat.le_succ n) _)
    | none =>
      rw [evalProgram_fresh p key next table ht, PMF.toOuterMeasure_bind_apply]
      calc
        _ ≤ ∑' value, p value * ((if target value then 1 else 0) +
            (n : ℝ≥0∞) * acceptMass p target) := by
          apply ENNReal.tsum_le_tsum
          intro value
          apply mul_le_mul_right
          cases hv : target value with
          | true =>
            simp only [↓reduceIte]
            exact (event_mass_le_one _ _).trans (le_add_right le_rfl)
          | false =>
            simpa only [hv, Bool.false_eq_true, ↓reduceIte, zero_add] using
              ih value (Function.update table key (some value))
                (noTarget_update target table h key value hv)
        _ = acceptMass p target + (n : ℝ≥0∞) * acceptMass p target := by
          simp_rw [mul_add]
          rw [ENNReal.tsum_add, ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]
          simp only [acceptMass, mul_ite, mul_one, mul_zero]
        _ = _ := by
          rw [Nat.cast_add, Nat.cast_one, add_mul, one_mul]
          exact add_comm _ _

theorem randomizedProgram_target_bound [DecidableEq K] (p : PMF α) (target : α → Bool) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (table : Memo K α) (h : NoTarget target table) :
    (randomizedProgram p client table).toOuterMeasure {out | ¬ NoTarget target out.2} ≤
      (n : ℝ≥0∞) * acceptMass p target := by
  rw [randomizedProgram, PMF.toOuterMeasure_bind_apply]
  calc
    _ ≤ ∑' program, client program * ((n : ℝ≥0∞) * acceptMass p target) := by
      apply ENNReal.tsum_le_tsum
      intro program
      exact mul_le_mul_right (evalProgram_target_bound p target program table h) _
    _ = _ := by rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]

theorem randomizedProgram_target_bound_real [DecidableEq K] (p : PMF α) (target : α → Bool) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (table : Memo K α) (h : NoTarget target table) :
    ((randomizedProgram p client table).toOuterMeasure
      {out | ¬ NoTarget target out.2}).toReal ≤
        (n : ℝ) * (acceptMass p target).toReal := by
  have hm : acceptMass p target ≠ ⊤ :=
    ne_top_of_le_ne_top ENNReal.one_ne_top (acceptMass_le_one p target)
  have hn : (n : ℝ≥0∞) * acceptMass p target ≠ ⊤ := ENNReal.mul_ne_top (by simp) hm
  have hb := ENNReal.toReal_mono hn (randomizedProgram_target_bound p target client table h)
  simpa only [ENNReal.toReal_mul, ENNReal.toReal_natCast] using hb

/-- Cached target hits cannot be erased by later execution, even at zero budget. -/
theorem evalProgram_initial_target_mass [DecidableEq K] (p : PMF α) (target : α → Bool) {n : ℕ}
    (program : QueryProgram K α R n) (table : Memo K α) (key : K) (value : α)
    (hv : table key = some value) (ht : target value = true) :
    (evalProgram p program table).toOuterMeasure {out | ¬ NoTarget target out.2} = 1 := by
  apply (PMF.toOuterMeasure_apply_eq_one_iff _ _).mpr
  intro out ho
  change ¬ NoTarget target out.2
  intro hn
  have hp := evalProgram_preserves p program table key value hv out ho
  have hf := hn key value hp
  simp only [ht, Bool.true_eq_false] at hf

theorem randomizedProgram_initial_target_mass [DecidableEq K] (p : PMF α) (target : α → Bool) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (table : Memo K α) (key : K) (value : α)
    (hv : table key = some value) (ht : target value = true) :
    (randomizedProgram p client table).toOuterMeasure {out | ¬ NoTarget target out.2} = 1 := by
  rw [randomizedProgram, PMF.toOuterMeasure_bind_apply]
  simp_rw [evalProgram_initial_target_mass p target _ table key value hv ht, mul_one]
  exact client.tsum_coe

end
end C10Probability

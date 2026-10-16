import Mathlib.Probability.ProbabilityMassFunction.Constructions
import Mathlib.Tactic

/-!
# Bounded first-accepted sampling

This is an independent-sample comparison experiment. Calling a memoized hash
oracle repeatedly does not, by itself, implement this PMF. In particular,
exhaustion remains an outcome and is never conditioned away.
-/

namespace C10Probability

open scoped ENNReal
noncomputable section

variable {α : Type*}

/-- Start at the supplied counter, return the first accepted sample and its
counter, or `none` after exactly `budget` rejected samples. -/
def grind (p : PMF α) (accept : α → Bool) (start : ℕ) : ℕ → PMF (Option (ℕ × α))
  | 0 => PMF.pure none
  | n + 1 => p.bind fun x =>
      if accept x then PMF.pure (some (start, x)) else grind p accept (start + 1) n

/-- One-draw rejection probability. -/
def rejectMass (p : PMF α) (accept : α → Bool) : ℝ≥0∞ :=
  ∑' x, if accept x then 0 else p x

/-- One-draw acceptance probability. -/
def acceptMass (p : PMF α) (accept : α → Bool) : ℝ≥0∞ :=
  ∑' x, if accept x then p x else 0

theorem acceptMass_event (p : PMF α) (accept : α → Bool) :
    acceptMass p accept = p.toOuterMeasure {x | accept x = true} := by
  rw [acceptMass, PMF.toOuterMeasure_apply]
  apply tsum_congr
  intro x
  cases h : accept x <;> simp [Set.indicator, h]

theorem acceptMass_pos (p : PMF α) (accept : α → Bool) (x : α)
    (hx : accept x = true) (hp : 0 < p x) : 0 < acceptMass p accept := by
  apply lt_of_lt_of_le hp
  simpa [acceptMass, hx] using
    (ENNReal.le_tsum (f := fun a => if accept a then p a else 0) x)

theorem mass_partition (p : PMF α) (accept : α → Bool) :
    acceptMass p accept + rejectMass p accept = 1 := by
  rw [acceptMass, rejectMass, ← ENNReal.tsum_add]
  trans ∑' x, p x
  · apply tsum_congr
    intro x
    cases accept x <;> simp
  · exact p.tsum_coe

theorem rejectMass_le_one (p : PMF α) (accept : α → Bool) :
    rejectMass p accept ≤ 1 := by
  rw [← mass_partition p accept]
  exact le_add_left le_rfl

theorem acceptMass_le_one (p : PMF α) (accept : α → Bool) :
    acceptMass p accept ≤ 1 := by
  rw [← mass_partition p accept]
  exact le_add_right le_rfl

theorem rejectMass_real (p : PMF α) (accept : α → Bool) :
    (rejectMass p accept).toReal = 1 - (acceptMass p accept).toReal := by
  have ha := ne_top_of_le_ne_top ENNReal.one_ne_top (acceptMass_le_one p accept)
  have hr := ne_top_of_le_ne_top ENNReal.one_ne_top (rejectMass_le_one p accept)
  have h := congrArg ENNReal.toReal (mass_partition p accept)
  rw [ENNReal.toReal_add ha hr, ENNReal.toReal_one] at h
  linarith

theorem grind_step (p : PMF α) (accept : α → Bool) (start n : ℕ)
    (y : Option (ℕ × α)) :
    grind p accept start (n + 1) y =
      (∑' x, if accept x then p x * PMF.pure (some (start, x)) y else 0) +
      rejectMass p accept * grind p accept (start + 1) n y := by
  rw [grind, PMF.bind_apply, rejectMass, ← ENNReal.tsum_mul_right, ← ENNReal.tsum_add]
  apply tsum_congr
  intro x
  cases accept x <;> simp

theorem grind_none (p : PMF α) (accept : α → Bool) (start n : ℕ) :
    grind p accept start n none = rejectMass p accept ^ n := by
  induction n generalizing start with
  | zero => simp [grind]
  | succ n ih =>
    rw [grind_step]
    simp only [PMF.pure_apply, reduceCtorEq, if_false, mul_zero, ite_self,
      tsum_zero, zero_add, ih, pow_succ']

theorem grind_some_step (p : PMF α) (accept : α → Bool) (start n i : ℕ) (x : α) :
    grind p accept start (n + 1) (some (i, x)) =
      (if i = start ∧ accept x = true then p x else 0) +
      rejectMass p accept * grind p accept (start + 1) n (some (i, x)) := by
  classical
  rw [grind_step]
  congr 1
  rw [tsum_eq_single x]
  · by_cases hi : i = start <;> cases accept x <;> simp [PMF.pure_apply, hi]
  · intro a ha
    simp [PMF.pure_apply, Ne.symm ha]

theorem grind_some (p : PMF α) (accept : α → Bool) (start n i : ℕ) (x : α) :
    grind p accept start n (some (i, x)) =
      if start ≤ i ∧ i < start + n ∧ accept x = true
      then rejectMass p accept ^ (i - start) * p x else 0 := by
  induction n generalizing start with
  | zero => simp [grind]; omega
  | succ n ih =>
    rw [grind_some_step, ih]
    by_cases ha : accept x = true
    · by_cases hi : i = start
      · subst i
        simp [ha]
      · by_cases hr : start + 1 ≤ i ∧ i < start + 1 + n
        · have hbound : start ≤ i ∧ i < start + (n + 1) := by omega
          have hexp : i - start = (i - (start + 1)) + 1 := by omega
          simp only [hi, ha, false_and, ↓reduceIte, hr.1, hr.2, and_self,
            hbound.1, hbound.2, zero_add]
          rw [hexp, pow_succ']
          exact (mul_assoc _ _ _).symm
        · have hbound : ¬ (start ≤ i ∧ i < start + (n + 1)) := by omega
          have htail : ¬ (start + 1 ≤ i ∧ i < start + 1 + n ∧ accept x = true) := by omega
          have hout : ¬ (start ≤ i ∧ i < start + (n + 1) ∧ accept x = true) := by omega
          simp only [hi, false_and, if_false, if_neg htail, if_neg hout, mul_zero, zero_add]
    · simp [ha]

theorem grind_none_real (p : PMF α) (accept : α → Bool) (start n : ℕ) :
    (grind p accept start n none).toReal = (1 - (acceptMass p accept).toReal) ^ n := by
  rw [grind_none, ENNReal.toReal_pow, rejectMass_real]

theorem grind_some_real (p : PMF α) (accept : α → Bool) (start n i : ℕ) (x : α) :
    (grind p accept start n (some (i, x))).toReal =
      if start ≤ i ∧ i < start + n ∧ accept x = true
      then (1 - (acceptMass p accept).toReal) ^ (i - start) * (p x).toReal else 0 := by
  rw [grind_some]
  split_ifs <;> simp [ENNReal.toReal_mul, ENNReal.toReal_pow, rejectMass_real]

/-- Every returned pair is accepted and its counter is inside the budget. -/
theorem grind_returned (p : PMF α) (accept : α → Bool) (start n i : ℕ) (x : α)
    (h : some (i, x) ∈ (grind p accept start n).support) :
    start ≤ i ∧ i < start + n ∧ accept x = true := by
  rw [PMF.mem_support_iff, grind_some] at h
  by_contra hn
  simp [hn] at h

/-- Discard only the counter, retaining failure as `none`. -/
def samples (p : PMF α) (accept : α → Bool) (n : ℕ) : PMF (Option α) :=
  (grind p accept 0 n).map (Option.map Prod.snd)

theorem tsum_option_enn (f : Option α → ℝ≥0∞) :
    ∑' x, f x = f none + ∑' x, f (some x) := by
  calc
    _ = ∑' x : α ⊕ PUnit.{1}, f ((Equiv.optionEquivSumPUnit α).symm x) :=
      ((Equiv.optionEquivSumPUnit α).symm.tsum_eq f).symm
    _ = _ := by rw [ENNReal.summable.tsum_sum ENNReal.summable]; simp [add_comm]

theorem samples_none (p : PMF α) (accept : α → Bool) (n : ℕ) :
    samples p accept n none = rejectMass p accept ^ n := by
  classical
  simp [samples, PMF.map_apply, grind_none]

theorem samples_some (p : PMF α) (accept : α → Bool) (n : ℕ) (x : α) :
    samples p accept n (some x) =
      if accept x then (∑ i ∈ Finset.range n, rejectMass p accept ^ i) * p x else 0 := by
  classical
  have hmap : samples p accept n (some x) = ∑' i, grind p accept 0 n (some (i, x)) := by
    rw [samples, PMF.map_apply, tsum_option_enn]
    simp only [Option.map_none, reduceCtorEq, ↓reduceIte, zero_add]
    rw [ENNReal.tsum_prod']
    apply tsum_congr
    intro i
    simp only [Option.map_some, Option.some.injEq]
    rw [tsum_eq_single x]
    · simp
    · intro a ha
      simp [Ne.symm ha]
  rw [hmap]
  have hsum : (∑' i, grind p accept 0 n (some (i, x))) =
      ∑ i ∈ Finset.range n, grind p accept 0 n (some (i, x)) := by
    apply tsum_eq_sum
    intro i hi
    simp only [Finset.mem_range, not_lt] at hi
    simp [grind_some, Nat.not_lt_of_ge hi]
  rw [hsum]
  cases ha : accept x
  · simp [grind_some, ha]
  · simp only [↓reduceIte, Finset.sum_mul]
    apply Finset.sum_congr rfl
    intro i hi
    simp [grind_some, ha, Finset.mem_range.mp hi]

end
end C10Probability

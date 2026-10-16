import C10Probability.Grind

/-! # Unconditioned probabilities of accepted outputs

The event is fixed before the draws. Failure contributes zero. The exact
formula keeps the bounded-success factor; it does not assume success.
-/

namespace C10Probability

open scoped ENNReal
noncomputable section

variable {α : Type*}

def geometricMass (p : PMF α) (accept : α → Bool) (n : ℕ) : ℝ≥0∞ :=
  ∑ i ∈ Finset.range n, rejectMass p accept ^ i

def returnedMass (p : PMF α) (accept event : α → Bool) (n : ℕ) : ℝ≥0∞ :=
  acceptMass (samples p accept n) (fun result => result.any event)

theorem returnedMass_exact (p : PMF α) (accept event : α → Bool) (n : ℕ) :
    returnedMass p accept event n =
      geometricMass p accept n * acceptMass p (fun x => accept x && event x) := by
  rw [returnedMass, acceptMass, tsum_option_enn]
  simp only [Option.any_none, Bool.false_eq_true, ↓reduceIte, zero_add, Option.any_some]
  rw [acceptMass, ← ENNReal.tsum_mul_left]
  apply tsum_congr
  intro x
  rw [samples_some]
  by_cases ha : accept x = true <;> by_cases he : event x = true <;>
    simp [ha, he, geometricMass]

theorem bounded_mass_partition (p : PMF α) (accept : α → Bool) (n : ℕ) :
    rejectMass p accept ^ n + geometricMass p accept n * acceptMass p accept = 1 := by
  have h := (samples p accept n).tsum_coe
  rw [tsum_option_enn, samples_none] at h
  have hs : (∑' x, samples p accept n (some x)) =
      geometricMass p accept n * acceptMass p accept := by
    rw [acceptMass, ← ENNReal.tsum_mul_left]
    apply tsum_congr
    intro x
    rw [samples_some]
    cases accept x <;> simp [geometricMass]
  rwa [hs] at h

theorem bounded_mass_partition_real (p : PMF α) (accept : α → Bool) (n : ℕ) :
    (geometricMass p accept n).toReal * (acceptMass p accept).toReal =
      1 - (1 - (acceptMass p accept).toReal) ^ n := by
  have h := bounded_mass_partition p accept n
  have hl : rejectMass p accept ^ n ≤ 1 := by rw [← h]; exact le_add_right le_rfl
  have hr : geometricMass p accept n * acceptMass p accept ≤ 1 := by
    rw [← h]; exact le_add_left le_rfl
  have he := congrArg ENNReal.toReal h
  rw [ENNReal.toReal_add (ne_top_of_le_ne_top ENNReal.one_ne_top hl)
      (ne_top_of_le_ne_top ENNReal.one_ne_top hr), ENNReal.toReal_one,
    ENNReal.toReal_pow, ENNReal.toReal_mul, rejectMass_real] at he
  linarith

/-- Positive acceptance is needed only to write the ratio, not to define or
terminate the search. The numerator also enforces acceptance. -/
theorem returnedMass_real (p : PMF α) (accept event : α → Bool) (n : ℕ)
    (ha : 0 < acceptMass p accept) :
    (returnedMass p accept event n).toReal =
      (1 - (1 - (acceptMass p accept).toReal) ^ n) *
        ((acceptMass p (fun x => accept x && event x)).toReal /
          (acceptMass p accept).toReal) := by
  have hfinite := ne_top_of_le_ne_top ENNReal.one_ne_top (acceptMass_le_one p accept)
  have hp : 0 < (acceptMass p accept).toReal := ENNReal.toReal_pos ha.ne' hfinite
  rw [returnedMass_exact, ENNReal.toReal_mul, ← bounded_mass_partition_real]
  field_simp

theorem returnedMass_le_conditional (p : PMF α) (accept event : α → Bool) (n : ℕ)
    (ha : 0 < acceptMass p accept) :
    (returnedMass p accept event n).toReal ≤
      (acceptMass p (fun x => accept x && event x)).toReal /
        (acceptMass p accept).toReal := by
  rw [returnedMass_real p accept event n ha]
  apply mul_le_of_le_one_left (div_nonneg ENNReal.toReal_nonneg ENNReal.toReal_nonneg)
  have hr : 0 ≤ 1 - (acceptMass p accept).toReal := by
    rw [← rejectMass_real]
    exact ENNReal.toReal_nonneg
  have := pow_nonneg hr n
  linarith

end
end C10Probability

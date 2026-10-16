import C10Probability.Uniform
import Mathlib.Data.Nat.Choose.Basic

/-! A collision detector for independent uniform query keys, including keys
already in a finite history. This experiment does not assert that a concrete
secret-keyed randomizer produces independent keys in the full signer session. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {K : Type*} [Fintype K] [Nonempty K] [DecidableEq K]

def keyCollision (seen : Finset K) : ℕ → PMF Bool
  | 0 => PMF.pure false
  | n + 1 => (PMF.uniformOfFintype K).bind fun key =>
      if key ∈ seen then PMF.pure true else keyCollision (insert key seen) n

/-- One possible hit against each old key per trial, and each earlier trial. -/
def collisionPairs (history trials : ℕ) : ℕ := trials * history + trials.choose 2

theorem collision_pairs_zero (h : ℕ) : collisionPairs h 0 = 0 := by
  simp [collisionPairs]

theorem collision_pairs_step (h n : ℕ) :
    collisionPairs h (n + 1) = h + collisionPairs (h + 1) n := by
  simp only [collisionPairs, Nat.choose_succ_succ, Nat.choose_one_right]
  ring

theorem collision_pairs_formula (h n : ℕ) :
    collisionPairs h n = n * h + n * (n - 1) / 2 := by
  rw [collisionPairs, Nat.choose_two_right]

theorem uniform_seen_mass (seen : Finset K) :
    (∑' key, (PMF.uniformOfFintype K) key * (if key ∈ seen then 1 else 0)) =
      (seen.card : ℝ≥0∞) / Fintype.card K := by
  simp only [PMF.uniformOfFintype_apply, tsum_fintype]
  simp [mul_ite, Finset.sum_ite_mem, div_eq_mul_inv]

/-- Bound on the actual detector result, rather than an assumed bad-event mass. -/
theorem key_collision_bound (seen : Finset K) (n : ℕ) :
    keyCollision seen n true ≤
      (collisionPairs seen.card n : ℝ≥0∞) / Fintype.card K := by
  induction n generalizing seen with
  | zero => simp [keyCollision, collision_pairs_zero]
  | succ n ih =>
    rw [keyCollision, PMF.bind_apply]
    calc
      _ ≤ ∑' key, (PMF.uniformOfFintype K) key *
          ((if key ∈ seen then 1 else 0) +
            (collisionPairs (seen.card + 1) n : ℝ≥0∞) / Fintype.card K) := by
        apply ENNReal.tsum_le_tsum
        intro key
        apply mul_le_mul_right
        by_cases hk : key ∈ seen
        · simp only [hk, ↓reduceIte, PMF.pure_apply_self]
          exact le_add_right le_rfl
        · simpa [hk, Finset.card_insert_of_notMem hk] using ih (insert key seen)
      _ = (seen.card : ℝ≥0∞) / Fintype.card K +
          (collisionPairs (seen.card + 1) n : ℝ≥0∞) / Fintype.card K := by
        simp_rw [mul_add]
        rw [ENNReal.tsum_add, uniform_seen_mass, ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]
      _ = _ := by rw [collision_pairs_step, Nat.cast_add, ENNReal.add_div]

theorem key_collision_one (seen : Finset K) :
    keyCollision seen 1 true = (seen.card : ℝ≥0∞) / Fintype.card K := by
  rw [keyCollision, PMF.bind_apply]
  convert uniform_seen_mass seen using 1
  apply tsum_congr
  intro key
  by_cases hk : key ∈ seen <;> simp [hk, keyCollision]

theorem key_collision_empty_one : keyCollision (∅ : Finset K) 1 true = 0 := by
  rw [key_collision_one]; simp

theorem key_collision_all_one : keyCollision (Finset.univ : Finset K) 1 true = 1 := by
  simp [keyCollision]

theorem key_collision_bool_two : keyCollision (∅ : Finset Bool) 2 true =
    (2 : ℝ≥0∞)⁻¹ := by
  norm_num [keyCollision, PMF.bind_apply, PMF.pure_apply, tsum_fintype]
  rw [← add_mul, ← two_mul, ENNReal.mul_inv_cancel (by norm_num) (by simp), one_mul]

theorem key_collision_bound_real (seen : Finset K) (n : ℕ) :
    (keyCollision seen n true).toReal ≤
      (collisionPairs seen.card n : ℝ) / Fintype.card K := by
  have h := ENNReal.toReal_mono (show
      (collisionPairs seen.card n : ℝ≥0∞) / Fintype.card K ≠ ⊤ by
        exact ENNReal.div_ne_top (by simp) (by simp)) (key_collision_bound seen n)
  simpa using h

theorem randomizer_key_collision_bound (seen : Finset (Fin (2 ^ 128))) (n : ℕ) :
    (keyCollision seen n true).toReal ≤
      (collisionPairs seen.card n : ℝ) / (2 : ℝ) ^ 128 := by
  simpa only [Fintype.card_fin, Nat.cast_pow, Nat.cast_ofNat] using
    key_collision_bound_real seen n

end
end C10Probability

import C10Probability.Projections
import Mathlib.Algebra.BigOperators.Fin
import Mathlib.Data.Fintype.BigOperators

/-! Finite words with an exact integer digit sum. Integer residuals retain
negative targets instead of silently clamping subtraction to zero. -/
namespace C10Probability
section

abbrev SumWords (base digits : ℕ) (target : ℤ) :=
  {word : Fin digits → Fin base // ∑ i, ((word i).val : ℤ) = target}

def wordCount (base digits : ℕ) (target : ℤ) : ℕ :=
  Fintype.card (SumWords base digits target)

/-- Split off the actual first digit, preserving the exact residual sum. -/
def sumWordsSuccEquiv (base digits : ℕ) (target : ℤ) :
    SumWords base (digits + 1) target ≃
      Σ digit : Fin base, SumWords base digits (target - digit.val) where
  toFun word := ⟨word.1 0, ⟨Fin.tail word.1, by
    have h := word.2
    rw [Fin.sum_univ_succ] at h
    dsimp [Fin.tail]
    omega⟩⟩
  invFun pair := ⟨Fin.cons pair.1 pair.2.1, by
    rw [Fin.sum_univ_succ]
    simp only [Fin.cons_zero, Fin.cons_succ]
    have h := pair.2.2
    omega⟩
  left_inv word := by
    apply Subtype.ext
    exact Fin.cons_self_tail _
  right_inv pair := by
    rcases pair with ⟨digit, word, h⟩
    simp
    rfl

theorem word_count_succ (base digits : ℕ) (target : ℤ) :
    wordCount base (digits + 1) target =
      ∑ digit : Fin base, wordCount base digits (target - digit.val) := by
  unfold wordCount
  rw [Fintype.card_congr (sumWordsSuccEquiv base digits target), Fintype.card_sigma]

theorem word_count_zero (base : ℕ) (target : ℤ) :
    wordCount base 0 target = if target = 0 then 1 else 0 := by
  by_cases h : target = 0
  · simp [wordCount, SumWords, h]
  · simp [wordCount, SumWords, h, eq_comm]

theorem word_count_negative (base digits : ℕ) (target : ℤ) (h : target < 0) :
    wordCount base digits target = 0 := by
  apply Fintype.card_eq_zero_iff.mpr
  refine ⟨fun word => ?_⟩
  have hn : 0 ≤ ∑ i, ((word.1 i).val : ℤ) :=
    Finset.sum_nonneg fun i _ => Int.natCast_nonneg _
  have hs := word.2
  omega

end
end C10Probability

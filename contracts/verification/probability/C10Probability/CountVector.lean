import C10Probability.WordCount

/-! A descending-target finite vector for the exact word count. The final
entry represents target zero; absent entries represent negative targets. -/
namespace C10Probability
section

def countStep (base : ℕ) : List ℕ → List ℕ
  | [] => []
  | value :: rest => ((value :: rest).take base).sum :: countStep base rest

def countRun (base : ℕ) : ℕ → List ℕ → List ℕ
  | 0, row => row
  | digits + 1, row => countRun base digits (countStep base row)

def countBasis (target : ℕ) : List ℕ := List.replicate target 0 ++ [1]

def CountRep (base digits target : ℕ) (row : List ℕ) : Prop :=
  ∀ i : ℕ, row[i]?.getD 0 = wordCount base digits ((target : ℤ) - i)

theorem count_take_sum (base : ℕ) (row : List ℕ) :
    (row.take base).sum = ∑ digit : Fin base, row[digit.val]?.getD 0 := by
  induction base generalizing row with
  | zero => simp
  | succ base ih =>
    cases row with
    | nil => simp
    | cons value rest =>
      simp only [List.take_succ_cons, List.sum_cons, Fin.sum_univ_succ,
        Fin.val_zero, Fin.val_succ, List.getElem?_cons_zero, Option.getD_some,
        List.getElem?_cons_succ]
      rw [ih]

theorem count_step_lookup (base i : ℕ) (row : List ℕ) :
    (countStep base row)[i]?.getD 0 =
      ∑ digit : Fin base, row[i + digit.val]?.getD 0 := by
  have h : (countStep base row)[i]?.getD 0 = ((row.drop i).take base).sum := by
    induction row generalizing i with
    | nil => simp [countStep]
    | cons value rest ih =>
      cases i with
      | zero => simp [countStep]
      | succ i => simpa only [countStep, List.getElem?_cons_succ, List.drop_succ_cons] using ih i
  rw [h, count_take_sum]
  simp only [List.getElem?_drop]

theorem count_step_rep (base digits target : ℕ) (row : List ℕ)
    (h : CountRep base digits target row) :
    CountRep base (digits + 1) target (countStep base row) := by
  intro i
  rw [count_step_lookup, word_count_succ]
  apply Finset.sum_congr rfl
  intro digit _
  rw [h]
  congr 1
  push_cast
  omega

theorem count_basis_rep (base target : ℕ) : CountRep base 0 target (countBasis target) := by
  intro i
  rw [word_count_zero]
  unfold countBasis
  by_cases hi : i < target
  · rw [List.getElem?_append_left (by simpa using hi), List.getElem?_replicate_of_lt hi]
    simp only [Option.getD_some]
    rw [if_neg (by omega)]
  · rw [List.getElem?_append_right (by simpa using Nat.le_of_not_gt hi)]
    simp only [List.length_replicate]
    by_cases heq : i = target
    · subst i
      simp
    · have hd : 0 < i - target := by omega
      have hz : ([1] : List ℕ)[i - target]? = none := by
        apply List.getElem?_eq_none_iff.mpr
        simp only [List.length_singleton]
        omega
      rw [hz]
      simp only [Option.getD_none]
      rw [if_neg (by omega)]

theorem count_run_rep (base steps digits target : ℕ) (row : List ℕ)
    (h : CountRep base digits target row) :
    CountRep base (digits + steps) target (countRun base steps row) := by
  induction steps generalizing digits row with
  | zero => simpa only [countRun, Nat.add_zero] using h
  | succ steps ih =>
    simpa only [countRun, Nat.add_assoc, Nat.add_comm 1 steps] using
      ih (digits + 1) (countStep base row) (count_step_rep base digits target row h)

theorem word_count_vector (base digits target : ℕ) :
    wordCount base digits target = (countRun base digits (countBasis target))[0]?.getD 0 := by
  have h := count_run_rep base digits 0 target (countBasis target) (count_basis_rep base target)
  simpa only [Nat.zero_add, Nat.cast_zero, sub_zero] using (h 0).symm

end
end C10Probability

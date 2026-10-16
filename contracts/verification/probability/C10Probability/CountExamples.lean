import C10Probability.WotsCount

/-! Small counts use direct finite-word enumeration independently of the vector
recurrence. They exercise digits, bounds and signed targets, including base zero. -/
namespace C10Probability
section

theorem count_empty_zero : wordCount 3 0 0 = 1 := by decide

theorem count_empty_nonzero : wordCount 3 0 1 = 0 := by decide

theorem count_empty_alphabet_empty_word : wordCount 0 0 0 = 1 := by decide

theorem count_empty_alphabet_nonempty_word : wordCount 0 1 0 = 0 := by decide

theorem count_negative_target : wordCount 3 2 (-1) = 0 := by decide

theorem count_zero_target : wordCount 3 4 0 = 1 := by decide

theorem count_small_middle : wordCount 3 4 4 = 19 := by decide

theorem count_small_maximum : wordCount 3 4 8 = 1 := by decide

theorem count_small_above_maximum : wordCount 3 4 9 = 0 := by decide

theorem count_two_base_eight : wordCount 8 2 7 = 8 := by decide

theorem count_vector_small : countRun 3 4 (countBasis 8) = [1, 4, 10, 16, 19, 16, 10, 4, 1] :=
  by decide

theorem count_vector_zero_steps : countRun 3 0 (countBasis 2) = [0, 0, 1] := by decide

theorem count_vector_empty_alphabet : countRun 0 1 (countBasis 2) = [0, 0, 0] := by decide

theorem count_step_window : countStep 2 [2, 3, 5] = [5, 8, 5] := by decide

theorem count_step_empty : countStep 8 [] = [] := by decide

theorem count_basis_zero : countBasis 0 = [1] := by decide

theorem count_lookup_beyond : (countRun 3 4 (countBasis 8))[9]?.getD 0 = 0 := by decide

end
end C10Probability

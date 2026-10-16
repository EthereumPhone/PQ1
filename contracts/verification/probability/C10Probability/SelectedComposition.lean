import C10Probability.SelectedBudget

/-! Compose selected-call budgets without changing the full interpreter. -/
namespace C10Probability
noncomputable section

variable {K α R T : Type*}

theorem selectedBudget_reserve (select : K → Bool) (extra : ℕ) {n : ℕ}
    (program : QueryProgram K α R n) (q : ℕ) :
    SelectedBudget select (reserveProgram extra program) q =
      SelectedBudget select program q := by
  induction program generalizing q with
  | done value => rfl
  | query key next ih =>
    cases hs : select key <;>
      simp only [reserveProgram, SelectedBudget, hs, Bool.false_eq_true, ↓reduceIte, ih]

theorem selectedBudget_bind (select : K → Bool) {n m : ℕ}
    (program : QueryProgram K α R n) (after : R → QueryProgram K α T m) (q r : ℕ)
    (first : SelectedBudget select program q)
    (later : ∀ value, SelectedBudget select (after value) r) :
    SelectedBudget select (bindProgram program after) (q + r) := by
  induction program generalizing q with
  | @done n value =>
    simpa only [bindProgram, selectedBudget_cast, selectedBudget_reserve] using
      selectedBudget_mono select (after value) (show r ≤ q + r by omega) (later value)
  | query key next ih =>
    cases hs : select key <;>
      simp only [bindProgram, SelectedBudget, hs, Bool.false_eq_true, ↓reduceIte] at first ⊢
    · exact fun reply => ih reply q (first reply)
    · refine ⟨by omega, fun reply => ?_⟩
      have h := ih reply (q - 1) (first.2 reply)
      simpa only [show q - 1 + r = q + r - 1 by omega] using h

end
end C10Probability

import C10Probability.ChainCollection
import C10Probability.SelectedComposition

/-! Ordered, stateful query folds. The index is the actual sum of component
bounds, and the direct loop threads the complete memo table through every call. -/
namespace C10Probability
noncomputable section

variable {I K L P α S T : Type*}

def stateFoldProgram (cost : I → ℕ)
    (step : (i : I) → S → QueryProgram K α S (cost i)) :
    (indices : List I) → S → QueryProgram K α S (collectionSteps cost indices)
  | [], state => .done state
  | i :: rest, state => castProgram (by simp [collectionSteps, Nat.add_comm])
      (bindProgram (step i state) (stateFoldProgram cost step rest))

def stateFoldLoop [DecidableEq K] (p : PMF α) (cost : I → ℕ)
    (step : (i : I) → S → QueryProgram K α S (cost i)) :
    List I → S → Memo K α → PMF (S × Memo K α)
  | [], state, table => PMF.pure (state, table)
  | i :: rest, state, table => (evalProgram p (step i state) table).bind
      (fun out => stateFoldLoop p cost step rest out.1 out.2)

theorem evalProgram_stateFold [DecidableEq K] (p : PMF α) (cost : I → ℕ)
    (step : (i : I) → S → QueryProgram K α S (cost i))
    (indices : List I) (state : S) (table : Memo K α) :
    evalProgram p (stateFoldProgram cost step indices state) table =
      stateFoldLoop p cost step indices state table := by
  induction indices generalizing state table with
  | nil => rfl
  | cons i rest ih =>
    simp only [stateFoldProgram, evalProgram_cast, evalProgram_bind, ih, stateFoldLoop]

theorem mapProgram_mapReturn (encode : K → L) (f : S → T) {n : ℕ}
    (program : QueryProgram K α S n) :
    mapProgram encode (mapReturnProgram f program) =
      mapReturnProgram f (mapProgram encode program) := by
  induction program with
  | done value => rfl
  | query key next ih =>
    simp only [mapProgram, mapReturnProgram]
    congr 1
    funext reply
    exact ih reply

theorem publicBudget_mapReturn (f : S → T) {n : ℕ}
    (program : QueryProgram (Sum K P) α S n) (q : ℕ) :
    PublicBudget (mapReturnProgram f program) q = PublicBudget program q := by
  induction program generalizing q with
  | done value => rfl
  | query key next ih => cases key <;> simp only [mapReturnProgram, PublicBudget, ih]

theorem mapProgram_stateFold (encode : K → L) (cost : I → ℕ)
    (step : (i : I) → S → QueryProgram K α S (cost i))
    (indices : List I) (state : S) :
    mapProgram encode (stateFoldProgram cost step indices state) =
      stateFoldProgram cost (fun i s => mapProgram encode (step i s)) indices state := by
  induction indices generalizing state with
  | nil => rfl
  | cons i rest ih =>
    simp only [stateFoldProgram, mapProgram_cast, mapProgram_bind, ih]

theorem publicBudget_stateFold (cost charge : I → ℕ)
    (step : (i : I) → S → QueryProgram (Sum K P) α S (cost i))
    (budget : ∀ i state, PublicBudget (step i state) (charge i))
    (indices : List I) (state : S) :
    PublicBudget (stateFoldProgram cost step indices state) (collectionSteps charge indices) := by
  induction indices generalizing state with
  | nil => trivial
  | cons i rest ih =>
    rw [stateFoldProgram, publicBudget_cast]
    simpa only [collectionSteps, List.map_cons, List.sum_cons] using
      publicBudget_bind (step i state) (stateFoldProgram cost step rest)
        (charge i) (collectionSteps charge rest) (budget i state) ih

theorem selectedBudget_stateFold (select : K → Bool) (cost charge : I → ℕ)
    (step : (i : I) → S → QueryProgram K α S (cost i))
    (budget : ∀ i state, SelectedBudget select (step i state) (charge i))
    (indices : List I) (state : S) :
    SelectedBudget select (stateFoldProgram cost step indices state)
      (collectionSteps charge indices) := by
  induction indices generalizing state with
  | nil => trivial
  | cons i rest ih =>
    rw [stateFoldProgram, selectedBudget_cast]
    simpa only [collectionSteps, List.map_cons, List.sum_cons] using
      selectedBudget_bind select (step i state) (stateFoldProgram cost step rest)
        (charge i) (collectionSteps charge rest) (budget i state) ih

theorem collectionSteps_perm (cost : I → ℕ) {first second : List I}
    (order : first.Perm second) : collectionSteps cost first = collectionSteps cost second := by
  exact (order.map cost).sum_eq

end
end C10Probability

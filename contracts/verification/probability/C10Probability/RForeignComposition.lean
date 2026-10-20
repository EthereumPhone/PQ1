import C10Probability.RForeignBudget
import C10Probability.TreeRun

/-! Zero selected-call budgets compose through the existing adaptive chain,
state-fold and stack-tree compilers. No new execution semantics are introduced. -/
namespace C10Probability
noncomputable section

variable {I K α N R S T : Type*}

theorem selected_zero_bind (select : K → Bool) {n m : ℕ}
    (program : QueryProgram K α R n) (after : R → QueryProgram K α T m)
    (first : SelectedBudget select program 0)
    (later : ∀ value, SelectedBudget select (after value) 0) :
    SelectedBudget select (bindProgram program after) 0 := by
  exact selectedBudget_bind select program after 0 0 first later

theorem selected_zero_query (select : K → Bool) {n : ℕ} (key : K)
    (next : α → QueryProgram K α R n) (unselected : select key = false)
    (later : ∀ reply, SelectedBudget select (next reply) 0) :
    SelectedBudget select (.query key next) 0 := by
  simpa only [SelectedBudget, unselected, Bool.false_eq_true, ↓reduceIte] using later

theorem selected_zero_chain (select : K → Bool) (input : ℕ → N → K)
    (project : α → N) (unselected : ∀ pos current, select (input pos current) = false)
    (start steps : ℕ) (current : N) :
    SelectedBudget select (chainProgram input project start steps current) 0 := by
  induction steps generalizing start current with
  | zero => trivial
  | succ steps ih =>
    exact selected_zero_query select _ _ (unselected start current)
      (fun reply => ih (start + 1) (project reply))

theorem selected_zero_stateFold (select : K → Bool) (cost : I → ℕ)
    (step : (i : I) → S → QueryProgram K α S (cost i))
    (budget : ∀ i state, SelectedBudget select (step i state) 0)
    (indices : List I) (state : S) :
    SelectedBudget select (stateFoldProgram cost step indices state) 0 := by
  simpa [collectionSteps] using
    selectedBudget_stateFold select cost (fun _ => 0) step budget indices state

theorem selected_castTreeProgram (select : K → Bool)
    {first second : List ℕ} {n m : ℕ} (shapeEq : first = second) (costEq : n = m)
    (program : QueryProgram K α (ShapeStack N first × S) n) (q : ℕ) :
    SelectedBudget select (castTreeProgram shapeEq costEq program) q =
      SelectedBudget select program q := by
  subst second
  subst m
  rfl

theorem selected_zero_merge (select : K → Bool)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (unselected : ∀ kp h left right, select (input kp h left right) = false)
    (remember : ℕ → ℕ → N → N → S → S) (kp : ℕ)
    (shape : List ℕ) (height : ℕ) (stack : ShapeStack N shape)
    (current : N) (state : S) :
    SelectedBudget select
      (mergeProgram input project remember kp shape height stack current state) 0 := by
  induction shape generalizing height current state with
  | nil => trivial
  | cons level rest ih =>
    by_cases same : level = height
    · rw [mergeProgram, dif_pos same, selected_castTreeProgram]
      exact selected_zero_query select _ _ (unselected _ _ _ _)
        (fun reply => ih (height + 1) stack.2 (project reply)
          (remember kp height stack.1 current state))
    · rw [mergeProgram, dif_neg same, selected_castTreeProgram]
      trivial

theorem selected_zero_tree (select : K → Bool) (leafCost : ℕ)
    (leaf : ℕ → QueryProgram K α N leafCost)
    (leafBudget : ∀ kp, SelectedBudget select (leaf kp) 0)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (unselected : ∀ kp h left right, select (input kp h left right) = false)
    (remember : ℕ → ℕ → N → N → S → S)
    (n start : ℕ) (shape : List ℕ) (stack : ShapeStack N shape) (state : S) :
    SelectedBudget select
      (treeProgram leafCost leaf input project remember n start shape stack state) 0 := by
  induction n generalizing start shape state with
  | zero => trivial
  | succ n ih =>
    rw [treeProgram, selectedBudget_cast]
    apply selected_zero_bind select _ _ (leafBudget start)
    intro current
    apply selected_zero_bind select _ _
      (selected_zero_merge select input project unselected remember start shape 0 stack current state)
    intro merged
    exact ih (start + 1) (nextShape shape) merged.1 merged.2

end
end C10Probability

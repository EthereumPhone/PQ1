import C10Probability.OpeningTree

/-! Structural tree guarantees require leaf facts only over the actual loop
range. The same full stack, remembered state and adaptive merge calls are kept;
no out-of-range leaf or truncation assumption is used. -/
namespace C10Probability
noncomputable section
variable {K P α H N S : Type*}

theorem opening_tree_sealed_bounded (target : K) (leafCost limit : ℕ)
    (leaf : ℕ → OpeningProgram K P α H N leafCost)
    (leaves : ∀ kp, kp < limit → OpeningSealed target (leaf kp))
    (input : ℕ → ℕ → N → N → K)
    (different : ∀ kp height left right, input kp height left right ≠ target)
    (project : α → N) (remember : ℕ → ℕ → N → N → S → S)
    (n start : ℕ) (bound : start + n ≤ limit) (shape : List ℕ)
    (stack : ShapeStack N shape) (state : S) :
    OpeningSealed target
      (openingTreeProgram leafCost leaf input project remember n start shape stack state) := by
  induction n generalizing start shape state with
  | zero => trivial
  | succ n ih =>
    rw [openingTreeProgram, opening_sealed_cast]
    apply opening_sealed_bind target _ _ (leaves start (by omega))
    intro current
    apply opening_sealed_bind target _ _
      (opening_merge_sealed target input different project remember start shape 0 stack current state)
    intro merged
    exact ih (start + 1) (by omega) (nextShape shape) merged.1 merged.2

theorem opening_tree_budget_bounded (select : Sum K P → Bool) (leafCost leafCharge limit : ℕ)
    (leaf : ℕ → OpeningProgram K P α H N leafCost)
    (leaves : ∀ kp, kp < limit → SelectedBudget select (redactOpening (leaf kp)) leafCharge)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S)
    (n start : ℕ) (bound : start + n ≤ limit) (shape : List ℕ)
    (stack : ShapeStack N shape) (state : S) :
    SelectedBudget select
      (redactOpening (openingTreeProgram leafCost leaf input project remember n start shape stack state))
      (treeCalls leafCharge n shape) := by
  induction n generalizing start shape state with
  | zero => trivial
  | succ n ih =>
    rw [openingTreeProgram, redact_opening_cast, selectedBudget_cast, tree_calls_step]
    have budget := opening_selected_bind select (leaf start) _ leafCharge
      ((mergeShape 0 shape).calls + treeCalls leafCharge n (nextShape shape))
      (leaves start (by omega))
      (fun current => opening_selected_bind select
        (liftOpening (P := P) (H := H)
          (mergeProgram input project remember start shape 0 stack current state))
        _ (mergeShape 0 shape).calls
        (treeCalls leafCharge n (nextShape shape)) (selectedBudget_total _ _)
        (fun merged => ih (start + 1) (by omega) (nextShape shape) merged.1 merged.2))
    simpa only [Nat.add_comm, Nat.add_left_comm, Nat.add_assoc] using budget

end
end C10Probability

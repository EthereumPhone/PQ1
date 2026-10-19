import C10Probability.OpeningSealed
import C10Probability.TreeRun

/-! The existing stack-shape schedule lifts compositionally to hidden leaf
commitments. Merges keep the original adaptive query program and remembered
authentication state; no equality between built and recovered roots is assumed. -/
namespace C10Probability
noncomputable section
variable {K P α H N S U : Type*}

def openingTreeProgram (leafCost : ℕ) (leaf : ℕ → OpeningProgram K P α H N leafCost)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S) :
    (n start : ℕ) → (shape : List ℕ) → ShapeStack N shape → S →
      OpeningProgram K P α H (ShapeStack N (runShape n shape) × S) (treeCalls leafCost n shape)
  | 0, _, _, stack, state => .done (stack, state)
  | n + 1, start, shape, stack, state =>
      castOpening (tree_calls_step leafCost n shape).symm
        (bindOpening (leaf start) (fun current =>
          bindOpening (liftOpening (mergeProgram input project remember start shape 0 stack current state))
            (fun merged => openingTreeProgram leafCost leaf input project remember n (start + 1)
              (nextShape shape) merged.1 merged.2)))

theorem opening_tree_refines [DecidableEq K] (p : PMF α) (encode : U → P → K)
    (hiddenProject : α → U) (target : K) (secret : α) (leafCost : ℕ)
    (leaf : ℕ → OpeningProgram K P α α N leafCost)
    (ordinary : ℕ → QueryProgram K α N leafCost)
    (leaves : ∀ kp, OpeningRefines p encode hiddenProject target secret id (leaf kp) (ordinary kp))
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S)
    (n start : ℕ) (shape : List ℕ) (stack : ShapeStack N shape) (state : S) :
    OpeningRefines p encode hiddenProject target secret id
      (openingTreeProgram leafCost leaf input project remember n start shape stack state)
      (treeProgram leafCost ordinary input project remember n start shape stack state) := by
  induction n generalizing start shape state with
  | zero => exact opening_refines_done p encode hiddenProject target secret id _ _ _
  | succ n ih =>
    rw [openingTreeProgram, treeProgram]
    apply opening_refines_cast
    apply opening_refines_bind p encode hiddenProject target secret id id _ _ _ _ (leaves start)
    intro current
    apply opening_refines_bind p encode hiddenProject target secret id id _ _ _ _
      (opening_refines_lift p encode hiddenProject target secret _)
    intro merged
    exact ih (start + 1) (nextShape shape) merged.1 merged.2

theorem opening_merge_sealed (target : K) (input : ℕ → ℕ → N → N → K)
    (different : ∀ kp height left right, input kp height left right ≠ target)
    (project : α → N) (remember : ℕ → ℕ → N → N → S → S) (kp : ℕ)
    (shape : List ℕ) (height : ℕ) (stack : ShapeStack N shape) (current : N) (state : S) :
    OpeningSealed target (liftOpening (P := P) (H := H)
      (mergeProgram input project remember kp shape height stack current state)) := by
  have sealed := opening_sealed_lift_mapped (P := P) (H := H) target
    (fun args : ℕ × ℕ × N × N => input args.1 args.2.1 args.2.2.1 args.2.2.2)
    (fun args => different args.1 args.2.1 args.2.2.1 args.2.2.2)
    (mergeProgram (fun kp height left right => (kp, height, left, right)) project remember
      kp shape height stack current state)
  simpa only [merge_program_map] using sealed

theorem opening_tree_sealed (target : K) (leafCost : ℕ)
    (leaf : ℕ → OpeningProgram K P α H N leafCost)
    (leaves : ∀ kp, OpeningSealed target (leaf kp)) (input : ℕ → ℕ → N → N → K)
    (different : ∀ kp height left right, input kp height left right ≠ target)
    (project : α → N) (remember : ℕ → ℕ → N → N → S → S)
    (n start : ℕ) (shape : List ℕ) (stack : ShapeStack N shape) (state : S) :
    OpeningSealed target
      (openingTreeProgram leafCost leaf input project remember n start shape stack state) := by
  induction n generalizing start shape state with
  | zero => trivial
  | succ n ih =>
    rw [openingTreeProgram, opening_sealed_cast]
    apply opening_sealed_bind target _ _ (leaves start)
    intro current
    apply opening_sealed_bind target _ _
      (opening_merge_sealed target input different project remember start shape 0 stack current state)
    intro merged
    exact ih (start + 1) (nextShape shape) merged.1 merged.2

theorem opening_tree_budget (select : Sum K P → Bool) (leafCost leafCharge : ℕ)
    (leaf : ℕ → OpeningProgram K P α H N leafCost)
    (leaves : ∀ kp, SelectedBudget select (redactOpening (leaf kp)) leafCharge)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S)
    (n start : ℕ) (shape : List ℕ) (stack : ShapeStack N shape) (state : S) :
    SelectedBudget select
      (redactOpening (openingTreeProgram leafCost leaf input project remember n start shape stack state))
      (treeCalls leafCharge n shape) := by
  induction n generalizing start shape state with
  | zero => trivial
  | succ n ih =>
    rw [openingTreeProgram, redact_opening_cast, selectedBudget_cast, tree_calls_step]
    have bound := opening_selected_bind select (leaf start) _ leafCharge
      ((mergeShape 0 shape).calls + treeCalls leafCharge n (nextShape shape)) (leaves start)
      (fun current => opening_selected_bind select
        (liftOpening (P := P) (H := H)
          (mergeProgram input project remember start shape 0 stack current state))
        _ (mergeShape 0 shape).calls
        (treeCalls leafCharge n (nextShape shape)) (selectedBudget_total _ _)
        (fun merged => ih (start + 1) (nextShape shape) merged.1 merged.2))
    simpa only [Nat.add_comm, Nat.add_left_comm, Nat.add_assoc] using bound

end
end C10Probability

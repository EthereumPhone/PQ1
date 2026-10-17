import C10Probability.TreeMerge

/-! Compile the actual leaf-by-leaf stack loop. The cost index follows the
proved stack-height schedule, not a supplied number of merges. -/
namespace C10Probability
noncomputable section

variable {K L P α N S : Type*}

def treeProgram (leafCost : ℕ) (leaf : ℕ → QueryProgram K α N leafCost)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S) :
    (n start : ℕ) → (shape : List ℕ) → ShapeStack N shape → S →
      QueryProgram K α (ShapeStack N (runShape n shape) × S) (treeCalls leafCost n shape)
  | 0, _, _, stack, state => .done (stack, state)
  | n + 1, start, shape, stack, state =>
      castProgram (tree_calls_step leafCost n shape).symm
        (bindProgram (leaf start) (fun current =>
          bindProgram (mergeProgram input project remember start shape 0 stack current state)
            (fun merged => treeProgram leafCost leaf input project remember n (start + 1)
              (nextShape shape) merged.1 merged.2)))

def treeLoop [DecidableEq K] (p : PMF α)
    (leaf : ℕ → Memo K α → PMF (N × Memo K α))
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S) :
    ℕ → ℕ → List (N × ℕ) → S → Memo K α → PMF ((List (N × ℕ) × S) × Memo K α)
  | 0, _, stack, state, table => PMF.pure ((stack, state), table)
  | n + 1, start, stack, state, table =>
      (leaf start table).bind (fun current =>
        (mergeLoop p input project remember start stack 0 current.1 state current.2).bind
          (fun merged => treeLoop p leaf input project remember n (start + 1)
            merged.1.1 merged.1.2 merged.2))

theorem tree_program_eval [DecidableEq K] (p : PMF α)
    (leafCost : ℕ) (leaf : ℕ → QueryProgram K α N leafCost)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S)
    (n start : ℕ) (shape : List ℕ) (stack : ShapeStack N shape) (state : S)
    (table : Memo K α) :
    (evalProgram p (treeProgram leafCost leaf input project remember n start shape stack state)
      table).map (eraseTreeOutput (runShape n shape)) =
      treeLoop p (fun kp memo => evalProgram p (leaf kp) memo) input project remember
        n start (eraseStack shape stack) state table := by
  induction n generalizing start shape state table with
  | zero => simp [treeProgram, evalProgram, PMF.pure_map, treeLoop,
      eraseTreeOutput, eraseTreeState, runShape]
  | succ n ih =>
    simp only [treeProgram, evalProgram_cast, evalProgram_bind, PMF.map_bind, runShape,
      ih, treeLoop]
    congr 1
    funext current
    rw [← merge_program_eval p input project remember start shape 0 stack current.1 state current.2,
      PMF.bind_map]
    rfl

theorem tree_program_map (encode : K → L)
    (leafCost : ℕ) (leaf : ℕ → QueryProgram K α N leafCost)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S)
    (n start : ℕ) (shape : List ℕ) (stack : ShapeStack N shape) (state : S) :
    mapProgram encode (treeProgram leafCost leaf input project remember n start shape stack state) =
      treeProgram leafCost (fun kp => mapProgram encode (leaf kp))
        (fun k h l r => encode (input k h l r)) project remember n start shape stack state := by
  induction n generalizing start shape state with
  | zero => rfl
  | succ n ih =>
    simp only [treeProgram, mapProgram_cast, mapProgram_bind, merge_program_map]
    congr 1
    congr 1
    funext current
    congr 1
    funext merged
    exact ih (start + 1) (nextShape shape) merged.1 merged.2

theorem tree_program_public (leafCost leafCharge : ℕ)
    (leaf : ℕ → QueryProgram (Sum K P) α N leafCost)
    (leafBudget : ∀ kp, PublicBudget (leaf kp) leafCharge)
    (input : ℕ → ℕ → N → N → Sum K P) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S)
    (n start : ℕ) (shape : List ℕ) (stack : ShapeStack N shape) (state : S) :
    PublicBudget (treeProgram leafCost leaf input project remember n start shape stack state)
      (treeCalls leafCharge n shape) := by
  induction n generalizing start shape state with
  | zero => trivial
  | succ n ih =>
    rw [treeProgram, publicBudget_cast, tree_calls_step]
    have hb := publicBudget_bind (leaf start) _ leafCharge
      ((mergeShape 0 shape).calls + treeCalls leafCharge n (nextShape shape))
      (leafBudget start) (fun current =>
        publicBudget_bind (mergeProgram input project remember start shape 0 stack current state)
          _ (mergeShape 0 shape).calls (treeCalls leafCharge n (nextShape shape))
          (publicBudget_total _) (fun merged => ih (start + 1) (nextShape shape) merged.1 merged.2))
    simpa only [Nat.add_comm, Nat.add_left_comm, Nat.add_assoc] using hb

end
end C10Probability

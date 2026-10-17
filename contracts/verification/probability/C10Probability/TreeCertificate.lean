import C10Probability.TreeReplay

/-! A certificate contains actual leaf replays and parent lookups. The right
edge is exclusive, so the empty initial forest needs no fictitious negative
index. The certificate is derived from the existing stack loop. -/
namespace C10Probability
noncomputable section

variable {K α N S : Type*}

inductive RecordedTreeNode (table : Memo K α) (leaf : ℕ → Option N)
    (input : ℕ → ℕ → N → N → K) (project : α → N) : ℕ → ℕ → N → Prop
  | leaf (kp : ℕ) (value : N) (recorded : leaf kp = some value) :
      RecordedTreeNode table leaf input project 0 (kp + 1) value
  | pair (height edge : ℕ) (left right : N) (reply : α)
      (left_recorded : RecordedTreeNode table leaf input project height (edge - 2 ^ height) left)
      (right_recorded : RecordedTreeNode table leaf input project height edge right)
      (recorded : table (input (edge - 1) height left right) = some reply) :
      RecordedTreeNode table leaf input project (height + 1) edge (project reply)

def RecordedForest (table : Memo K α) (leaf : ℕ → Option N)
    (input : ℕ → ℕ → N → N → K) (project : α → N) : ℕ → List (N × ℕ) → Prop
  | _, [] => True
  | edge, (root, height) :: rest =>
      RecordedTreeNode table leaf input project height edge root ∧
        RecordedForest table leaf input project (edge - 2 ^ height) rest

theorem recorded_tree_node_edge (table : Memo K α) (leaf : ℕ → Option N)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    {height edge : ℕ} {root : N}
    (recorded : RecordedTreeNode table leaf input project height edge root) :
    2 ^ height ≤ edge := by
  induction recorded with
  | leaf kp value h => simp
  | pair height edge left right reply hl hr hd ihl ihr =>
    rw [pow_succ]
    have hp : 0 < 2 ^ height := pow_pos (by decide) _
    omega

theorem recorded_tree_node_extends (before after : Memo K α)
    (leaf leaf' : ℕ → Option N) (input : ℕ → ℕ → N → N → K) (project : α → N)
    (extension : MemoExtends before after)
    (leaves : ∀ kp value, leaf kp = some value → leaf' kp = some value)
    {height edge : ℕ} {root : N}
    (recorded : RecordedTreeNode before leaf input project height edge root) :
    RecordedTreeNode after leaf' input project height edge root := by
  induction recorded with
  | leaf kp value h => exact .leaf kp value (leaves kp value h)
  | pair height edge left right reply hl hr hd ihl ihr =>
      exact .pair height edge left right reply ihl ihr (extension _ _ hd)

theorem recorded_forest_extends (before after : Memo K α)
    (leaf leaf' : ℕ → Option N) (input : ℕ → ℕ → N → N → K) (project : α → N)
    (extension : MemoExtends before after)
    (leaves : ∀ kp value, leaf kp = some value → leaf' kp = some value)
    (edge : ℕ) (stack : List (N × ℕ))
    (recorded : RecordedForest before leaf input project edge stack) :
    RecordedForest after leaf' input project edge stack := by
  induction stack generalizing edge with
  | nil => trivial
  | cons entry rest ih =>
      exact ⟨recorded_tree_node_extends before after leaf leaf' input project
        extension leaves recorded.1, ih _ recorded.2⟩

theorem replay_merge_recorded (table : Memo K α) (leaf : ℕ → Option N)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S) (kp : ℕ)
    (stack : List (N × ℕ)) (height : ℕ) (current : N) (state : S)
    (out : List (N × ℕ) × S)
    (prior : RecordedForest table leaf input project (kp + 1 - 2 ^ height) stack)
    (node : RecordedTreeNode table leaf input project height (kp + 1) current)
    (recorded : replayMerge table input project remember kp stack height current state = some out) :
    RecordedForest table leaf input project (kp + 1) out.1 := by
  induction stack generalizing height current state out with
  | nil =>
    have he : out = ([(current, height)], state) := Option.some.inj recorded.symm
    exact he ▸ ⟨node, trivial⟩
  | cons entry rest ih =>
    obtain ⟨left, level⟩ := entry
    by_cases he : level = height
    · subst level
      simp only [replayMerge, ↓reduceIte] at recorded
      cases hd : table (input kp height left current) with
      | none => simp only [hd, Option.bind_none] at recorded; cases recorded
      | some reply =>
        simp only [hd, Option.bind_some] at recorded
        have hp : 2 ^ (height + 1) = 2 ^ height + 2 ^ height := by rw [pow_succ]; omega
        have restRecorded : RecordedForest table leaf input project (kp + 1 - 2 ^ (height + 1)) rest := by
          simpa only [hp, Nat.sub_sub] using prior.2
        have parent : RecordedTreeNode table leaf input project (height + 1) (kp + 1) (project reply) :=
          .pair height (kp + 1) left current reply prior.1 node (by simpa using hd)
        exact ih (height + 1) (project reply) (remember kp height left current state)
          out restRecorded parent recorded
    · simp only [replayMerge, he, ↓reduceIte, Option.some.injEq] at recorded
      subst out
      exact ⟨node, prior⟩

theorem replay_tree_recorded (table : Memo K α) (leaf : ℕ → Option N)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S)
    (n start : ℕ) (stack : List (N × ℕ)) (state : S) (out : List (N × ℕ) × S)
    (prior : RecordedForest table leaf input project start stack)
    (recorded : replayTree table leaf input project remember n start stack state = some out) :
    RecordedForest table leaf input project (start + n) out.1 := by
  induction n generalizing start stack state out with
  | zero =>
    have he : out = (stack, state) := Option.some.inj recorded.symm
    simpa only [he, Nat.add_zero] using prior
  | succ n ih =>
    rw [replayTree] at recorded
    cases hl : leaf start with
    | none => simp only [hl, Option.bind_none] at recorded; cases recorded
    | some current =>
      simp only [hl, Option.bind_some] at recorded
      cases hm : replayMerge table input project remember start stack 0 current state with
      | none => simp only [hm, Option.bind_none] at recorded; cases recorded
      | some merged =>
        simp only [hm, Option.bind_some] at recorded
        have mergedRecorded := replay_merge_recorded table leaf input project remember
          start stack 0 current state merged (by simpa using prior) (.leaf start current hl) hm
        simpa only [Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using
          ih (start + 1) merged.1 merged.2 out mergedRecorded recorded

theorem tree_program_recorded (table : Memo K α)
    (leafCost : ℕ) (leaf : ℕ → QueryProgram K α N leafCost)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S)
    (n start : ℕ) (shape : List ℕ) (stack : ShapeStack N shape) (state : S)
    (out : ShapeStack N (runShape n shape) × S)
    (prior : RecordedForest table (fun kp => replayProgram table (leaf kp)) input project
      start (eraseStack shape stack))
    (recorded : replayProgram table
      (treeProgram leafCost leaf input project remember n start shape stack state) = some out) :
    RecordedForest table (fun kp => replayProgram table (leaf kp)) input project
      (start + n) (eraseStack (runShape n shape) out.1) := by
  have hr := congrArg (Option.map (eraseTreeState (runShape n shape))) recorded
  rw [replay_tree_program] at hr
  exact replay_tree_recorded table _ input project remember n start _ state _ prior hr

theorem tree_execution_recorded [DecidableEq K] (p : PMF α) (table : Memo K α)
    (leafCost : ℕ) (leaf : ℕ → QueryProgram K α N leafCost)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S)
    (n start : ℕ) (shape : List ℕ) (stack : ShapeStack N shape) (state : S)
    (out : (ShapeStack N (runShape n shape) × S) × Memo K α)
    (prior : RecordedForest table (fun kp => replayProgram table (leaf kp)) input project
      start (eraseStack shape stack))
    (ho : out ∈ (evalProgram p
      (treeProgram leafCost leaf input project remember n start shape stack state) table).support) :
    RecordedForest out.2 (fun kp => replayProgram out.2 (leaf kp)) input project
      (start + n) (eraseStack (runShape n shape) out.1.1) := by
  have extension := eval_program_extends p _ table out ho
  have history := recorded_forest_extends table out.2 _ _ input project extension
    (fun kp value h => replay_program_extends (leaf kp) table out.2 value extension h)
    start _ prior
  exact tree_program_recorded out.2 leafCost leaf input project remember n start shape stack
    state out.1 history (eval_program_replay p _ table out ho)

theorem recorded_erased_root (table : Memo K α) (leaf : ℕ → Option N)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (edge height : ℕ) (shape : List ℕ) (stack : ShapeStack N shape) (fallback : N)
    (complete : shape = [height])
    (recorded : RecordedForest table leaf input project edge (eraseStack shape stack)) :
    RecordedTreeNode table leaf input project height edge
      ((eraseStack shape stack).headD (fallback, 0)).1 := by
  subst shape
  exact recorded.1

theorem replay_complete_tree_recorded (table : Memo K α)
    (leafCost : ℕ) (leaf : ℕ → QueryProgram K α N leafCost)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S)
    (n height : ℕ) (state : S) (fallback : N) (out : List (N × ℕ) × S)
    (complete : runShape n [] = [height])
    (recorded : (replayProgram table
      (treeProgram leafCost leaf input project remember n 0 [] PUnit.unit state)).map
        (eraseTreeState (runShape n [])) = some out) :
    RecordedTreeNode table (fun kp => replayProgram table (leaf kp)) input project
      height n (out.1.headD (fallback, 0)).1 := by
  cases hx : replayProgram table
      (treeProgram leafCost leaf input project remember n 0 [] PUnit.unit state) with
  | none => simp only [hx, Option.map_none] at recorded; cases recorded
  | some value =>
    simp only [hx, Option.map_some, Option.some.injEq] at recorded
    subst out
    have nodes := tree_program_recorded table leafCost leaf input project remember
      n 0 [] PUnit.unit state value trivial hx
    exact recorded_erased_root table _ input project n height _ value.1 fallback complete
      (by simpa only [Nat.zero_add] using nodes)

end
end C10Probability

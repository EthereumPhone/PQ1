import C10Probability.QueryReplay
import C10Probability.TreeRun

/-! Lookup-only execution of the existing stack builder. These equations
erase the compiler's static stack indices, preserving every leaf result,
ordered parent lookup and remembered authentication update. -/
namespace C10Probability
noncomputable section

variable {K α N S : Type*}

def replayMerge (table : Memo K α)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S) (kp : ℕ) :
    List (N × ℕ) → ℕ → N → S → Option (List (N × ℕ) × S)
  | [], height, current, state => some ([(current, height)], state)
  | (left, level) :: rest, height, current, state =>
      if level = height then
        (table (input kp height left current)).bind (fun reply =>
          replayMerge table input project remember kp rest (height + 1)
            (project reply) (remember kp height left current state))
      else some ((current, height) :: (left, level) :: rest, state)

def replayTree (table : Memo K α) (leaf : ℕ → Option N)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S) :
    ℕ → ℕ → List (N × ℕ) → S → Option (List (N × ℕ) × S)
  | 0, _, stack, state => some (stack, state)
  | n + 1, start, stack, state =>
      (leaf start).bind (fun current =>
        (replayMerge table input project remember start stack 0 current state).bind
          (fun merged => replayTree table leaf input project remember n (start + 1)
            merged.1 merged.2))

theorem replay_cast_tree_program {first second : List ℕ} {n m : ℕ}
    (shapeEq : first = second) (costEq : n = m)
    (program : QueryProgram K α (ShapeStack N first × S) n) (table : Memo K α) :
    (replayProgram table (castTreeProgram shapeEq costEq program)).map
        (eraseTreeState second) =
      (replayProgram table program).map (eraseTreeState first) := by
  subst second
  subst m
  rfl

theorem replay_merge_program (table : Memo K α)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S) (kp : ℕ)
    (shape : List ℕ) (height : ℕ) (stack : ShapeStack N shape) (current : N) (state : S) :
    (replayProgram table (mergeProgram input project remember kp shape height stack current state)).map
        (eraseTreeState (mergedShape height shape)) =
      replayMerge table input project remember kp (eraseStack shape stack) height current state := by
  induction shape generalizing height current state with
  | nil => simp [mergeProgram, replayProgram, eraseTreeState, eraseStack,
      mergedShape, mergeShape, replayMerge]
  | cons level rest ih =>
    by_cases he : level = height
    · simp only [mergeProgram, he, ↓reduceDIte, ↓reduceIte, replay_cast_tree_program,
        replayProgram, Option.map_bind, replayMerge, eraseStack]
      congr 1
      funext reply
      exact ih (height + 1) stack.2 (project reply)
        (remember kp height stack.1 current state)
    · simp only [mergeProgram, he, ↓reduceDIte, ↓reduceIte, replay_cast_tree_program,
        replayProgram, Option.map_some, replayMerge, eraseStack,
        eraseTreeState, mergedShape, mergeShape]

theorem replay_tree_program (table : Memo K α)
    (leafCost : ℕ) (leaf : ℕ → QueryProgram K α N leafCost)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S)
    (n start : ℕ) (shape : List ℕ) (stack : ShapeStack N shape) (state : S) :
    (replayProgram table (treeProgram leafCost leaf input project remember n start shape stack state)).map
        (eraseTreeState (runShape n shape)) =
      replayTree table (fun kp => replayProgram table (leaf kp)) input project remember
        n start (eraseStack shape stack) state := by
  induction n generalizing start shape state with
  | zero => simp [treeProgram, replayProgram, replayTree, eraseTreeState, runShape]
  | succ n ih =>
    simp only [treeProgram, replay_program_cast, replay_program_bind, Option.map_bind,
      Function.comp_def, runShape, ih, replayTree]
    congr 1
    funext current
    rw [← replay_merge_program table input project remember start shape 0 stack current state,
      Option.bind_map]
    rfl

end
end C10Probability

import C10Probability.TreeReplay

/-! A value-independent schedule checks alignment and array bounds for every
actual merge. Concrete proofs cover all merges, without enumerating targets. -/
namespace C10Probability
noncomputable section

def mergeAuthSchedule (bound kp : ℕ) : ℕ → List ℕ → Prop
  | _, [] => True
  | height, level :: rest => if level = height then
      height < bound ∧ (kp + 1) % 2 ^ (height + 1) = 0 ∧
        mergeAuthSchedule bound kp (height + 1) rest else True

instance mergeAuthScheduleDecidable (bound kp height : ℕ) (shape : List ℕ) :
    Decidable (mergeAuthSchedule bound kp height shape) := by
  induction shape generalizing height with
  | nil => exact isTrue True.intro
  | cons level rest ih =>
    unfold mergeAuthSchedule
    haveI := ih (height + 1)
    infer_instance

def treeAuthSchedule (bound : ℕ) : ℕ → ℕ → List ℕ → Prop
  | 0, _, _ => True
  | n + 1, start, shape => mergeAuthSchedule bound start 0 shape ∧
      treeAuthSchedule bound n (start + 1) (nextShape shape)

instance treeAuthScheduleDecidable (bound n start : ℕ) (shape : List ℕ) :
    Decidable (treeAuthSchedule bound n start shape) := by
  induction n generalizing start shape with
  | zero => exact isTrue True.intro
  | succ n ih =>
    unfold treeAuthSchedule
    haveI := ih (start + 1) (nextShape shape)
    infer_instance

set_option maxRecDepth 80000 in
theorem merkle_auth_schedule : treeAuthSchedule 9 512 0 [] := by decide +kernel

set_option maxRecDepth 80000 in
theorem fors_auth_schedule : treeAuthSchedule 11 2048 0 [] := by decide +kernel

variable {K α N S : Type*}

theorem erased_stack_shape (shape : List ℕ) (stack : ShapeStack N shape) :
    (eraseStack shape stack).map Prod.snd = shape := by
  induction shape with
  | nil => rfl
  | cons height rest ih => simp [eraseStack, ih]

theorem replay_merge_shape (table : Memo K α)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S) (kp : ℕ)
    (stack : List (N × ℕ)) (height : ℕ) (current : N) (state : S)
    (out : List (N × ℕ) × S)
    (recorded : replayMerge table input project remember kp stack height current state = some out) :
    out.1.map Prod.snd = mergedShape height (stack.map Prod.snd) := by
  induction stack generalizing height current state out with
  | nil =>
    have he : out = ([(current, height)], state) := Option.some.inj recorded.symm
    simp [he, mergedShape, mergeShape]
  | cons entry rest ih =>
    obtain ⟨left, level⟩ := entry
    by_cases he : level = height
    · subst level
      simp only [replayMerge, ↓reduceIte] at recorded
      cases hd : table (input kp height left current) with
      | none => simp only [hd, Option.bind_none] at recorded; cases recorded
      | some reply =>
        simp only [hd, Option.bind_some] at recorded
        simpa only [List.map_cons, mergedShape, mergeShape, ↓reduceIte] using
          ih (height + 1) (project reply) (remember kp height left current state) out recorded
    · simp only [replayMerge, he, ↓reduceIte, Option.some.injEq] at recorded
      subst out
      simp [mergedShape, mergeShape, he]

end
end C10Probability

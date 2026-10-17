import C10Probability.StateFold

/-! The actual treehash control is independent of oracle replies. Each equal
height pops one stack entry; the final current node is pushed once. Costs are
derived from these transitions, including the concrete 512-leaf geometry. -/
namespace C10Probability

structure MergeShape where
  height : ℕ
  rest : List ℕ
  calls : ℕ
  deriving DecidableEq, Repr

def mergeShape : ℕ → List ℕ → MergeShape
  | height, [] => ⟨height, [], 0⟩
  | height, level :: rest =>
      if level = height then
        let next := mergeShape (height + 1) rest
        ⟨next.height, next.rest, next.calls + 1⟩
      else ⟨height, level :: rest, 0⟩

def nextShape (stack : List ℕ) : List ℕ :=
  let out := mergeShape 0 stack
  out.height :: out.rest

def runShape : ℕ → List ℕ → List ℕ
  | 0, stack => stack
  | n + 1, stack => runShape n (nextShape stack)

def shapeCalls : ℕ → List ℕ → ℕ
  | 0, _ => 0
  | n + 1, stack => (mergeShape 0 stack).calls + shapeCalls n (nextShape stack)

def shapeHeightBound (bound : ℕ) : ℕ → List ℕ → Prop
  | 0, _ => True
  | n + 1, stack =>
      (mergeShape 0 stack).height ≤ bound ∧ shapeHeightBound bound n (nextShape stack)

instance shapeHeightBoundDecidable (bound n : ℕ) (stack : List ℕ) :
    Decidable (shapeHeightBound bound n stack) := by
  induction n generalizing stack with
  | zero => exact isTrue True.intro
  | succ n ih =>
    unfold shapeHeightBound
    haveI := ih (nextShape stack)
    infer_instance

theorem merge_shape_accounting (height : ℕ) (stack : List ℕ) :
    (mergeShape height stack).calls + (mergeShape height stack).rest.length = stack.length := by
  induction stack generalizing height with
  | nil => rfl
  | cons level rest ih =>
    by_cases he : level = height
    · simp only [mergeShape, he, ↓reduceIte, List.length_cons]
      have h := ih (height + 1)
      omega
    · simp [mergeShape, he]

theorem merge_shape_height_mono (height : ℕ) (stack : List ℕ) :
    height ≤ (mergeShape height stack).height := by
  induction stack generalizing height with
  | nil => exact le_refl _
  | cons level rest ih =>
    by_cases he : level = height
    · simp only [mergeShape, he, ↓reduceIte]
      exact le_trans (by omega) (ih (height + 1))
    · simp [mergeShape, he]

theorem shape_calls_accounting (n : ℕ) (stack : List ℕ) :
    shapeCalls n stack + (runShape n stack).length = stack.length + n := by
  induction n generalizing stack with
  | zero => simp [shapeCalls, runShape]
  | succ n ih =>
    have h := ih (nextShape stack)
    have hm := merge_shape_accounting 0 stack
    simp only [nextShape, List.length_cons] at h
    simp only [shapeCalls, runShape, nextShape]
    omega

theorem subtree_shape : runShape 512 [] = [9] := by
  set_option maxRecDepth 20000 in decide +kernel

theorem subtree_merge_calls : shapeCalls 512 [] = 511 := by
  have h := shape_calls_accounting 512 []
  rw [subtree_shape] at h
  simp only [List.length_cons, List.length_nil] at h
  omega

theorem subtree_merge_height_bound : shapeHeightBound 9 512 [] := by
  set_option maxRecDepth 20000 in decide +kernel

def treeCalls (leafCalls n : ℕ) (stack : List ℕ) : ℕ :=
  leafCalls * n + shapeCalls n stack

theorem tree_calls_step (leafCalls n : ℕ) (stack : List ℕ) :
    treeCalls leafCalls (n + 1) stack =
      treeCalls leafCalls n (nextShape stack) + (mergeShape 0 stack).calls + leafCalls := by
  simp only [treeCalls, shapeCalls, Nat.mul_add, Nat.mul_one]
  omega

theorem subtree_raw_calls : treeCalls 345 512 [] = 177151 := by
  rw [treeCalls, subtree_merge_calls]

theorem subtree_public_calls : treeCalls 302 512 [] = 155135 := by
  rw [treeCalls, subtree_merge_calls]

end C10Probability

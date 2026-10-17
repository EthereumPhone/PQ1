import C10Probability.TreeShape

/-! The stack shape is static, but node values and the memo table remain fully
adaptive. Erasure compares the indexed compiler to the ordinary list-stack
procedure, including the remembered authentication state. -/
namespace C10Probability
noncomputable section

variable {K L α N S : Type*}

universe uN

def ShapeStack (N : Type uN) : List ℕ → Type uN
  | [] => PUnit
  | _ :: rest => N × ShapeStack N rest

def eraseStack : (shape : List ℕ) → ShapeStack N shape → List (N × ℕ)
  | [], _ => []
  | height :: rest, stack => (stack.1, height) :: eraseStack rest stack.2

def mergedShape (height : ℕ) (shape : List ℕ) : List ℕ :=
  let out := mergeShape height shape
  out.height :: out.rest

def eraseTreeState (shape : List ℕ) (state : ShapeStack N shape × S) :
    List (N × ℕ) × S := (eraseStack shape state.1, state.2)

def eraseTreeOutput (shape : List ℕ)
    (out : (ShapeStack N shape × S) × Memo K α) :
    (List (N × ℕ) × S) × Memo K α := (eraseTreeState shape out.1, out.2)

def castTreeProgram {first second : List ℕ} {n m : ℕ}
    (shapeEq : first = second) (costEq : n = m)
    (program : QueryProgram K α (ShapeStack N first × S) n) :
    QueryProgram K α (ShapeStack N second × S) m :=
  shapeEq ▸ costEq ▸ program

theorem eval_castTreeProgram [DecidableEq K] (p : PMF α)
    {first second : List ℕ} {n m : ℕ} (shapeEq : first = second) (costEq : n = m)
    (program : QueryProgram K α (ShapeStack N first × S) n) (table : Memo K α) :
    (evalProgram p (castTreeProgram shapeEq costEq program) table).map
        (eraseTreeOutput second) =
      (evalProgram p program table).map (eraseTreeOutput first) := by
  subst second
  subst m
  rfl

theorem map_castTreeProgram (encode : K → L) {first second : List ℕ} {n m : ℕ}
    (shapeEq : first = second) (costEq : n = m)
    (program : QueryProgram K α (ShapeStack N first × S) n) :
    mapProgram encode (castTreeProgram shapeEq costEq program) =
      castTreeProgram shapeEq costEq (mapProgram encode program) := by
  subst second
  subst m
  rfl

theorem public_castTreeProgram {P : Type*} {first second : List ℕ} {n m : ℕ}
    (shapeEq : first = second) (costEq : n = m)
    (program : QueryProgram (Sum K P) α (ShapeStack N first × S) n) (q : ℕ) :
    PublicBudget (castTreeProgram shapeEq costEq program) q = PublicBudget program q := by
  subst second
  subst m
  rfl

def mergeProgram (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S) (kp : ℕ) :
    (shape : List ℕ) → (height : ℕ) → ShapeStack N shape → N → S →
      QueryProgram K α (ShapeStack N (mergedShape height shape) × S)
        (mergeShape height shape).calls
  | [], height, _, current, state => .done ((current, PUnit.unit), state)
  | level :: rest, height, stack, current, state =>
      if he : level = height then
        castTreeProgram (by simp [mergedShape, mergeShape, he]) (by simp [mergeShape, he])
          (.query (input kp height stack.1 current) (fun reply =>
            mergeProgram input project remember kp rest (height + 1) stack.2
              (project reply) (remember kp height stack.1 current state)))
      else
        castTreeProgram (by simp [mergedShape, mergeShape, he]) (by simp [mergeShape, he])
          (.done ((current, stack), state) :
            QueryProgram K α (ShapeStack N (height :: level :: rest) × S) 0)

def mergeLoop [DecidableEq K] (p : PMF α)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S) (kp : ℕ) :
    List (N × ℕ) → ℕ → N → S → Memo K α → PMF ((List (N × ℕ) × S) × Memo K α)
  | [], height, current, state, table => PMF.pure (([(current, height)], state), table)
  | (left, level) :: rest, height, current, state, table =>
      if level = height then
        (memoQuery p table (input kp height left current)).bind (fun reply =>
          mergeLoop p input project remember kp rest (height + 1) (project reply.1)
            (remember kp height left current state) reply.2)
      else PMF.pure (((current, height) :: (left, level) :: rest, state), table)

theorem merge_program_eval [DecidableEq K] (p : PMF α)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S) (kp : ℕ)
    (shape : List ℕ) (height : ℕ) (stack : ShapeStack N shape)
    (current : N) (state : S) (table : Memo K α) :
    (evalProgram p (mergeProgram input project remember kp shape height stack current state)
      table).map (eraseTreeOutput (mergedShape height shape)) =
      mergeLoop p input project remember kp (eraseStack shape stack) height current state table := by
  induction shape generalizing height current state table with
  | nil => simp [mergeProgram, evalProgram, PMF.pure_map, eraseTreeOutput,
      eraseTreeState, eraseStack, mergedShape, mergeShape, mergeLoop]
  | cons level rest ih =>
    by_cases he : level = height
    · simp only [mergeProgram, he, ↓reduceDIte, ↓reduceIte, eval_castTreeProgram, evalProgram, PMF.map_bind,
        mergeLoop, eraseStack]
      congr 1
      funext reply
      exact ih (height + 1) stack.2 (project reply.1)
        (remember kp height stack.1 current state) reply.2
    · simp only [mergeProgram, he, ↓reduceDIte, ↓reduceIte, eval_castTreeProgram, evalProgram, PMF.pure_map,
        mergeLoop, eraseStack, eraseTreeOutput, eraseTreeState, mergedShape, mergeShape]

theorem merge_program_map (encode : K → L)
    (input : ℕ → ℕ → N → N → K) (project : α → N)
    (remember : ℕ → ℕ → N → N → S → S) (kp : ℕ)
    (shape : List ℕ) (height : ℕ) (stack : ShapeStack N shape) (current : N) (state : S) :
    mapProgram encode (mergeProgram input project remember kp shape height stack current state) =
      mergeProgram (fun k h l r => encode (input k h l r)) project remember kp
        shape height stack current state := by
  induction shape generalizing height current state with
  | nil => rfl
  | cons level rest ih =>
    by_cases he : level = height <;>
      simp only [mergeProgram, he, ↓reduceDIte, map_castTreeProgram, mapProgram, ih]

end
end C10Probability

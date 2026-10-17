import C10Probability.QueryReplay

/-! Bottom-up reference paths use the existing memo table. Pair labels take
the child height and parent index; parity determines the ordered children. -/
namespace C10Probability
noncomputable section

variable {K α N : Type*}

def pathPairInput (pair : ℕ → ℕ → N → N → K)
    (height index : ℕ) (current sibling : N) : K :=
  if index % 2 = 0 then pair height (index / 2) current sibling
  else pair height (index / 2) sibling current

def replayPath (table : Memo K α) (pair : ℕ → ℕ → N → N → K)
    (project : α → N) : ℕ → ℕ → N → List N → Option N
  | _, _, current, [] => some current
  | height, index, current, sibling :: rest =>
      (table (pathPairInput pair height index current sibling)).bind (fun reply =>
        replayPath table pair project (height + 1) (index / 2) (project reply) rest)

theorem replay_path_append (table : Memo K α) (pair : ℕ → ℕ → N → N → K)
    (project : α → N) (height index : ℕ) (current : N) (auth rest : List N) :
    replayPath table pair project height index current (auth ++ rest) =
      (replayPath table pair project height index current auth).bind
        (fun middle => replayPath table pair project (height + auth.length)
          (index / 2 ^ auth.length) middle rest) := by
  induction auth generalizing height index current with
  | nil => simp only [List.nil_append, replayPath, Option.bind_some, List.length_nil,
      Nat.add_zero, pow_zero, Nat.div_one]
  | cons sibling auth ih =>
    simp only [List.cons_append, replayPath, ih, Option.bind_assoc, List.length_cons]
    congr 1
    funext reply
    congr 1
    funext middle
    congr 1 <;> simp [Nat.add_comm, Nat.add_left_comm,
      Nat.div_div_eq_div_mul, pow_succ, Nat.mul_comm]

theorem replay_path_extends (before after : Memo K α) (pair : ℕ → ℕ → N → N → K)
    (project : α → N) (height index : ℕ) (current root : N) (auth : List N)
    (extension : MemoExtends before after)
    (recorded : replayPath before pair project height index current auth = some root) :
    replayPath after pair project height index current auth = some root := by
  induction auth generalizing height index current with
  | nil => exact recorded
  | cons sibling rest ih =>
    cases hd : before (pathPairInput pair height index current sibling) with
    | none => simp only [replayPath, hd, Option.bind_none] at recorded; cases recorded
    | some reply =>
      simp only [replayPath, hd, Option.bind_some] at recorded
      simp only [replayPath, extension _ _ hd, Option.bind_some]
      exact ih (height + 1) (index / 2) (project reply) recorded

end
end C10Probability

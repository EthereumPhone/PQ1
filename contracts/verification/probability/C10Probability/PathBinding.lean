import C10Probability.PathReplay

/-! Same-coordinate paths with the same root have the same leaf whenever
recorded pair hashes bind their ordered children. Concrete byte inputs and
the existing selected-node collision predicate discharge that condition. -/
namespace C10Probability
noncomputable section

variable {K α N : Type*}

theorem replay_path_leaf_eq (table : Memo K α) (pair : ℕ → ℕ → N → N → K)
    (project : α → N)
    (binding : ∀ height parent left right left' right' first second,
      table (pair height parent left right) = some first →
      table (pair height parent left' right') = some second →
      project first = project second → left = left' ∧ right = right')
    (height index : ℕ) (first second root : N) (auth auth' : List N)
    (length : auth.length = auth'.length)
    (recorded : replayPath table pair project height index first auth = some root)
    (recorded' : replayPath table pair project height index second auth' = some root) :
    first = second := by
  induction auth generalizing auth' height index first second with
  | nil =>
    have he : auth' = [] := by simpa using length.symm
    subst auth'
    exact (Option.some.inj recorded).trans (Option.some.inj recorded').symm
  | cons sibling rest ih =>
    cases auth' with
    | nil => simp only [List.length_cons, List.length_nil] at length; omega
    | cons sibling' rest' =>
      have hlen : rest.length = rest'.length := Nat.succ.inj length
      cases hf : table (pathPairInput pair height index first sibling) with
      | none => simp only [replayPath, hf, Option.bind_none] at recorded; cases recorded
      | some value =>
        simp only [replayPath, hf, Option.bind_some] at recorded
        cases hs : table (pathPairInput pair height index second sibling') with
        | none => simp only [replayPath, hs, Option.bind_none] at recorded'; cases recorded'
        | some reply =>
          simp only [replayPath, hs, Option.bind_some] at recorded'
          have same := ih (height + 1) (index / 2) (project value) (project reply)
            rest' hlen recorded recorded'
          by_cases parity : index % 2 = 0
          · exact (binding height (index / 2) first sibling second sibling' value reply
              (by simpa only [pathPairInput, parity, ↓reduceIte] using hf)
              (by simpa only [pathPairInput, parity, ↓reduceIte] using hs) same).1
          · exact (binding height (index / 2) sibling first sibling' second value reply
              (by simpa only [pathPairInput, parity, ↓reduceIte] using hf)
              (by simpa only [pathPairInput, parity, ↓reduceIte] using hs) same).2

end
end C10Probability

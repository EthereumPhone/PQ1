import C10Probability.RandomGrind

/-! A proved observation of one memo table. Entries hidden by this observation
are still present in the executed shared table; this is not a second oracle. -/
namespace C10Probability
noncomputable section

variable {K α : Type*}

def eraseMemo (hidden : K → Bool) (table : Memo K α) : Memo K α :=
  fun key => if hidden key then none else table key

theorem eraseMemo_hidden (hidden : K → Bool) (table : Memo K α) (key : K)
    (h : hidden key = true) : eraseMemo hidden table key = none := by
  simp [eraseMemo, h]

theorem eraseMemo_visible (hidden : K → Bool) (table : Memo K α) (key : K)
    (h : hidden key = false) : eraseMemo hidden table key = table key := by
  simp [eraseMemo, h]

theorem eraseMemo_idempotent (hidden : K → Bool) (table : Memo K α) :
    eraseMemo hidden (eraseMemo hidden table) = eraseMemo hidden table := by
  funext key
  cases h : hidden key <;> simp [eraseMemo, h]

theorem eraseMemo_update_hidden [DecidableEq K] (hidden : K → Bool)
    (table : Memo K α) (key : K) (value : Option α) (h : hidden key = true) :
    eraseMemo hidden (Function.update table key value) = eraseMemo hidden table := by
  funext other
  by_cases he : other = key
  · subst other; simp [eraseMemo, h]
  · simp [eraseMemo, he]

theorem eraseMemo_update_visible [DecidableEq K] (hidden : K → Bool)
    (table : Memo K α) (key : K) (value : Option α) (h : hidden key = false) :
    eraseMemo hidden (Function.update table key value) =
      Function.update (eraseMemo hidden table) key value := by
  funext other
  by_cases he : other = key
  · subst other; simp [eraseMemo, h]
  · simp [eraseMemo, he]

theorem memoQuery_erase [DecidableEq K] (p : PMF α) (hidden : K → Bool)
    (table : Memo K α) (key : K) (h : hidden key = false) :
    memoQuery p (eraseMemo hidden table) key =
      (memoQuery p table key).map (fun out => (out.1, eraseMemo hidden out.2)) := by
  cases ht : table key with
  | none =>
    simp [memoQuery, eraseMemo_visible hidden table key h, ht, PMF.map_comp,
      Function.comp_def, eraseMemo_update_visible hidden table key _ h]
  | some x =>
    simp [memoQuery, eraseMemo_visible hidden table key h, ht, PMF.pure_map]

end
end C10Probability

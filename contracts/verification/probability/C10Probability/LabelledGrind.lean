import C10Probability.MemoView

/-! The independent-key comparison retains the selected key label as well as
the full reply, counter and table. Forgetting the label is an explicit map. -/
namespace C10Probability
noncomputable section

variable {K L α : Type*}

def labelledMemoGrind [DecidableEq K] (q : PMF L) (p : PMF α) (encode : L → K)
    (accept : α → Bool) (table : Memo K α) (start : ℕ) :
    ℕ → PMF (Option (ℕ × L × α) × Memo K α)
  | 0 => PMF.pure (none, table)
  | n + 1 => q.bind fun label => (memoQuery p table (encode label)).bind fun out =>
      if accept out.1 then PMF.pure (some (start, label, out.1), out.2)
      else labelledMemoGrind q p encode accept out.2 (start + 1) n

def forgetLabel (result : Option (ℕ × L × α)) : Option (ℕ × α) :=
  result.map fun hit => (hit.1, hit.2.2)

theorem forgetLabel_some (start : ℕ) (label : L) (reply : α) :
    forgetLabel (some (start, label, reply)) = some (start, reply) := by rfl

theorem forgetLabel_none : forgetLabel (none : Option (ℕ × L × α)) = none := by rfl

theorem forgetLabel_none_mass (p : PMF (Option (ℕ × L × α))) :
    (p.map forgetLabel) none = p none := by
  simp [PMF.map_apply, forgetLabel]

theorem labelledMemoGrind_projection [DecidableEq K] (q : PMF L) (p : PMF α)
    (encode : L → K) (accept : α → Bool) (table : Memo K α) (start n : ℕ) :
    (labelledMemoGrind q p encode accept table start n).map
      (fun out => (forgetLabel out.1, out.2)) =
        randomMemoGrind (q.map encode) p accept table start n := by
  induction n generalizing table start with
  | zero => simp [labelledMemoGrind, randomMemoGrind, PMF.pure_map, forgetLabel]
  | succ n ih =>
    rw [labelledMemoGrind, randomMemoGrind, PMF.bind_map, PMF.map_bind]
    simp only [Function.comp_def]
    congr 1
    funext label
    rw [PMF.map_bind]
    congr 1
    funext out
    cases ha : accept out.1
    · simp only [Bool.false_eq_true, ↓reduceIte]
      exact ih out.2 (start + 1)
    · simp [PMF.pure_map, forgetLabel]

theorem labelledMemoGrind_erase [DecidableEq K] (q : PMF L) (p : PMF α)
    (encode : L → K) (accept : α → Bool) (hidden : K → Bool)
    (visible : ∀ label, hidden (encode label) = false) (table : Memo K α)
    (start n : ℕ) :
    labelledMemoGrind q p encode accept (eraseMemo hidden table) start n =
      (labelledMemoGrind q p encode accept table start n).map
        (fun out => (out.1, eraseMemo hidden out.2)) := by
  induction n generalizing table start with
  | zero => simp [labelledMemoGrind, PMF.pure_map]
  | succ n ih =>
    rw [labelledMemoGrind, labelledMemoGrind, PMF.map_bind]
    congr 1
    funext label
    rw [memoQuery_erase p hidden table (encode label) (visible label), PMF.bind_map,
      PMF.map_bind]
    simp only [Function.comp_def]
    congr 1
    funext out
    cases ha : accept out.1
    · simp only [Bool.false_eq_true, ↓reduceIte]
      exact ih out.2 (start + 1)
    · simp [PMF.pure_map]

end
end C10Probability

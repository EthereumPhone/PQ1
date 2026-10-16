import C10Probability.SelectedComposition

/-! The one-query bounded search as an actual memoized client. The compilation
preserves the full table on both early success and exhaustion. -/
namespace C10Probability
noncomputable section

variable {K J α : Type*}

def countProgram (accept : α → Bool) (start : ℕ) :
    (keys : List K) → QueryProgram K α (Option (ℕ × α)) keys.length
  | [] => .done none
  | key :: keys => .query key (fun reply =>
      if accept reply then .done (some (start, reply))
      else countProgram accept (start + 1) keys)

theorem evalProgram_mapped_count [DecidableEq J] (p : PMF α) (encode : K → J)
    (accept : α → Bool) (start : ℕ) (keys : List K) (table : Memo J α) :
    evalProgram p (mapProgram encode (countProgram accept start keys)) table =
      memoGrind p accept table start (keys.map encode) := by
  induction keys generalizing start table with
  | nil => simp [countProgram, mapProgram, evalProgram, memoGrind]
  | cons key keys ih =>
    simp only [countProgram, mapProgram, evalProgram, List.map_cons, memoGrind]
    congr 1
    funext reply
    cases ha : accept reply.1
    · simpa only [ha, Bool.false_eq_true, ↓reduceIte] using ih (start + 1) reply.2
    · simp only [↓reduceIte, mapProgram, evalProgram]

theorem evalProgram_count [DecidableEq K] (p : PMF α) (accept : α → Bool)
    (start : ℕ) (keys : List K) (table : Memo K α) :
    evalProgram p (countProgram accept start keys) table =
      memoGrind p accept table start keys := by
  simpa only [mapProgram_id, List.map_id] using
    evalProgram_mapped_count p id accept start keys table

theorem countProgram_selected_budget (select : K → Bool) (accept : α → Bool)
    (start : ℕ) (keys : List K) :
    SelectedBudget select (countProgram accept start keys) (keys.filter select).length := by
  induction keys generalizing start with
  | nil => trivial
  | cons key keys ih =>
    cases hs : select key <;>
      simp only [countProgram, SelectedBudget, hs, Bool.false_eq_true, ↓reduceIte,
        List.filter_cons, List.length_cons]
    · intro reply
      cases ha : accept reply
      · simpa only [ha, Bool.false_eq_true, ↓reduceIte] using ih (start + 1)
      · simp only [↓reduceIte, SelectedBudget]
    · refine ⟨by omega, fun reply => ?_⟩
      cases ha : accept reply
      · simpa only [ha, Bool.false_eq_true, ↓reduceIte, Nat.add_sub_cancel] using ih (start + 1)
      · simp only [↓reduceIte, SelectedBudget]

theorem countProgram_selected_zero (select : K → Bool) (accept : α → Bool)
    (start : ℕ) (keys : List K) (excluded : ∀ key ∈ keys, select key = false) :
    SelectedBudget select (countProgram accept start keys) 0 := by
  have he : keys.filter select = [] :=
    List.filter_eq_nil_iff.mpr (fun key hk => by simp [excluded key hk])
  simpa only [he, List.length_nil] using countProgram_selected_budget select accept start keys

theorem count_program_fresh [DecidableEq K] (p : PMF α) (accept : α → Bool)
    (start : ℕ) (keys : List K) (table : Memo K α) (hd : keys.Nodup)
    (hf : ∀ key ∈ keys, table key = none) :
    (evalProgram p (countProgram accept start keys) table).map Prod.fst =
      grind p accept start keys.length := by
  rw [evalProgram_count]
  exact memoGrind_fresh p accept table start keys hd hf

end
end C10Probability

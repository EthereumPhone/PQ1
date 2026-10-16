import C10Probability.Schedules
import C10Probability.Memo

/-! An online random-key loop. Keys are independent draws from `q`; replies
come from the persistent memo table. No key or reply is resampled after success. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {K α : Type*}

def randomMemoGrind [DecidableEq K] (q : PMF K) (p : PMF α) (accept : α → Bool)
    (table : Memo K α) (start : ℕ) : ℕ → PMF (Option (ℕ × α) × Memo K α)
  | 0 => PMF.pure (none, table)
  | n + 1 => q.bind fun key => (memoQuery p table key).bind fun out =>
      if accept out.1 then PMF.pure (some (start, out.1), out.2)
      else randomMemoGrind q p accept out.2 (start + 1) n

/- Pre-sampling the independent keys changes neither the result nor the final
table. Unused keys after the first hit are integrated out, not queried. -/
theorem randomMemoGrind_schedule [DecidableEq K] (q : PMF K) (p : PMF α) (accept : α → Bool)
    (table : Memo K α) (start n : ℕ) :
    randomMemoGrind q p accept table start n =
      (drawList q n).bind (memoGrind p accept table start) := by
  induction n generalizing table start with
  | zero => simp [randomMemoGrind, drawList, memoGrind, PMF.pure_bind]
  | succ n ih =>
    rw [randomMemoGrind, drawList, PMF.bind_bind]
    simp only [PMF.bind_map, Function.comp_def, memoGrind]
    congr 1
    funext key
    rw [PMF.bind_comm (drawList q n) (memoQuery p table key)]
    congr 1
    funext out
    cases ha : accept out.1
    · simp only [Bool.false_eq_true, ↓reduceIte]
      exact ih out.2 (start + 1)
    · simp

theorem randomMemoGrind_preserves [DecidableEq K] (q : PMF K) (p : PMF α) (accept : α → Bool)
    (table : Memo K α) (start n : ℕ) (key : K) (x : α) (hx : table key = some x)
    (out : Option (ℕ × α) × Memo K α)
    (ho : out ∈ (randomMemoGrind q p accept table start n).support) :
    out.2 key = some x := by
  rw [randomMemoGrind_schedule, PMF.mem_support_bind_iff] at ho
  obtain ⟨keys, _, ho⟩ := ho
  exact memoGrind_preserves p accept table start keys key x hx out ho

theorem randomMemoGrind_embedded (q : PMF K) (p : PMF α) (accept : α → Bool)
    {L : Type*} [DecidableEq L] (embed : K → L) (table : Memo L α) (start n : ℕ) :
    randomMemoGrind (q.map embed) p accept table start n =
      (drawList q n).bind fun keys => memoGrind p accept table start (keys.map embed) := by
  rw [randomMemoGrind_schedule, drawList_map, PMF.bind_map]
  rfl

end
end C10Probability

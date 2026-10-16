import C10Probability.ProgramComposition
import C10Probability.DerivedGrind

/-! Compile the existing two-query search into the bounded client language.
No freshness or acceptance premise is required by the full-state equality. -/
namespace C10Probability
noncomputable section

variable {K P L J α : Type*}

def derivedProgram (firstKey : P → K) (derive : α → L) (encode : L → K)
    (accept : α → Bool) (start : ℕ) : (keys : List P) →
    QueryProgram K α (Option (ℕ × L × α)) (2 * keys.length)
  | [] => .done none
  | key :: keys => castProgram (by simp [Nat.mul_succ, Nat.add_assoc])
      (.query (firstKey key) (fun first => .query (encode (derive first))
        (fun second => if accept second then .done (some (start, derive first, second))
          else derivedProgram firstKey derive encode accept (start + 1) keys)))

theorem evalProgram_mapped_derived [DecidableEq J] (p : PMF α)
    (relabel : K → J) (firstKey : P → K) (derive : α → L) (encode : L → K)
    (accept : α → Bool) (start : ℕ) (keys : List P) (table : Memo J α) :
    evalProgram p (mapProgram relabel (derivedProgram firstKey derive encode accept start keys))
      table = derivedMemoGrind p derive (relabel ∘ encode) accept table start
        (keys.map (relabel ∘ firstKey)) := by
  induction keys generalizing start table with
  | nil => simp [derivedProgram, mapProgram, evalProgram, derivedMemoGrind]
  | cons key keys ih =>
    simp only [derivedProgram, mapProgram_cast, evalProgram_cast, mapProgram,
      evalProgram, List.map_cons, derivedMemoGrind, Function.comp_apply]
    congr 1
    funext first
    congr 1
    funext second
    cases ha : accept second.1
    · simpa only [ha, Bool.false_eq_true, ↓reduceIte] using ih (start + 1) second.2
    · simp only [↓reduceIte, mapProgram, evalProgram]

theorem evalProgram_derived [DecidableEq K] (p : PMF α)
    (firstKey : P → K) (derive : α → L) (encode : L → K)
    (accept : α → Bool) (start : ℕ) (keys : List P) (table : Memo K α) :
    evalProgram p (derivedProgram firstKey derive encode accept start keys) table =
      derivedMemoGrind p derive encode accept table start (keys.map firstKey) := by
  simpa only [mapProgram_id, Function.id_comp] using
    evalProgram_mapped_derived p id firstKey derive encode accept start keys table

theorem private_derived_public_budget (derive : α → L) (encode : L → K)
    (accept : α → Bool) (start : ℕ) (keys : List P) :
    PublicBudget (derivedProgram Sum.inr derive (Sum.inl ∘ encode) accept start keys)
      keys.length := by
  induction keys generalizing start with
  | nil => trivial
  | cons key keys ih =>
    simp only [derivedProgram, publicBudget_cast, PublicBudget, Function.comp_apply,
      List.length_cons]
    intro first
    refine ⟨by omega, fun second => ?_⟩
    cases ha : accept second
    · simpa only [ha, Bool.false_eq_true, ↓reduceIte, Nat.add_sub_cancel] using ih (start + 1)
    · simp only [↓reduceIte, PublicBudget]

theorem derived_program_zero [DecidableEq K] (p : PMF α)
    (firstKey : P → K) (derive : α → L) (encode : L → K)
    (accept : α → Bool) (start : ℕ) (table : Memo K α) :
    evalProgram p (derivedProgram firstKey derive encode accept start []) table =
      PMF.pure (none, table) := by rfl

end
end C10Probability

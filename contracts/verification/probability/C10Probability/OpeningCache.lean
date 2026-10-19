import C10Probability.OpeningComposition
import C10Probability.MemoPresample
import C10Probability.DerivedGrind

/-! A selected private entry is distinct from commitment keys and is never
queried by a hidden opening context. Its presampled value can therefore be
threaded through the full cache without supplying it to that context. -/
namespace C10Probability
noncomputable section
variable {K P α H S R : Type*} [DecidableEq K]

def openingErase (out : OpeningOutput K α R) : R × Memo K α := (out.value, out.cache)

def OpeningAvoids (target : K) : {n : ℕ} → OpeningProgram K P α H R n → Prop
  | _, .done _ => True
  | _, .query key next => key ≠ target ∧ ∀ reply, OpeningAvoids target (next reply)
  | _, .commit _ next => ∀ reply, OpeningAvoids target (next reply)
  | _, .reveal next => ∀ secret, OpeningAvoids target (next secret)

theorem memo_query_update_other (p : PMF α) (table : Memo K α) (key target : K)
    (value : Option α) (different : key ≠ target) :
    memoQuery p (Function.update table target value) key =
      (memoQuery p table key).map fun out => (out.1, Function.update out.2 target value) := by
  cases cached : table key with
  | some reply => simp [memoQuery, different, cached, PMF.pure_map]
  | none =>
    simp only [memoQuery, Function.update_of_ne different, cached, PMF.map_comp]
    congr 1
    funext reply
    simp only [Function.comp_def]
    rw [Function.update_comm different]

theorem eval_opening_preserves (p : PMF α) (encode : S → P → K)
    (project : H → S) (secret : H) {n : ℕ} (program : OpeningProgram K P α H R n)
    (table : Memo K α) (opened : Bool) (key : K) (value : α)
    (cached : table key = some value) (out : OpeningOutput K α R)
    (supported : out ∈ (evalOpening p encode project secret program table opened).support) :
    out.cache key = some value := by
  induction program generalizing table opened out with
  | done result =>
    have equal : out = ⟨result, table, opened⟩ := by simpa [evalOpening] using supported
    simpa only [equal] using cached
  | query first next ih =>
    rw [evalOpening, PMF.mem_support_bind_iff] at supported
    obtain ⟨reply, hr, supported⟩ := supported
    exact ih reply.1 reply.2 opened
      (memoQuery_preserves p table first key value cached reply hr) out supported
  | commit label next ih =>
    rw [evalOpening, PMF.mem_support_bind_iff] at supported
    obtain ⟨reply, hr, supported⟩ := supported
    exact ih reply.1 reply.2 opened
      (memoQuery_preserves p table _ key value cached reply hr) out supported
  | reveal next ih => exact ih secret table true cached out supported

theorem eval_opening_update_avoided (p : PMF α) (encode : S → P → K)
    (project : H → S) (secret : H) (target : K)
    (separate : ∀ label, encode (project secret) label ≠ target) {n : ℕ}
    (program : OpeningProgram K P α H R n) (avoids : OpeningAvoids target program)
    (table : Memo K α) (value : Option α) (opened : Bool) :
    evalOpening p encode project secret program (Function.update table target value) opened =
      (evalOpening p encode project secret program table opened).map
        (fun out => ⟨out.value, Function.update out.cache target value, out.opened⟩) := by
  induction program generalizing table opened with
  | done result => simp only [evalOpening, PMF.pure_map]
  | query key next ih =>
    rw [evalOpening, memo_query_update_other p table key target value avoids.1,
      PMF.bind_map, evalOpening, PMF.map_bind]
    congr 1
    funext reply
    exact ih reply.1 (avoids.2 reply.1) reply.2 opened
  | commit label next ih =>
    rw [evalOpening, memo_query_update_other p table _ target value (separate label),
      PMF.bind_map, evalOpening, PMF.map_bind]
    congr 1
    funext reply
    exact ih reply.1 (avoids reply.1) reply.2 opened
  | reveal next ih => exact ih secret (avoids secret) table true

theorem eval_opening_erase_flag (p : PMF α) (encode : S → P → K)
    (project : H → S) (secret : H) {n : ℕ} (program : OpeningProgram K P α H R n)
    (table : Memo K α) (opened : Bool) :
    (evalOpening p encode project secret program table opened).map openingErase =
      (evalOpening p encode project secret program table false).map openingErase := by
  induction program generalizing table opened with
  | done result => simp only [evalOpening, PMF.pure_map, openingErase]
  | query key next ih =>
    simp only [evalOpening, PMF.map_bind]
    congr 1
    funext reply
    exact ih reply.1 reply.2 opened
  | commit label next ih =>
    simp only [evalOpening, PMF.map_bind]
    congr 1
    funext reply
    exact ih reply.1 reply.2 opened
  | reveal next ih => rfl

def revealLift (target : K) : {n : ℕ} → QueryProgram K α R n →
    OpeningProgram K P α α R n
  | _, .done value => .done value
  | _, .query key next => if key = target then
      .reveal (fun secret => revealLift target (next secret))
    else .query key (fun reply => revealLift target (next reply))

theorem reveal_lift_avoids (target : K) {n : ℕ} (program : QueryProgram K α R n) :
    OpeningAvoids target (revealLift (P := P) target program) := by
  induction program with
  | done value => trivial
  | query key next ih =>
    by_cases equal : key = target
    · simp only [revealLift, equal, ↓reduceIte, OpeningAvoids]
      exact ih
    · simp only [revealLift, equal, ↓reduceIte, OpeningAvoids]
      exact ⟨equal, ih⟩

theorem eval_reveal_lift (p : PMF α) (encode : S → P → K) (project : α → S)
    (secret : α) (target : K) {n : ℕ} (program : QueryProgram K α R n)
    (table : Memo K α) (opened : Bool) (cached : table target = some secret) :
    (evalOpening p encode project secret (revealLift target program) table opened).map
      openingErase = evalProgram p program table := by
  induction program generalizing table opened with
  | done value => simp only [revealLift, evalOpening, PMF.pure_map, openingErase, evalProgram]
  | query key next ih =>
    by_cases equal : key = target
    · subst key
      rw [revealLift, if_pos rfl, evalOpening, evalProgram_cached p target next table secret cached]
      exact ih secret table true cached
    · simp only [revealLift, equal, ↓reduceIte, evalOpening, PMF.map_bind, evalProgram]
      apply bind_eq_of_support
      intro reply hr
      exact ih reply.1 reply.2 opened
        (memoQuery_preserves p table key target secret cached reply hr)

theorem reveal_lift_selected (select : Sum K P → Bool) (target : K) {n : ℕ}
    (program : QueryProgram K α R n) (q : ℕ)
    (budget : SelectedBudget (fun key => select (.inl key)) program q) :
    SelectedBudget select (redactOpening (revealLift target program)) q := by
  induction program generalizing q with
  | done value => trivial
  | query key next ih =>
    by_cases equal : key = target
    · simp only [revealLift, equal, ↓reduceIte, redactOpening, SelectedBudget]
    · simp only [revealLift, equal, ↓reduceIte, redactOpening, SelectedBudget]
      cases hs : select (.inl key) <;>
        simp only [SelectedBudget, hs, Bool.false_eq_true, ↓reduceIte] at budget ⊢
      · exact fun reply => ih reply q (budget reply)
      · exact ⟨budget.1, fun reply => ih reply (q - 1) (budget.2 reply)⟩

end
end C10Probability

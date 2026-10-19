import C10Probability.OpeningProgram
import C10Probability.StateFold

/-! Composition preserves the ordinary execution, complete cache and reveal
flag. The redacted program stops only the unopened-result view, including when
a reveal occurs in the first component of a larger computation. -/
namespace C10Probability
noncomputable section

variable {K P α H S R T : Type*}

def castOpening {n m : ℕ} (h : n = m) (program : OpeningProgram K P α H R n) :
    OpeningProgram K P α H R m := h ▸ program

theorem eval_opening_cast [DecidableEq K] (p : PMF α) (encode : S → P → K)
    (project : H → S) (secret : H) {n m : ℕ} (h : n = m)
    (program : OpeningProgram K P α H R n) (table : Memo K α) (opened : Bool) :
    evalOpening p encode project secret (castOpening h program) table opened =
      evalOpening p encode project secret program table opened := by
  subst m
  rfl

theorem redact_opening_cast {n m : ℕ} (h : n = m)
    (program : OpeningProgram K P α H R n) :
    redactOpening (castOpening h program) = castProgram h (redactOpening program) := by
  subst m
  rfl

def reserveOpening (extra : ℕ) : {n : ℕ} → OpeningProgram K P α H R n →
    OpeningProgram K P α H R (extra + n)
  | _, .done value => .done value
  | _, .query key next => .query key (fun reply => reserveOpening extra (next reply))
  | _, .commit label next => .commit label (fun reply => reserveOpening extra (next reply))
  | _, .reveal next => .reveal (fun secret => reserveOpening extra (next secret))

theorem eval_opening_reserve [DecidableEq K] (p : PMF α) (encode : S → P → K)
    (project : H → S) (secret : H) (extra : ℕ) {n : ℕ}
    (program : OpeningProgram K P α H R n) (table : Memo K α) (opened : Bool) :
    evalOpening p encode project secret (reserveOpening extra program) table opened =
      evalOpening p encode project secret program table opened := by
  induction program generalizing table opened with
  | done value => rfl
  | query key next ih => simp only [reserveOpening, evalOpening, ih]
  | commit label next ih => simp only [reserveOpening, evalOpening, ih]
  | reveal next ih => exact ih secret table true

theorem redact_opening_reserve (extra : ℕ) {n : ℕ}
    (program : OpeningProgram K P α H R n) :
    redactOpening (reserveOpening extra program) = reserveProgram extra (redactOpening program) := by
  induction program with
  | done value => rfl
  | query key next ih => simp only [reserveOpening, redactOpening, reserveProgram, ih]
  | commit label next ih => simp only [reserveOpening, redactOpening, reserveProgram, ih]
  | reveal next ih => rfl

def bindOpening {m : ℕ} : {n : ℕ} → OpeningProgram K P α H R n →
    (R → OpeningProgram K P α H T m) → OpeningProgram K P α H T (m + n)
  | n, .done value, after => castOpening (Nat.add_comm n m) (reserveOpening n (after value))
  | _, .query key next, after => .query key (fun reply => bindOpening (next reply) after)
  | _, .commit label next, after => .commit label (fun reply => bindOpening (next reply) after)
  | _, .reveal next, after => .reveal (fun secret => bindOpening (next secret) after)

theorem eval_opening_bind [DecidableEq K] (p : PMF α) (encode : S → P → K)
    (project : H → S) (secret : H) {n m : ℕ} (program : OpeningProgram K P α H R n)
    (after : R → OpeningProgram K P α H T m) (table : Memo K α) (opened : Bool) :
    evalOpening p encode project secret (bindOpening program after) table opened =
      (evalOpening p encode project secret program table opened).bind fun out =>
        evalOpening p encode project secret (after out.value) out.cache out.opened := by
  induction program generalizing table opened with
  | done value => simp only [bindOpening, eval_opening_cast, eval_opening_reserve,
      evalOpening, PMF.pure_bind]
  | query key next ih => simp only [bindOpening, evalOpening, ih, PMF.bind_bind]
  | commit label next ih => simp only [bindOpening, evalOpening, ih, PMF.bind_bind]
  | reveal next ih => exact ih secret table true

theorem cast_query_done {n m : ℕ} (h : n = m) (value : R) :
    castProgram h (.done (K := K) (α := α) (n := n) value) = .done (n := m) value := by
  subst m
  rfl

theorem redact_opening_bind {n m : ℕ} (program : OpeningProgram K P α H R n)
    (after : R → OpeningProgram K P α H T m) :
    redactOpening (bindOpening program after) =
      bindProgram (redactOpening program) (fun out =>
        match out with | none => .done (n := m) none | some value => redactOpening (after value)) := by
  induction program with
  | done value => simp only [bindOpening, redact_opening_cast, redact_opening_reserve,
      redactOpening, bindProgram]
  | query key next ih => simp only [bindOpening, redactOpening, bindProgram, ih]
  | commit label next ih => simp only [bindOpening, redactOpening, bindProgram, ih]
  | reveal next ih => simp only [bindOpening, redactOpening, bindProgram,
      reserveProgram, cast_query_done]

theorem opening_selected_bind (select : Sum K P → Bool) {n m : ℕ}
    (program : OpeningProgram K P α H R n) (after : R → OpeningProgram K P α H T m)
    (q r : ℕ) (first : SelectedBudget select (redactOpening program) q)
    (later : ∀ value, SelectedBudget select (redactOpening (after value)) r) :
    SelectedBudget select (redactOpening (bindOpening program after)) (q + r) := by
  rw [redact_opening_bind]
  apply selectedBudget_bind select _ _ q r first
  intro value
  cases value with
  | none => trivial
  | some value => exact later value

def mapOpeningReturn (f : R → T) : {n : ℕ} → OpeningProgram K P α H R n →
    OpeningProgram K P α H T n
  | _, .done value => .done (f value)
  | _, .query key next => .query key (fun reply => mapOpeningReturn f (next reply))
  | _, .commit label next => .commit label (fun reply => mapOpeningReturn f (next reply))
  | _, .reveal next => .reveal (fun secret => mapOpeningReturn f (next secret))

theorem redact_opening_mapReturn (f : R → T) {n : ℕ}
    (program : OpeningProgram K P α H R n) :
    redactOpening (mapOpeningReturn f program) =
      mapReturnProgram (Option.map f) (redactOpening program) := by
  induction program with
  | done value => rfl
  | query key next ih => simp only [mapOpeningReturn, redactOpening, mapReturnProgram, ih]
  | commit label next ih => simp only [mapOpeningReturn, redactOpening, mapReturnProgram, ih]
  | reveal next ih => rfl

theorem eval_opening_mapReturn [DecidableEq K] (p : PMF α) (encode : S → P → K)
    (project : H → S) (secret : H) (f : R → T) {n : ℕ}
    (program : OpeningProgram K P α H R n) (table : Memo K α) (opened : Bool) :
    evalOpening p encode project secret (mapOpeningReturn f program) table opened =
      (evalOpening p encode project secret program table opened).map
        (fun out => (⟨f out.value, out.cache, out.opened⟩ : OpeningOutput K α T)) := by
  induction program generalizing table opened with
  | done value => simp only [mapOpeningReturn, evalOpening, PMF.pure_map]
  | query key next ih => simp only [mapOpeningReturn, evalOpening, ih, PMF.map_bind]
  | commit label next ih => simp only [mapOpeningReturn, evalOpening, ih, PMF.map_bind]
  | reveal next ih => exact ih secret table true

def liftOpening : {n : ℕ} → QueryProgram K α R n → OpeningProgram K P α H R n
  | _, .done value => .done value
  | _, .query key next => .query key (fun reply => liftOpening (next reply))

theorem eval_opening_lift [DecidableEq K] (p : PMF α) (encode : S → P → K)
    (project : H → S) (secret : H) {n : ℕ} (program : QueryProgram K α R n)
    (table : Memo K α) (opened : Bool) :
    evalOpening p encode project secret (liftOpening program) table opened =
      (evalProgram p program table).map
        (fun out => (⟨out.1, out.2, opened⟩ : OpeningOutput K α R)) := by
  induction program generalizing table with
  | done value => simp only [liftOpening, evalOpening, evalProgram, PMF.pure_map]
  | query key next ih => simp only [liftOpening, evalOpening, evalProgram, ih, PMF.map_bind]

theorem redact_opening_lift {n : ℕ} (program : QueryProgram K α R n) :
    redactOpening (liftOpening (P := P) (H := H) program) =
      mapReturnProgram some (mapProgram Sum.inl program) := by
  induction program with
  | done value => rfl
  | query key next ih => simp only [liftOpening, redactOpening, mapProgram, mapReturnProgram, ih]

end
end C10Probability

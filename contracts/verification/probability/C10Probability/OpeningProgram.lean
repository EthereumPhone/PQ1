import C10Probability.CommitmentGuess

/-! A finite commitment context may explicitly reveal the selected hidden
value. Its ordinary execution keeps running afterwards and retains the cache.
Redaction is an exact theorem about the unopened-result view only: a revealed
execution contributes no candidate to that view. -/
namespace C10Probability
noncomputable section

inductive OpeningProgram (K P α H R : Type*) : ℕ → Type _
  | done {n : ℕ} (value : R) : OpeningProgram K P α H R n
  | query {n : ℕ} (key : K) (next : α → OpeningProgram K P α H R n) :
      OpeningProgram K P α H R (n + 1)
  | commit {n : ℕ} (label : P) (next : α → OpeningProgram K P α H R n) :
      OpeningProgram K P α H R (n + 1)
  | reveal {n : ℕ} (next : H → OpeningProgram K P α H R n) :
      OpeningProgram K P α H R (n + 1)

structure OpeningOutput (K α R : Type*) where
  value : R
  cache : Memo K α
  opened : Bool

variable {K P α H S R : Type*}

def openingRetain (out : OpeningOutput K α R) : Option R :=
  if out.opened then none else some out.value

def evalOpening [DecidableEq K] (p : PMF α) (encode : S → P → K)
    (project : H → S) (secret : H) : {n : ℕ} → OpeningProgram K P α H R n →
      Memo K α → Bool → PMF (OpeningOutput K α R)
  | _, .done value, table, opened => PMF.pure ⟨value, table, opened⟩
  | _, .query key next, table, opened => (memoQuery p table key).bind fun reply =>
      evalOpening p encode project secret (next reply.1) reply.2 opened
  | _, .commit label next, table, opened =>
      (memoQuery p table (encode (project secret) label)).bind fun reply =>
        evalOpening p encode project secret (next reply.1) reply.2 opened
  | _, .reveal next, table, _ => evalOpening p encode project secret (next secret) table true

def redactOpening : {n : ℕ} → OpeningProgram K P α H R n →
    QueryProgram (Sum K P) α (Option R) n
  | _, .done value => .done (some value)
  | _, .query key next => .query (.inl key) (fun reply => redactOpening (next reply))
  | _, .commit label next => .query (.inr label) (fun reply => redactOpening (next reply))
  | _, .reveal _ => .done none

theorem eval_opening_revealed [DecidableEq K] (p : PMF α) (encode : S → P → K)
    (project : H → S) (secret : H) {n : ℕ} (program : OpeningProgram K P α H R n)
    (table : Memo K α) :
    (evalOpening p encode project secret program table true).map openingRetain = PMF.pure none := by
  induction program generalizing table with
  | done value => simp [evalOpening, PMF.pure_map, openingRetain]
  | query key next ih => simp only [evalOpening, PMF.map_bind, ih, PMF.bind_const]
  | commit label next ih => simp only [evalOpening, PMF.map_bind, ih, PMF.bind_const]
  | reveal next ih => exact ih secret table

theorem eval_opening_redaction [DecidableEq K] (p : PMF α) (encode : S → P → K)
    (project : H → S) (secret : H) {n : ℕ} (program : OpeningProgram K P α H R n)
    (table : Memo K α) :
    (evalOpening p encode project secret program table false).map openingRetain =
      (evalProgram p (mapProgram (privateKey encode (project secret))
        (redactOpening program)) table).map Prod.fst := by
  induction program generalizing table with
  | done value => simp [evalOpening, openingRetain, redactOpening, mapProgram,
      evalProgram, PMF.pure_map]
  | query key next ih =>
    simp only [evalOpening, redactOpening, mapProgram, privateKey, evalProgram, PMF.map_bind]
    congr 1
    funext reply
    exact ih reply.1 reply.2
  | commit label next ih =>
    simp only [evalOpening, redactOpening, mapProgram, privateKey, evalProgram, PMF.map_bind]
    congr 1
    funext reply
    exact ih reply.1 reply.2
  | reveal next ih =>
    simp only [evalOpening, eval_opening_revealed, redactOpening, mapProgram,
      evalProgram, PMF.pure_map]

theorem eval_opening_commit_cached [DecidableEq K] (p : PMF α) (encode : S → P → K)
    (project : H → S) (secret : H) {n : ℕ} (label : P)
    (next : α → OpeningProgram K P α H R n) (table : Memo K α) (opened : Bool)
    (value : α) (cached : table (encode (project secret) label) = some value) :
    evalOpening p encode project secret (.commit label next) table opened =
      evalOpening p encode project secret (next value) table opened := by
  simp only [evalOpening, memoQuery_cached p table _ value cached, PMF.pure_bind]

theorem eval_opening_reveal_continues [DecidableEq K] (p : PMF α) (encode : S → P → K)
    (project : H → S) (secret : H) {n : ℕ} (next : H → OpeningProgram K P α H R n)
    (table : Memo K α) (opened : Bool) :
    evalOpening p encode project secret (.reveal next) table opened =
      evalOpening p encode project secret (next secret) table true := by rfl

theorem redact_opening_reveal {n : ℕ} (next : H → OpeningProgram K P α H R n) :
    redactOpening (.reveal next) = .done (n := n + 1) none := by rfl

end
end C10Probability

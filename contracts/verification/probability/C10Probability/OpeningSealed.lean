import C10Probability.OpeningRefinement

/-! A sealed computation neither reads the selected private memo entry nor
reveals its value. Commitments remain permitted and retain their ordinary cache
behavior. This condition is structural, on every possible continuation. -/
namespace C10Probability
noncomputable section
variable {K P α H S R T L : Type*}

def OpeningSealed (target : K) : {n : ℕ} → OpeningProgram K P α H R n → Prop
  | _, .done _ => True
  | _, .query key next => key ≠ target ∧ ∀ reply, OpeningSealed target (next reply)
  | _, .commit _ next => ∀ reply, OpeningSealed target (next reply)
  | _, .reveal _ => False

theorem opening_sealed_avoids [DecidableEq K] (target : K) {n : ℕ}
    (program : OpeningProgram K P α H R n) (sealed : OpeningSealed target program) :
    OpeningAvoids target program := by
  induction program with
  | done value => trivial
  | query key next ih => exact ⟨sealed.1, fun reply => ih reply (sealed.2 reply)⟩
  | commit label next ih => exact fun reply => ih reply (sealed reply)
  | reveal next ih => exact sealed.elim

theorem opening_sealed_flag [DecidableEq K] (p : PMF α) (encode : S → P → K)
    (project : H → S) (secret : H) (target : K) {n : ℕ}
    (program : OpeningProgram K P α H R n) (sealed : OpeningSealed target program)
    (table : Memo K α) (opened : Bool) (out : OpeningOutput K α R)
    (supported : out ∈ (evalOpening p encode project secret program table opened).support) :
    out.opened = opened := by
  induction program generalizing table opened out with
  | done result =>
    have equal : out = ⟨result, table, opened⟩ := by simpa [evalOpening] using supported
    exact congrArg OpeningOutput.opened equal
  | query key next ih =>
    rw [evalOpening, PMF.mem_support_bind_iff] at supported
    obtain ⟨reply, _, supported⟩ := supported
    exact ih reply.1 (sealed.2 reply.1) reply.2 opened out supported
  | commit label next ih =>
    rw [evalOpening, PMF.mem_support_bind_iff] at supported
    obtain ⟨reply, _, supported⟩ := supported
    exact ih reply.1 (sealed reply.1) reply.2 opened out supported
  | reveal next ih => exact sealed.elim

theorem opening_sealed_cast (target : K) {n m : ℕ} (h : n = m)
    (program : OpeningProgram K P α H R n) :
    OpeningSealed target (castOpening h program) = OpeningSealed target program := by
  subst m
  rfl

theorem opening_sealed_reserve (target : K) (extra : ℕ) {n : ℕ}
    (program : OpeningProgram K P α H R n) :
    OpeningSealed target (reserveOpening extra program) = OpeningSealed target program := by
  induction program with
  | done value => rfl
  | query key next ih => simp only [reserveOpening, OpeningSealed, ih]
  | commit label next ih => simp only [reserveOpening, OpeningSealed, ih]
  | reveal next ih => rfl

theorem opening_sealed_bind (target : K) {n m : ℕ}
    (program : OpeningProgram K P α H R n) (after : R → OpeningProgram K P α H T m)
    (first : OpeningSealed target program) (later : ∀ value, OpeningSealed target (after value)) :
    OpeningSealed target (bindOpening program after) := by
  induction program with
  | done value =>
    simpa only [bindOpening, opening_sealed_cast, opening_sealed_reserve] using later value
  | query key next ih => exact ⟨first.1, fun reply => ih reply (first.2 reply)⟩
  | commit label next ih => exact fun reply => ih reply (first reply)
  | reveal next ih => exact first.elim

theorem opening_sealed_map (target : K) (f : R → T) {n : ℕ}
    (program : OpeningProgram K P α H R n) :
    OpeningSealed target (mapOpeningReturn f program) = OpeningSealed target program := by
  induction program with
  | done value => rfl
  | query key next ih => simp only [mapOpeningReturn, OpeningSealed, ih]
  | commit label next ih => simp only [mapOpeningReturn, OpeningSealed, ih]
  | reveal next ih => rfl

theorem opening_sealed_lift_mapped (target : K) (encode : L → K)
    (different : ∀ key, encode key ≠ target) {n : ℕ} (program : QueryProgram L α R n) :
    OpeningSealed target (liftOpening (P := P) (H := H) (mapProgram encode program)) := by
  induction program with
  | done value => trivial
  | query key next ih => exact ⟨different key, ih⟩

end
end C10Probability

import C10Probability.ForestFillOpening

/-! Structural result predicates for deferred computations. Every reply branch
is checked; support conclusions are derived from the evaluator, including all
memo hits. These predicates do not assume an independent returned transcript. -/
namespace C10Probability
noncomputable section
variable {K P α H U R S I : Type*}

def OpeningPost (post : R → Prop) : {n : ℕ} → OpeningProgram K P α H R n → Prop
  | _, .done value => post value
  | _, .query _ next => ∀ reply, OpeningPost post (next reply)
  | _, .commit _ next => ∀ reply, OpeningPost post (next reply)
  | _, .reveal next => ∀ secret, OpeningPost post (next secret)

theorem opening_post_support [DecidableEq K] (p : PMF α) (encode : U → P → K)
    (project : H → U) (secret : H) (post : R → Prop) {n : ℕ}
    (program : OpeningProgram K P α H R n) (valid : OpeningPost post program)
    (table : Memo K α) (opened : Bool) (out : OpeningOutput K α R)
    (supported : out ∈ (evalOpening p encode project secret program table opened).support) : post out.value := by
  induction program generalizing table opened out with
  | done value =>
    have equal : out = ⟨value, table, opened⟩ := by simpa [evalOpening] using supported
    simpa only [equal] using valid
  | query key next ih =>
    rw [evalOpening, PMF.mem_support_bind_iff] at supported
    obtain ⟨reply, _, supported⟩ := supported
    exact ih reply.1 (valid reply.1) reply.2 opened out supported
  | commit label next ih =>
    rw [evalOpening, PMF.mem_support_bind_iff] at supported
    obtain ⟨reply, _, supported⟩ := supported
    exact ih reply.1 (valid reply.1) reply.2 opened out supported
  | reveal next ih => exact ih secret (valid secret) table true out supported

theorem opening_post_constant (property : Prop) (valid : property) {n : ℕ}
    (program : OpeningProgram K P α H R n) : OpeningPost (fun _ => property) program := by
  induction program with
  | done value => exact valid
  | query key next ih => exact ih
  | commit label next ih => exact ih
  | reveal next ih => exact ih

theorem opening_post_cast (post : R → Prop) {n m : ℕ} (h : n = m)
    (program : OpeningProgram K P α H R n) :
    OpeningPost post (castOpening h program) = OpeningPost post program := by
  subst m
  rfl

theorem opening_post_reserve (post : R → Prop) (extra : ℕ) {n : ℕ}
    (program : OpeningProgram K P α H R n) :
    OpeningPost post (reserveOpening extra program) = OpeningPost post program := by
  induction program with
  | done value => rfl
  | query key next ih => simp only [reserveOpening, OpeningPost, ih]
  | commit label next ih => simp only [reserveOpening, OpeningPost, ih]
  | reveal next ih => simp only [reserveOpening, OpeningPost, ih]

theorem opening_post_map (post : S → Prop) (f : R → S) {n : ℕ}
    (program : OpeningProgram K P α H R n) :
    OpeningPost post (mapOpeningReturn f program) = OpeningPost (post ∘ f) program := by
  induction program with
  | done value => rfl
  | query key next ih => simp only [mapOpeningReturn, OpeningPost, ih]
  | commit label next ih => simp only [mapOpeningReturn, OpeningPost, ih]
  | reveal next ih => simp only [mapOpeningReturn, OpeningPost, ih]

theorem opening_post_bind (middle : R → Prop) (post : S → Prop) {n m : ℕ}
    (program : OpeningProgram K P α H R n) (after : R → OpeningProgram K P α H S m)
    (first : OpeningPost middle program) (later : ∀ value, middle value → OpeningPost post (after value)) :
    OpeningPost post (bindOpening program after) := by
  induction program with
  | done value =>
    simpa only [bindOpening, opening_post_cast, opening_post_reserve] using later value first
  | query key next ih => exact fun reply => ih reply (first reply)
  | commit label next ih => exact fun reply => ih reply (first reply)
  | reveal next ih => exact fun secret => ih secret (first secret)

theorem opening_post_fold (post : S → Prop) (cost : I → ℕ)
    (step : (i : I) → S → OpeningProgram K P α H S (cost i))
    (each : ∀ i state, post state → OpeningPost post (step i state))
    (indices : List I) (state : S) (valid : post state) :
    OpeningPost post (openingStateFold cost step indices state) := by
  induction indices generalizing state with
  | nil => exact valid
  | cons i rest ih =>
    rw [openingStateFold, opening_post_cast]
    exact opening_post_bind post post _ _ (each i state valid) ih

end
end C10Probability

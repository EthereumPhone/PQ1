import C10Probability.QueryMap

/-! Compose bounded clients while preserving the actual interpreter and cache.
The index is an upper bound, so unused allowance at an early return is harmless.
Reindexing below changes only a proved-equal natural-number index. -/
namespace C10Probability
noncomputable section

variable {K L P α R T : Type*}

def castProgram {n m : ℕ} (h : n = m) (program : QueryProgram K α R n) :
    QueryProgram K α R m := h ▸ program

theorem evalProgram_cast [DecidableEq K] (p : PMF α) {n m : ℕ} (h : n = m)
    (program : QueryProgram K α R n) (table : Memo K α) :
    evalProgram p (castProgram h program) table = evalProgram p program table := by
  subst m
  rfl

theorem publicBudget_cast {n m : ℕ} (h : n = m)
    (program : QueryProgram (Sum K P) α R n) (q : ℕ) :
    PublicBudget (castProgram h program) q = PublicBudget program q := by
  subst m
  rfl

theorem mapProgram_cast (encode : K → L) {n m : ℕ} (h : n = m)
    (program : QueryProgram K α R n) :
    mapProgram encode (castProgram h program) = castProgram h (mapProgram encode program) := by
  subst m
  rfl

def reserveProgram (extra : ℕ) : {n : ℕ} → QueryProgram K α R n →
    QueryProgram K α R (extra + n)
  | _, .done value => .done value
  | _, .query key next => .query key (fun reply => reserveProgram extra (next reply))

theorem evalProgram_reserve [DecidableEq K] (p : PMF α) (extra : ℕ) {n : ℕ}
    (program : QueryProgram K α R n) (table : Memo K α) :
    evalProgram p (reserveProgram extra program) table = evalProgram p program table := by
  induction program generalizing table with
  | done value => rfl
  | query key next ih =>
    simp only [reserveProgram, evalProgram]
    congr 1
    funext reply
    exact ih reply.1 reply.2

theorem publicBudget_reserve (extra : ℕ) {n : ℕ}
    (program : QueryProgram (Sum K P) α R n) (q : ℕ) :
    PublicBudget (reserveProgram extra program) q = PublicBudget program q := by
  induction program generalizing q with
  | done value => rfl
  | query key next ih =>
    cases key <;> simp only [reserveProgram, PublicBudget, ih]

theorem mapProgram_reserve (encode : K → L) (extra : ℕ) {n : ℕ}
    (program : QueryProgram K α R n) :
    mapProgram encode (reserveProgram extra program) =
      reserveProgram extra (mapProgram encode program) := by
  induction program with
  | done value => rfl
  | query key next ih =>
    simp only [reserveProgram, mapProgram]
    congr 1
    funext reply
    exact ih reply

def bindProgram {m : ℕ} : {n : ℕ} → QueryProgram K α R n →
    (R → QueryProgram K α T m) → QueryProgram K α T (m + n)
  | n, .done value, after =>
      castProgram (Nat.add_comm n m) (reserveProgram n (after value))
  | _, .query key next, after => .query key (fun reply => bindProgram (next reply) after)

theorem evalProgram_bind [DecidableEq K] (p : PMF α) {n m : ℕ}
    (program : QueryProgram K α R n) (after : R → QueryProgram K α T m)
    (table : Memo K α) :
    evalProgram p (bindProgram program after) table =
      (evalProgram p program table).bind (fun out => evalProgram p (after out.1) out.2) := by
  induction program generalizing table with
  | done value => simp [bindProgram, evalProgram_cast, evalProgram_reserve, evalProgram]
  | query key next ih =>
    simp only [bindProgram, evalProgram, PMF.bind_bind]
    congr 1
    funext reply
    exact ih reply.1 reply.2

theorem mapProgram_bind (encode : K → L) {n m : ℕ}
    (program : QueryProgram K α R n) (after : R → QueryProgram K α T m) :
    mapProgram encode (bindProgram program after) =
      bindProgram (mapProgram encode program) (fun value => mapProgram encode (after value)) := by
  induction program with
  | done value => simp only [bindProgram, mapProgram, mapProgram_cast, mapProgram_reserve]
  | query key next ih =>
    simp only [bindProgram, mapProgram]
    congr 1
    funext reply
    exact ih reply

theorem publicBudget_bind {n m : ℕ} (program : QueryProgram (Sum K P) α R n)
    (after : R → QueryProgram (Sum K P) α T m) (q r : ℕ)
    (first : PublicBudget program q) (later : ∀ value, PublicBudget (after value) r) :
    PublicBudget (bindProgram program after) (q + r) := by
  induction program generalizing q with
  | @done n value =>
    simpa only [bindProgram, publicBudget_cast, publicBudget_reserve] using
      publicBudget_mono (after value) (show r ≤ q + r by omega) (later value)
  | query key next ih =>
    cases key with
    | inl key =>
      obtain ⟨hq, hb⟩ := first
      refine ⟨by omega, fun reply => ?_⟩
      have h := ih reply (q - 1) (hb reply)
      simpa only [show q - 1 + r = q + r - 1 by omega] using h
    | inr tail => exact fun reply => ih reply q (first reply)

end
end C10Probability

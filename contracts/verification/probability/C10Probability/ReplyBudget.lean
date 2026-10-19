import C10Probability.SelectedComposition
import C10Probability.HmsgPool

/-! Reply-dependent budgets charge calls even on cache hits. They therefore
bound fresh accepted entries without requiring an independence assumption. -/
namespace C10Probability
noncomputable section
variable {K α R T : Type*}

def ReplyBudget (charge : K → α → Bool) : {n : ℕ} → QueryProgram K α R n → ℕ → Prop
  | _, .done _, _ => True
  | _, .query key next, q => ∀ reply, if charge key reply then
      0 < q ∧ ReplyBudget charge (next reply) (q - 1)
    else ReplyBudget charge (next reply) q

theorem replyBudget_mono (charge : K → α → Bool) {n : ℕ}
    (program : QueryProgram K α R n) {q larger : ℕ} (hle : q ≤ larger)
    (budget : ReplyBudget charge program q) : ReplyBudget charge program larger := by
  induction program generalizing q larger with
  | done value => trivial
  | query key next ih =>
    intro reply
    have hb := budget reply
    cases hc : charge key reply <;> simp only [hc, Bool.false_eq_true, ↓reduceIte] at hb ⊢
    · exact ih reply hle hb
    · exact ⟨lt_of_lt_of_le hb.1 hle, ih reply (Nat.sub_le_sub_right hle 1) hb.2⟩

theorem replyBudget_query (charge : K → α → Bool) {n : ℕ} (key : K)
    (next : α → QueryProgram K α R n) (q : ℕ)
    (budget : ∀ reply, ReplyBudget charge (next reply) q) :
    ReplyBudget charge (.query key next) (q + 1) := by
  intro reply
  cases charge key reply <;> simp only [Bool.false_eq_true, ↓reduceIte]
  · exact replyBudget_mono charge (next reply) (Nat.le_succ q) (budget reply)
  · simpa only [Nat.add_sub_cancel] using And.intro (Nat.zero_lt_succ q) (budget reply)

theorem replyBudget_of_selected (select : K → Bool) (charge : K → α → Bool)
    (dominated : ∀ key reply, charge key reply = true → select key = true)
    {n : ℕ} (program : QueryProgram K α R n) (q : ℕ)
    (budget : SelectedBudget select program q) : ReplyBudget charge program q := by
  induction program generalizing q with
  | done value => trivial
  | query key next ih =>
    intro reply
    cases hs : select key <;> simp only [SelectedBudget, hs, Bool.false_eq_true,
      ↓reduceIte] at budget
    · have hc : charge key reply = false := by
        cases h : charge key reply
        · rfl
        · have := dominated key reply h
          simp [hs] at this
      simp only [hc, Bool.false_eq_true, ↓reduceIte]
      exact ih reply q (budget reply)
    · cases charge key reply <;> simp only [Bool.false_eq_true, ↓reduceIte]
      · exact replyBudget_mono charge _ (Nat.sub_le q 1) (ih reply (q - 1) (budget.2 reply))
      · exact ⟨budget.1, ih reply (q - 1) (budget.2 reply)⟩

theorem replyBudget_cast (charge : K → α → Bool) {n m : ℕ} (h : n = m)
    (program : QueryProgram K α R n) (q : ℕ) :
    ReplyBudget charge (castProgram h program) q = ReplyBudget charge program q := by
  subst m
  rfl

theorem replyBudget_reserve (charge : K → α → Bool) (extra : ℕ) {n : ℕ}
    (program : QueryProgram K α R n) (q : ℕ) :
    ReplyBudget charge (reserveProgram extra program) q = ReplyBudget charge program q := by
  induction program generalizing q with
  | done value => rfl
  | query key next ih => simp only [reserveProgram, ReplyBudget, ih]

theorem replyBudget_bind (charge : K → α → Bool) {n m : ℕ}
    (program : QueryProgram K α R n) (after : R → QueryProgram K α T m) (q r : ℕ)
    (first : ReplyBudget charge program q)
    (later : ∀ value, ReplyBudget charge (after value) r) :
    ReplyBudget charge (bindProgram program after) (q + r) := by
  induction program generalizing q with
  | @done n value =>
    simpa only [bindProgram, replyBudget_cast, replyBudget_reserve] using
      replyBudget_mono charge (after value) (show r ≤ q + r by omega) (later value)
  | query key next ih =>
    intro reply
    have hb := first reply
    cases hc : charge key reply <;> simp only [hc, Bool.false_eq_true, ↓reduceIte] at hb ⊢
    · exact ih reply q hb
    · refine ⟨by omega, ?_⟩
      simpa only [show q - 1 + r = q + r - 1 by omega] using ih reply (q - 1) hb.2

theorem replyBudget_mapReturn (charge : K → α → Bool) (f : R → T) {n : ℕ}
    (program : QueryProgram K α R n) (q : ℕ) :
    ReplyBudget charge (mapReturnProgram f program) q = ReplyBudget charge program q := by
  induction program generalizing q with
  | done value => rfl
  | query key next ih => simp only [mapReturnProgram, ReplyBudget, ih]

def hmsgReplyCharge (select : K → Bool) (key : K) (value : Digest) : Bool :=
  select key && forsAccept (forsOfDigest value)

theorem hmsg_pool_length [DecidableEq K] (select : K → Bool) {n : ℕ}
    (program : QueryProgram K Digest R n) (q : ℕ)
    (budget : ReplyBudget (hmsgReplyCharge select) program q) (table : Memo K Digest)
    (out : HmsgPoolOutput K R) (supported : out ∈ (hmsgPoolProgram select program table).support) :
    out.entries.length ≤ q := by
  induction program generalizing q table out with
  | done value =>
    have he : out = ⟨value, table, []⟩ := by simpa [hmsgPoolProgram] using supported
    simp [he]
  | query key next ih =>
    cases cached : table key with
    | some value =>
      rw [hmsg_pool_program_cached select key next table value cached] at supported
      have hb := budget value
      cases hc : hmsgReplyCharge select key value <;>
        simp only [hc, Bool.false_eq_true, ↓reduceIte] at hb
      · exact ih value q hb table out supported
      · exact (ih value (q - 1) hb.2 table out supported).trans (Nat.sub_le q 1)
    | none =>
      rw [hmsg_pool_program_fresh select key next table cached, PMF.mem_support_bind_iff] at supported
      obtain ⟨value, _, supported⟩ := supported
      rw [PMF.mem_support_map_iff] at supported
      obtain ⟨tail, ht, rfl⟩ := supported
      have hb := budget value
      cases hc : hmsgReplyCharge select key value <;>
        simp only [hc, Bool.false_eq_true, ↓reduceIte] at hb
      · simp only [hmsgReplyCharge] at hc
        simpa only [hmsgPoolPrepend, hc, Bool.false_eq_true, ↓reduceIte] using
          ih value q hb (Function.update table key (some value)) tail ht
      · have h := ih value (q - 1) hb.2 (Function.update table key (some value)) tail ht
        simp only [hmsgReplyCharge] at hc
        simp only [hmsgPoolPrepend, hc, ↓reduceIte, List.length_cons]
        omega

end
end C10Probability

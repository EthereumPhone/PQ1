import C10Probability.ProgramComposition

/-! A fixed input-domain budget counts selected calls on every continuation,
including cached calls. The interpreter and its total-call index are unchanged. -/
namespace C10Probability
noncomputable section

variable {K α R : Type*}

def SelectedBudget (select : K → Bool) : {n : ℕ} → QueryProgram K α R n → ℕ → Prop
  | _, .done _, _ => True
  | _, .query key next, q => if select key then
      0 < q ∧ ∀ reply, SelectedBudget select (next reply) (q - 1)
    else ∀ reply, SelectedBudget select (next reply) q

theorem selectedBudget_mono (select : K → Bool) {n : ℕ}
    (program : QueryProgram K α R n) {q larger : ℕ} (hle : q ≤ larger)
    (budget : SelectedBudget select program q) : SelectedBudget select program larger := by
  induction program generalizing q larger with
  | done value => trivial
  | query key next ih =>
    cases hs : select key <;> simp only [SelectedBudget, hs, Bool.false_eq_true,
      ↓reduceIte] at budget ⊢
    · exact fun reply => ih reply hle (budget reply)
    · exact ⟨lt_of_lt_of_le budget.1 hle,
        fun reply => ih reply (Nat.sub_le_sub_right hle 1) (budget.2 reply)⟩

theorem selectedBudget_query (select : K → Bool) {n : ℕ} (key : K)
    (next : α → QueryProgram K α R n) (q : ℕ)
    (budget : ∀ reply, SelectedBudget select (next reply) q) :
    SelectedBudget select (.query key next) (q + 1) := by
  cases hs : select key <;> simp only [SelectedBudget, hs, Bool.false_eq_true, ↓reduceIte]
  · exact fun reply => selectedBudget_mono select (next reply) (Nat.le_succ q) (budget reply)
  · simpa only [Nat.add_sub_cancel] using And.intro (Nat.zero_lt_succ q) budget

theorem selectedBudget_total (select : K → Bool) {n : ℕ}
    (program : QueryProgram K α R n) : SelectedBudget select program n := by
  induction program with
  | done value => trivial
  | query key next ih => exact selectedBudget_query select key next _ ih

theorem selectedBudget_cast (select : K → Bool) {n m : ℕ} (h : n = m)
    (program : QueryProgram K α R n) (q : ℕ) :
    SelectedBudget select (castProgram h program) q = SelectedBudget select program q := by
  subst m
  rfl

theorem traceProgram_selected_length [DecidableEq K] (p : PMF α) (select : K → Bool)
    {n : ℕ} (program : QueryProgram K α R n) (q : ℕ)
    (budget : SelectedBudget select program q) (table : Memo K α)
    (out : TraceOutput K α R) (ho : out ∈ (traceProgram p program table).support) :
    (out.queries.filter select).length ≤ q := by
  induction program generalizing q table out with
  | done value =>
    have he : out = ⟨value, table, []⟩ := by simpa [traceProgram] using ho
    simp [he]
  | query key next ih =>
    rw [traceProgram, PMF.mem_support_bind_iff] at ho
    obtain ⟨reply, _, ho⟩ := ho
    rw [PMF.mem_support_map_iff] at ho
    obtain ⟨rest, hr, rfl⟩ := ho
    cases hs : select key <;> simp only [SelectedBudget, hs, Bool.false_eq_true,
      ↓reduceIte] at budget
    · simpa [hs] using ih reply.1 q (budget reply.1) reply.2 rest hr
    · have h := ih reply.1 (q - 1) (budget.2 reply.1) reply.2 rest hr
      simp only [List.filter_cons, hs, ↓reduceIte, List.length_cons]
      omega

theorem randomizedTrace_selected_length [DecidableEq K] (p : PMF α) (select : K → Bool)
    {n : ℕ} (client : PMF (QueryProgram K α R n)) (q : ℕ)
    (budget : ∀ program ∈ client.support, SelectedBudget select program q)
    (table : Memo K α) (out : TraceOutput K α R)
    (ho : out ∈ (randomizedTrace p client table).support) :
    (out.queries.filter select).length ≤ q := by
  rw [randomizedTrace, PMF.mem_support_bind_iff] at ho
  obtain ⟨program, hp, ho⟩ := ho
  exact traceProgram_selected_length p select program q (budget program hp) table out ho

end
end C10Probability

import C10Probability.QueryTrace

/-! Relabel the oracle inputs of the existing adaptive interpreter. The client
still receives the actual reply, and every continuation retains the original
worst-case total-call index. A separate structural bound counts public calls;
private calls consume the total index but not this public budget. -/
namespace C10Probability
noncomputable section

variable {K L P α R : Type*}

def mapProgram (encode : K → L) : {n : ℕ} → QueryProgram K α R n →
    QueryProgram L α R n
  | _, .done value => .done value
  | _, .query key next => .query (encode key) (fun reply => mapProgram encode (next reply))

theorem mapProgram_id {n : ℕ} (program : QueryProgram K α R n) :
    mapProgram id program = program := by
  induction program with
  | done value => rfl
  | query key next ih =>
    simp only [mapProgram, id_eq]
    congr 1
    funext reply
    exact ih reply

theorem mapProgram_comp {T : Type*} (first : K → L) (second : L → T) {n : ℕ}
    (program : QueryProgram K α R n) :
    mapProgram second (mapProgram first program) = mapProgram (second ∘ first) program := by
  induction program with
  | done value => rfl
  | query key next ih =>
    simp only [mapProgram, Function.comp_apply]
    congr 1
    funext reply
    exact ih reply

def publicQueries (queries : List (Sum K P)) : List K :=
  queries.filterMap (fun key => match key with | .inl key => some key | .inr _ => none)

def PublicBudget : {n : ℕ} → QueryProgram (Sum K P) α R n → ℕ → Prop
  | _, .done _, _ => True
  | _, .query (.inl _) next, q => 0 < q ∧ ∀ reply, PublicBudget (next reply) (q - 1)
  | _, .query (.inr _) next, q => ∀ reply, PublicBudget (next reply) q

theorem publicBudget_mono {n : ℕ} (program : QueryProgram (Sum K P) α R n)
    {q larger : ℕ} (hle : q ≤ larger) (budget : PublicBudget program q) :
    PublicBudget program larger := by
  induction program generalizing q larger with
  | done value => trivial
  | query key next ih =>
    cases key with
    | inl key =>
      obtain ⟨hq, hb⟩ := budget
      exact ⟨lt_of_lt_of_le hq hle,
        fun reply => ih reply (Nat.sub_le_sub_right hle 1) (hb reply)⟩
    | inr tail => exact fun reply => ih reply hle (budget reply)

theorem publicBudget_total {n : ℕ} (program : QueryProgram (Sum K P) α R n) :
    PublicBudget program n := by
  induction program with
  | done value => trivial
  | @query n key next ih =>
    cases key with
    | inl key => simpa [PublicBudget] using ih
    | inr tail => exact fun reply => publicBudget_mono (next reply) (by omega) (ih reply)

theorem traceProgram_public_length [DecidableEq K] [DecidableEq P] (p : PMF α)
    {n : ℕ} (program : QueryProgram (Sum K P) α R n) (q : ℕ)
    (budget : PublicBudget program q) (table : Memo (Sum K P) α)
    (out : TraceOutput (Sum K P) α R)
    (ho : out ∈ (traceProgram p program table).support) :
    (publicQueries out.queries).length ≤ q := by
  induction program generalizing q table out with
  | done value =>
    have he : out = ⟨value, table, []⟩ := by simpa [traceProgram] using ho
    simp [he, publicQueries]
  | query key next ih =>
    rw [traceProgram, PMF.mem_support_bind_iff] at ho
    obtain ⟨reply, _, ho⟩ := ho
    rw [PMF.mem_support_map_iff] at ho
    obtain ⟨rest, hr, rfl⟩ := ho
    cases key with
    | inl key =>
      obtain ⟨hq, hb⟩ := budget
      have h := ih reply.1 (q - 1) (hb reply.1) reply.2 rest hr
      simp only [publicQueries, List.filterMap_cons, List.length_cons] at h ⊢
      omega
    | inr tail =>
      simpa [publicQueries] using ih reply.1 q (budget reply.1) reply.2 rest hr

theorem randomizedTrace_public_length [DecidableEq K] [DecidableEq P] (p : PMF α)
    {n : ℕ} (client : PMF (QueryProgram (Sum K P) α R n)) (q : ℕ)
    (budget : ∀ program ∈ client.support, PublicBudget program q)
    (table : Memo (Sum K P) α) (out : TraceOutput (Sum K P) α R)
    (ho : out ∈ (randomizedTrace p client table).support) :
    (publicQueries out.queries).length ≤ q := by
  rw [randomizedTrace, PMF.mem_support_bind_iff] at ho
  obtain ⟨program, hp, ho⟩ := ho
  exact traceProgram_public_length p program q (budget program hp) table out ho

end
end C10Probability

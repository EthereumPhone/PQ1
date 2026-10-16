import C10Probability.QueryProgram

/-! The actual public query trace of a bounded adaptive client. Observers are
not visible to the client. Cached calls are retained in the trace and count
toward the worst-case budget, even though they do not draw a fresh reply. -/
namespace C10Probability
noncomputable section

structure TraceOutput (K α R : Type*) where
  value : R
  cache : Memo K α
  queries : List K

variable {K α R : Type*} [DecidableEq K]

def traceProgram (p : PMF α) : {n : ℕ} → QueryProgram K α R n →
    Memo K α → PMF (TraceOutput K α R)
  | _, .done value, table => PMF.pure ⟨value, table, []⟩
  | _, .query key next, table => (memoQuery p table key).bind fun out =>
      (traceProgram p (next out.1) out.2).map fun rest =>
        ⟨rest.value, rest.cache, key :: rest.queries⟩

def randomizedTrace (p : PMF α) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (table : Memo K α) : PMF (TraceOutput K α R) :=
  client.bind fun program => traceProgram p program table

theorem traceProgram_done (p : PMF α) (n : ℕ) (value : R) (table : Memo K α) :
    traceProgram p (.done (n := n) value) table = PMF.pure ⟨value, table, []⟩ := by rfl

theorem traceProgram_erases (p : PMF α) {n : ℕ} (program : QueryProgram K α R n)
    (table : Memo K α) :
    (traceProgram p program table).map (fun out => (out.value, out.cache)) =
      evalProgram p program table := by
  induction program generalizing table with
  | done value => simp [traceProgram, evalProgram, PMF.pure_map]
  | query key next ih =>
    simp only [traceProgram, evalProgram, PMF.map_bind, PMF.map_comp, Function.comp_def]
    congr 1
    funext out
    exact ih out.1 out.2

theorem traceProgram_length (p : PMF α) {n : ℕ} (program : QueryProgram K α R n)
    (table : Memo K α) (out : TraceOutput K α R)
    (ho : out ∈ (traceProgram p program table).support) : out.queries.length ≤ n := by
  induction program generalizing table out with
  | done value =>
    have he : out = ⟨value, table, []⟩ := by simpa [traceProgram] using ho
    simp [he]
  | query key next ih =>
    rw [traceProgram, PMF.mem_support_bind_iff] at ho
    obtain ⟨reply, _, ho⟩ := ho
    rw [PMF.mem_support_map_iff] at ho
    obtain ⟨rest, hr, rfl⟩ := ho
    simpa using Nat.succ_le_succ (ih reply.1 reply.2 rest hr)

theorem memoQuery_origin (p : PMF α) (table : Memo K α) (key other : K) (value : α)
    (out : α × Memo K α) (ho : out ∈ (memoQuery p table key).support)
    (hc : out.2 other = some value) : table other = some value ∨ other = key := by
  cases ht : table key with
  | none =>
    rw [memoQuery, ht, PMF.mem_support_map_iff] at ho
    obtain ⟨reply, _, rfl⟩ := ho
    by_cases he : other = key
    · exact Or.inr he
    · exact Or.inl (by simpa [he] using hc)
  | some reply =>
    have he : out = (reply, table) := by simpa [memoQuery, ht] using ho
    exact Or.inl (by simpa [he] using hc)

theorem traceProgram_origin (p : PMF α) {n : ℕ} (program : QueryProgram K α R n)
    (table : Memo K α) (out : TraceOutput K α R)
    (ho : out ∈ (traceProgram p program table).support) (key : K) (value : α)
    (hc : out.cache key = some value) : table key = some value ∨ key ∈ out.queries := by
  induction program generalizing table out with
  | done result =>
    have he : out = ⟨result, table, []⟩ := by simpa [traceProgram] using ho
    exact Or.inl (by simpa [he] using hc)
  | query first next ih =>
    rw [traceProgram, PMF.mem_support_bind_iff] at ho
    obtain ⟨reply, hreply, ho⟩ := ho
    rw [PMF.mem_support_map_iff] at ho
    obtain ⟨rest, hr, rfl⟩ := ho
    rcases ih reply.1 reply.2 rest hr hc with hcache | hmem
    · rcases memoQuery_origin p table first key value reply hreply hcache with hbase | he
      · exact Or.inl hbase
      · exact Or.inr (by simp [he])
    · exact Or.inr (by simp [hmem])

theorem traceProgram_empty_covered (p : PMF α) {n : ℕ}
    (program : QueryProgram K α R n) (out : TraceOutput K α R)
    (ho : out ∈ (traceProgram p program (fun _ => none)).support) (key : K) (value : α)
    (hc : out.cache key = some value) : key ∈ out.queries := by
  simpa using traceProgram_origin p program (fun _ => none) out ho key value hc

theorem randomizedTrace_erases (p : PMF α) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (table : Memo K α) :
    (randomizedTrace p client table).map (fun out => (out.value, out.cache)) =
      randomizedProgram p client table := by
  simp only [randomizedTrace, randomizedProgram, PMF.map_bind, traceProgram_erases]

theorem randomizedTrace_length (p : PMF α) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (table : Memo K α) (out : TraceOutput K α R)
    (ho : out ∈ (randomizedTrace p client table).support) : out.queries.length ≤ n := by
  rw [randomizedTrace, PMF.mem_support_bind_iff] at ho
  obtain ⟨program, _, hp⟩ := ho
  exact traceProgram_length p program table out hp

theorem randomizedTrace_empty_covered (p : PMF α) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (out : TraceOutput K α R)
    (ho : out ∈ (randomizedTrace p client (fun _ => none)).support) (key : K) (value : α)
    (hc : out.cache key = some value) : key ∈ out.queries := by
  rw [randomizedTrace, PMF.mem_support_bind_iff] at ho
  obtain ⟨program, _, hp⟩ := ho
  exact traceProgram_empty_covered p program out hp key value hc

end
end C10Probability

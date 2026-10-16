import C10Probability.SelectedComposition

/-! A reply-dependent chain retains the whole memo table between steps. Its
split law is an equality of complete executions, not independent sampling. -/
namespace C10Probability
noncomputable section

variable {K α N : Type*}

def chainProgram (input : ℕ → N → K) (project : α → N) (start : ℕ) :
    (steps : ℕ) → N → QueryProgram K α N steps
  | 0, current => .done current
  | steps + 1, current => .query (input start current) (fun reply =>
      chainProgram input project (start + 1) steps (project reply))

def chainLoop [DecidableEq K] (p : PMF α) (input : ℕ → N → K) (project : α → N)
    (start : ℕ) : ℕ → N → Memo K α → PMF (N × Memo K α)
  | 0, current, table => PMF.pure (current, table)
  | steps + 1, current, table => (memoQuery p table (input start current)).bind
      (fun reply => chainLoop p input project (start + 1) steps (project reply.1) reply.2)

theorem evalProgram_chain [DecidableEq K] (p : PMF α) (input : ℕ → N → K)
    (project : α → N) (start steps : ℕ) (current : N) (table : Memo K α) :
    evalProgram p (chainProgram input project start steps current) table =
      chainLoop p input project start steps current table := by
  induction steps generalizing start current table with
  | zero => rfl
  | succ steps ih =>
    simp only [chainProgram, evalProgram, chainLoop]
    congr 1
    funext reply
    exact ih (start + 1) (project reply.1) reply.2

theorem chainLoop_split [DecidableEq K] (p : PMF α) (input : ℕ → N → K)
    (project : α → N) (start first later : ℕ) (current : N) (table : Memo K α) :
    chainLoop p input project start (first + later) current table =
      (chainLoop p input project start first current table).bind (fun out =>
        chainLoop p input project (start + first) later out.1 out.2) := by
  induction first generalizing start current table with
  | zero => simp [chainLoop]
  | succ first ih =>
    simp only [Nat.succ_add, chainLoop, PMF.bind_bind]
    congr 1
    funext reply
    simpa only [Nat.add_assoc, Nat.add_left_comm, Nat.add_comm] using
      ih (start + 1) (project reply.1) reply.2

theorem traceProgram_chain_length [DecidableEq K] (p : PMF α) (input : ℕ → N → K)
    (project : α → N) (start steps : ℕ) (current : N) (table : Memo K α)
    (out : TraceOutput K α N)
    (ho : out ∈ (traceProgram p (chainProgram input project start steps current) table).support) :
    out.queries.length = steps := by
  induction steps generalizing start current table out with
  | zero =>
    have he : out = ⟨current, table, []⟩ := by simpa [chainProgram, traceProgram] using ho
    simp [he]
  | succ steps ih =>
    rw [chainProgram, traceProgram, PMF.mem_support_bind_iff] at ho
    obtain ⟨reply, _, ho⟩ := ho
    rw [PMF.mem_support_map_iff] at ho
    obtain ⟨rest, hr, rfl⟩ := ho
    simpa using ih (start + 1) (project reply.1) reply.2 rest hr

theorem traceProgram_chain_selected [DecidableEq K] (p : PMF α) (input : ℕ → N → K)
    (project : α → N) (select : K → Bool) (allSelected : ∀ pos current, select (input pos current) = true)
    (start steps : ℕ) (current : N) (table : Memo K α) (out : TraceOutput K α N)
    (ho : out ∈ (traceProgram p (chainProgram input project start steps current) table).support) :
    (out.queries.filter select).length = steps := by
  induction steps generalizing start current table out with
  | zero =>
    have he : out = ⟨current, table, []⟩ := by simpa [chainProgram, traceProgram] using ho
    simp [he]
  | succ steps ih =>
    rw [chainProgram, traceProgram, PMF.mem_support_bind_iff] at ho
    obtain ⟨reply, _, ho⟩ := ho
    rw [PMF.mem_support_map_iff] at ho
    obtain ⟨rest, hr, rfl⟩ := ho
    simpa [allSelected] using ih (start + 1) (project reply.1) reply.2 rest hr

end
end C10Probability

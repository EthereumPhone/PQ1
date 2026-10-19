import C10Probability.WotsSigningDisclosure

/-! Passive query recording compiled into the same adaptive query program.
Recording preserves replies, order, repeated calls and the complete cache.
It is used only for raw adversary and final-verifier queries. -/
namespace C10Probability
noncomputable section
variable {K P α R T S : Type*}

def probeProgram : {n : ℕ} → QueryProgram K α R n → QueryProgram K α (R × List K) n
  | _, .done value => .done (value, [])
  | _, .query key next => .query key (fun reply =>
      mapReturnProgram (fun out => (out.1, key :: out.2)) (probeProgram (next reply)))

theorem probe_program_eval [DecidableEq K] (p : PMF α) {n : ℕ}
    (program : QueryProgram K α R n) (table : Memo K α) :
    evalProgram p (probeProgram program) table =
      (traceProgram p program table).map (fun out => ((out.value, out.queries), out.cache)) := by
  induction program generalizing table with
  | done value => simp only [probeProgram, evalProgram, traceProgram, PMF.pure_map]
  | query key next ih =>
    simp only [probeProgram, evalProgram, evalProgram_mapReturn, ih, PMF.map_comp,
      traceProgram, PMF.map_bind, Function.comp_def]

theorem probe_program_erases [DecidableEq K] (p : PMF α) {n : ℕ}
    (program : QueryProgram K α R n) (table : Memo K α) :
    (evalProgram p (probeProgram program) table).map (fun out => (out.1.1, out.2)) =
      evalProgram p program table := by
  rw [probe_program_eval, PMF.map_comp]
  exact traceProgram_erases p program table

theorem probe_program_length [DecidableEq K] (p : PMF α) {n : ℕ}
    (program : QueryProgram K α R n) (table : Memo K α) (out : (R × List K) × Memo K α)
    (supported : out ∈ (evalProgram p (probeProgram program) table).support) : out.1.2.length ≤ n := by
  rw [probe_program_eval, PMF.mem_support_map_iff] at supported
  obtain ⟨trace, traced, rfl⟩ := supported
  exact traceProgram_length p program table trace traced

theorem probe_program_selected (select : K → Bool) {n : ℕ}
    (program : QueryProgram K α R n) (q : ℕ) (budget : SelectedBudget select program q) :
    SelectedBudget select (probeProgram program) q := by
  induction program generalizing q with
  | done value => trivial
  | query key next ih =>
    cases chosen : select key <;>
      simp only [probeProgram, SelectedBudget, chosen, Bool.false_eq_true, ↓reduceIte,
        selectedBudget_mapReturn] at budget ⊢
    · exact fun reply => ih reply q (budget reply)
    · exact ⟨budget.1, fun reply => ih reply (q - 1) (budget.2 reply)⟩

theorem reveal_lift_map_return [DecidableEq K] (target : K) (f : R → T) {n : ℕ}
    (program : QueryProgram K α R n) :
    revealLift (P := P) target (mapReturnProgram f program) =
      mapOpeningReturn f (revealLift target program) := by
  induction program with
  | done value => rfl
  | query key next ih =>
    by_cases equal : key = target <;>
      simp only [mapReturnProgram, revealLift, equal, ↓reduceIte, mapOpeningReturn, ih]

theorem reveal_lift_refines [DecidableEq K] (p : PMF α) (encode : S → P → K)
    (project : α → S) (target : K) (secret : α) {n : ℕ} (program : QueryProgram K α R n) :
    OpeningRefines p encode project target secret id (revealLift target program) program := by
  intro table opened cached
  exact eval_reveal_lift p encode project secret target program table opened cached

theorem reveal_probe_opened [DecidableEq K] (p : PMF α) (encode : S → P → K)
    (project : α → S) (target : K) (secret : α) {n : ℕ} (program : QueryProgram K α R n)
    (table : Memo K α) (out : OpeningOutput K α (R × List K))
    (supported : out ∈ (evalOpening p encode project secret
      (revealLift target (probeProgram program)) table false).support) (opened : out.opened = true) :
    target ∈ out.value.2 := by
  induction program generalizing table out with
  | done value =>
    have equal : out = ⟨(value, []), table, false⟩ := by
      simpa only [probeProgram, revealLift, evalOpening, PMF.mem_support_pure_iff] using supported
    simp only [equal, Bool.false_eq_true] at opened
  | query key next ih =>
    by_cases equal : key = target
    · subst key
      rw [probeProgram, revealLift, if_pos rfl, evalOpening, reveal_lift_map_return,
        eval_opening_mapReturn, PMF.mem_support_map_iff] at supported
      obtain ⟨rest, _, rfl⟩ := supported
      exact List.mem_cons_self
    · rw [probeProgram, revealLift, if_neg equal, evalOpening, PMF.mem_support_bind_iff] at supported
      obtain ⟨reply, _, supported⟩ := supported
      rw [reveal_lift_map_return, eval_opening_mapReturn, PMF.mem_support_map_iff] at supported
      obtain ⟨rest, restSupport, rfl⟩ := supported
      exact List.mem_cons_of_mem key (ih reply.1 reply.2 rest restSupport opened)

end
end C10Probability

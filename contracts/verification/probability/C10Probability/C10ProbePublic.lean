import C10Probability.C10Probes

/-! The passive probes contain only public-interface calls. In particular,
the cut-zero private seed cannot be revealed by raw or final-verifier probes.
This fact follows from the actual compiled verifier and observer. -/
namespace C10Probability
noncomputable section

theorem query_exclusion_all {K α R : Type*} (select : K → Bool)
    (never : ∀ key, select key = false) {n : ℕ} (program : QueryProgram K α R n) :
    QueryExclusion select (fun _ => True) program := by
  induction program with
  | done value => trivial
  | query key next ih => exact ⟨never key, ih⟩

theorem trace_program_excluded {K α R : Type*} [DecidableEq K] (p : PMF α)
    (select : K → Bool) (post : R → Prop) {n : ℕ} (program : QueryProgram K α R n)
    (excluded : QueryExclusion select post program) (table : Memo K α)
    (out : TraceOutput K α R) (supported : out ∈ (traceProgram p program table).support) :
    ∀ key ∈ out.queries, select key = false := by
  induction program generalizing table out with
  | done value =>
    have equal : out = ⟨value, table, []⟩ := by
      simpa only [traceProgram, PMF.mem_support_pure_iff] using supported
    simp only [equal, List.not_mem_nil, false_implies, implies_true]
  | query first next ih =>
    rw [traceProgram, PMF.mem_support_bind_iff] at supported
    obtain ⟨reply, _, supported⟩ := supported
    rw [PMF.mem_support_map_iff] at supported
    obtain ⟨rest, restSupport, rfl⟩ := supported
    intro key member
    rcases List.mem_cons.mp member with same | later
    · simpa only [same] using excluded.1
    · exact ih reply.1 (excluded.2 reply.1) reply.2 rest restSupport key later

theorem probe_program_excluded {K α R : Type*} [DecidableEq K] (p : PMF α)
    (select : K → Bool) (post : R → Prop) {n : ℕ} (program : QueryProgram K α R n)
    (excluded : QueryExclusion select post program) (table : Memo K α)
    (out : (R × List K) × Memo K α) (supported : out ∈ (evalProgram p (probeProgram program) table).support) :
    ∀ key ∈ out.1.2, select key = false := by
  rw [probe_program_eval, PMF.mem_support_map_iff] at supported
  obtain ⟨trace, traceSupport, rfl⟩ := supported
  exact trace_program_excluded p select post program excluded table trace traceSupport

def privateProbe : WotsQuery → Bool
  | .inl _ => false
  | .inr _ => true

theorem c10_final_private_excluded (cfg : C10SessionConfig) (out : C10SessionResult C10Forgery) :
    QueryExclusion privateProbe (fun _ => True) (c10FinalProgram id cfg out) := by
  cases admitted : sessionFinalAdmits out
  · rw [c10FinalProgram, admitted, if_neg Bool.false_ne_true]
    trivial
  · rw [c10FinalProgram, admitted, if_pos rfl]
    have mapped : QueryExclusion privateProbe (fun _ => True)
        (mapProgram Sum.inl (c10VerifyProgram id cfg.seed cfg.root out.value.1 out.value.2)) := by
      rw [queryExclusion_map]
      exact query_exclusion_all _ (fun _ => rfl) _
    simpa only [c10_verify_map, Function.comp_id, Function.id_comp] using mapped

theorem c10_probed_driver_final_public (cfg : C10SessionConfig) {fuel : ℕ}
    (client : C10Client C10Forgery fuel) (qr qs : ℕ) (table : Memo WotsQuery Digest)
    (out : C10ProbedDriver × Memo WotsQuery Digest)
    (supported : out ∈ (evalProgram digestDraw (c10ProbedDriverProgram cfg client qr qs) table).support) :
    ∀ tail, (.inr tail : WotsQuery) ∉ out.1.2 := by
  rw [c10ProbedDriverProgram, evalProgram_bind, PMF.mem_support_bind_iff] at supported
  obtain ⟨observed, _, supported⟩ := supported
  rw [evalProgram_mapReturn, PMF.mem_support_map_iff] at supported
  obtain ⟨final, finalSupport, rfl⟩ := supported
  intro tail member
  have impossible := probe_program_excluded digestDraw privateProbe (fun _ => True)
    (c10FinalProgram id cfg observed.1.session) (c10_final_private_excluded cfg observed.1.session)
    observed.2 final finalSupport (.inr tail) member
  cases impossible

theorem c10_probed_game_public (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) (table : Memo WotsQuery Digest)
    (out : C10ProbedGame × Memo WotsQuery Digest)
    (supported : out ∈ (evalProgram digestDraw
      (c10ProbedGameProgram cfg publicSeed adversary qr qs) table).support) :
    ∀ tail, (.inr tail : WotsQuery) ∉ c10ProbeQueries out.1 := by
  rw [c10ProbedGameProgram, evalProgram_bind, PMF.mem_support_bind_iff] at supported
  obtain ⟨key, _, supported⟩ := supported
  rw [evalProgram_mapReturn, PMF.mem_support_map_iff] at supported
  obtain ⟨driver, driverSupport, rfl⟩ := supported
  intro tail member
  rcases List.mem_append.mp member with raw | final
  · obtain ⟨bytes, _, impossible⟩ := List.mem_map.mp raw
    cases impossible
  · exact c10_probed_driver_final_public (sessionConfigAt cfg key.1) (adversary key.1.1 key.1.2)
      qr qs key.2 driver driverSupport tail final

end
end C10Probability

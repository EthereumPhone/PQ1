import C10Probability.ObservedDriver
import C10Probability.ObservedHistory
import C10Probability.SessionBranches

/-! All observed history is promoted through the actual final verifier into
one resulting cache. Successful-output witnesses use that same cache and the
actual final message/signature, rather than a separately chosen transcript. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem c10_final_history [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (session : C10SessionResult C10Forgery)
    (table : Memo K Digest) (out : Bool × Memo K Digest)
    (ho : out ∈ (c10Final encode cfg session table).support) :
    MemoExtends table out.2 ∧
      replayProgram out.2 (c10FinalProgram encode cfg session) = some out.1 := by
  have hp : out ∈ (evalProgram digestDraw (c10FinalProgram encode cfg session) table).support := by
    rw [c10_final_eval]
    exact ho
  exact ⟨eval_program_extends _ _ _ _ hp, eval_program_replay _ _ _ _ hp⟩

theorem c10_observed_driver_history [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client C10Forgery fuel)
    (qr qs : ℕ) (table : Memo K Digest) (out : C10ObservedDriver × Memo K Digest)
    (ho : out ∈ (c10ObservedDriver encode cfg client qr qs table).support) :
    (∀ entry ∈ out.1.session.exposures, ExposureSupported encode cfg out.2 entry) ∧
      (∀ key ∈ out.1.session.queries, ∃ reply, out.2 (encode (.inl key)) = some reply) ∧
      replayProgram out.2 (c10FinalProgram encode cfg out.1.session.session) = some out.1.accepted := by
  obtain ⟨sessionTable, hs, hv⟩ := c10_observed_driver_support encode cfg client qr qs table out ho
  obtain ⟨extension, replay⟩ := c10_final_history encode cfg out.1.session.session
    sessionTable (out.1.accepted, out.2) hv
  refine ⟨?_, ?_, replay⟩
  · intro entry he
    exact exposure_supported_extends encode cfg sessionTable out.2 entry extension
      (c10_observed_exposure_support encode cfg client qr qs emptySessionLedger table
        (out.1.session, sessionTable) hs entry he)
  · intro key hk
    obtain ⟨reply, hr⟩ := c10_observed_raw_support encode cfg client qr qs
      emptySessionLedger table (out.1.session, sessionTable) hs key hk
    exact ⟨reply, extension _ _ hr⟩

theorem c10_observed_driver_true [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client C10Forgery fuel)
    (qr qs : ℕ) (table : Memo K Digest) (out : C10ObservedDriver × Memo K Digest)
    (ho : out ∈ (c10ObservedDriver encode cfg client qr qs table).support)
    (win : out.1.accepted = true) :
    out.1.session.session.ledger.failed = false ∧
      out.1.session.session.value.1.length = 32 ∧
      C10SignatureWellFormed out.1.session.session.value.2 ∧
      (∀ entry ∈ out.1.session.exposures,
        out.1.session.session.value.1 ≠ entry.request.message) ∧
      replayProgram out.2 (c10VerifyProgram (encode ∘ Sum.inl) cfg.seed cfg.root
        out.1.session.session.value.1 out.1.session.session.value.2) = some true := by
  obtain ⟨sessionTable, hs, hv⟩ := c10_observed_driver_support encode cfg client qr qs table out ho
  obtain ⟨hf, hm, hw, fresh, verified⟩ := c10_final_true_support encode cfg out.1.session.session
    sessionTable (out.1.accepted, out.2) hv win
  refine ⟨hf, hm, hw, ?_, ?_⟩
  · exact c10_observed_fresh_message encode cfg client qr qs table
      (out.1.session, sessionTable) hs _ fresh
  · have hp : (out.1.accepted, out.2) ∈ (evalProgram digestDraw
        (c10VerifyProgram (encode ∘ Sum.inl) cfg.seed cfg.root
          out.1.session.session.value.1 out.1.session.session.value.2) sessionTable).support := by
      rw [c10_verify_eval]
      exact verified
    simpa only [win] using eval_program_replay digestDraw _ sessionTable
      (out.1.accepted, out.2) hp

end
end C10Probability

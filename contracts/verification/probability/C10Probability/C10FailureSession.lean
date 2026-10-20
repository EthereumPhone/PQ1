import C10Probability.C10WotsFailure
import C10Probability.C10RSession

/-! Actual session failure has only the two admitted-search causes. Malformed
requests and exhausted interaction caps do not set failure. A WOTS witness
persists through subsequent cached/raw calls, including calls after failure. -/
namespace C10Probability
noncomputable section

variable {R : Type*}

theorem c10_r_session_cache_extends (encode : WotsQuery → ByteKey)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client R fuel) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table : Memo ByteKey Digest)
    (out : C10RSessionResult R × Memo ByteKey Digest)
    (supported : out ∈ (c10RSession encode cfg client qr qs ledger table).support) :
    MemoExtends table out.2 := by
  rw [← c10_r_session_eval] at supported
  exact eval_program_extends digestDraw _ table out supported

theorem c10_r_session_failure_cases (encode : WotsQuery → ByteKey)
    (publicKeys : ∀ key, encode (.inl key) = key) (cfg : C10SessionConfig)
    {fuel : ℕ} (client : C10Client R fuel) (qr qs : ℕ) (ledger : C10SessionLedger)
    (table : Memo ByteKey Digest) (out : C10RSessionResult R × Memo ByteKey Digest)
    (supported : out ∈ (c10RSession encode cfg client qr qs ledger table).support)
    (failed : out.1.1.ledger.failed = true) :
    ledger.failed = true ∨ out.1.2 = true ∨
      WotsDomainExhausted cfg.seed cfg.wTrials cfg.wBound out.2 := by
  induction client generalizing qr qs ledger table out with
  | done value =>
    have equal : out = ((⟨value, ledger, qr, qs⟩, false), table) := by
      simpa [c10RSession] using supported
    exact Or.inl (by simpa [equal] using failed)
  | hash key next ih =>
    cases qr with
    | zero => exact ih 0 0 qs ledger table out supported failed
    | succ qr =>
      rw [c10RSession, PMF.mem_support_bind_iff] at supported
      obtain ⟨reply, _, finished⟩ := supported
      exact ih reply.1 qr qs ledger reply.2 out finished failed
  | sign req next ih =>
    cases qs with
    | zero => exact ih none qr 0 ledger table out supported failed
    | succ qs =>
      cases admitted : sessionAdmits ledger req
      · simp only [c10RSession, admitted, Bool.false_eq_true, ↓reduceIte] at supported
        exact ih none qr (qs + 1) ledger table out supported failed
      · simp only [c10RSession, admitted, ↓reduceIte, PMF.mem_support_bind_iff] at supported
        obtain ⟨reply, signing, finished⟩ := supported
        rw [PMF.mem_support_map_iff] at finished
        obtain ⟨later, continuing, rfl⟩ := finished
        have causes := ih reply.1.1 qr qs (sessionAfterSign ledger req.message reply.1.1)
          reply.2 later continuing failed
        rcases causes with prior | rfailure | wfailure
        · cases value : reply.1.1 with
          | none =>
            rcases c10_r_sign_failure_cases encode publicKeys table req.random req.message cfg.seed
              cfg.root req.shuffle cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound reply
              signing value with rfailure | wfailure
            · exact Or.inr (Or.inl (by simp [addC10RFlag, rfailure]))
            · exact Or.inr (Or.inr (wots_domain_exhausted_extends cfg.seed cfg.wTrials cfg.wBound
                reply.2 later.2 (c10_r_session_cache_extends encode cfg (next reply.1.1) qr qs
                  (sessionAfterSign ledger req.message reply.1.1) reply.2 later continuing) wfailure))
          | some signature =>
            exact Or.inl (by simpa [value, sessionAfterSign] using prior)
        · exact Or.inr (Or.inl (by simp [addC10RFlag, rfailure]))
        · exact Or.inr (Or.inr wfailure)

theorem c10_r_initialized_session_failure_cases (encode : WotsQuery → ByteKey)
    (publicKeys : ∀ key, encode (.inl key) = key) (cfg : C10SessionConfig)
    {fuel : ℕ} (client : C10Client R fuel) (qr qs : ℕ) (table : Memo ByteKey Digest)
    (out : C10RSessionResult R × Memo ByteKey Digest)
    (supported : out ∈ (c10RSession encode cfg client qr qs emptySessionLedger table).support)
    (failed : out.1.1.ledger.failed = true) :
    out.1.2 = true ∨ WotsDomainExhausted cfg.seed cfg.wTrials cfg.wBound out.2 := by
  have causes := c10_r_session_failure_cases encode publicKeys cfg client qr qs emptySessionLedger
    table out supported failed
  simpa only [emptySessionLedger, Bool.false_eq_true, false_or] using causes

end
end C10Probability

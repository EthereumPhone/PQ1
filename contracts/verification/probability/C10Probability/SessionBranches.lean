import C10Probability.SessionState
import C10Probability.SessionDriver

/-! Exact cache-preserving branch equations and successful-driver support.
They expose the admission boundary independently of the recursive compiler. -/
namespace C10Probability
noncomputable section

variable {K R : Type*}

theorem c10_session_hash_capped [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (key : ByteKey) (next : Digest → C10Client R fuel)
    (qs : ℕ) (ledger : C10SessionLedger) (table : Memo K Digest) :
    c10Session encode cfg (.hash key next) 0 qs ledger table =
      c10Session encode cfg (next 0) 0 qs ledger table := rfl

theorem c10_session_hash_live [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (key : ByteKey) (next : Digest → C10Client R fuel)
    (qr qs : ℕ) (ledger : C10SessionLedger) (table : Memo K Digest) :
    c10Session encode cfg (.hash key next) (qr + 1) qs ledger table =
      (memoQuery digestDraw table (encode (.inl key))).bind
        (fun reply => c10Session encode cfg (next reply.1) qr qs ledger reply.2) := rfl

theorem c10_session_sign_capped [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (req : C10SignRequest)
    (next : Option C10Signature → C10Client R fuel) (qr : ℕ)
    (ledger : C10SessionLedger) (table : Memo K Digest) :
    c10Session encode cfg (.sign req next) qr 0 ledger table =
      c10Session encode cfg (next none) qr 0 ledger table := rfl

theorem c10_session_sign_refused [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (req : C10SignRequest)
    (next : Option C10Signature → C10Client R fuel) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table : Memo K Digest) (ha : sessionAdmits ledger req = false) :
    c10Session encode cfg (.sign req next) qr qs ledger table =
      c10Session encode cfg (next none) qr qs ledger table := by
  cases qs <;> simp only [c10Session, ha, Bool.false_eq_true, ↓reduceIte]

theorem c10_session_sign_exhausted [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (req : C10SignRequest)
    (next : Option C10Signature → C10Client R fuel) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table finalTable : Memo K Digest)
    (ha : sessionAdmits ledger req = true)
    (execution : c10Sign encode table req.random req.message cfg.seed cfg.root req.shuffle
      cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound = PMF.pure (none, finalTable)) :
    c10Session encode cfg (.sign req next) qr (qs + 1) ledger table =
      c10Session encode cfg (next none) qr qs ⟨ledger.signedMessages, true⟩ finalTable := by
  simp only [c10Session, ha, ↓reduceIte, execution, PMF.pure_bind, sessionAfterSign]

theorem c10_session_sign_returned [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (req : C10SignRequest)
    (next : Option C10Signature → C10Client R fuel) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table finalTable : Memo K Digest) (sig : C10Signature)
    (ha : sessionAdmits ledger req = true)
    (execution : c10Sign encode table req.random req.message cfg.seed cfg.root req.shuffle
      cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound = PMF.pure (some sig, finalTable)) :
    c10Session encode cfg (.sign req next) qr (qs + 1) ledger table =
      c10Session encode cfg (next (some sig)) qr qs
        ⟨ledger.signedMessages ++ [req.message], ledger.failed⟩ finalTable := by
  simp only [c10Session, ha, ↓reduceIte, execution, PMF.pure_bind, sessionAfterSign]

theorem c10_final_refused [DecidableEq K] (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (out : C10SessionResult C10Forgery) (table : Memo K Digest)
    (refused : sessionFinalAdmits out = false) :
    c10Final encode cfg out table = PMF.pure (false, table) := by
  simp only [c10Final, refused, Bool.false_eq_true, ↓reduceIte]

theorem c10_final_recorded_refuses (out : C10SessionResult C10Forgery)
    (recorded : out.value.1 ∈ out.ledger.signedMessages) : sessionFinalAdmits out = false := by
  simp [sessionFinalAdmits, recorded]

theorem c10_final_failed_refuses (out : C10SessionResult C10Forgery)
    (failed : out.ledger.failed = true) : sessionFinalAdmits out = false := by
  simp [sessionFinalAdmits, failed]

theorem c10_final_bad_shape_refuses (out : C10SessionResult C10Forgery)
    (malformed : ¬ C10SignatureWellFormed out.value.2) : sessionFinalAdmits out = false := by
  have hw : sessionSignatureWidth out.value.2 = false := by
    simpa only [Bool.not_eq_true] using mt (session_signature_width_iff out.value.2).mp malformed
  simp [sessionFinalAdmits, hw]

theorem c10_final_true_support [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (session : C10SessionResult C10Forgery)
    (table : Memo K Digest) (out : Bool × Memo K Digest)
    (ho : out ∈ (c10Final encode cfg session table).support) (win : out.1 = true) :
    session.ledger.failed = false ∧ session.value.1.length = 32 ∧
      C10SignatureWellFormed session.value.2 ∧ session.value.1 ∉ session.ledger.signedMessages ∧
      out ∈ (c10Verify (encode ∘ Sum.inl) table cfg.seed cfg.root session.value.1 session.value.2).support := by
  cases ha : sessionFinalAdmits session
  · have he : out = (false, table) := by
      simpa only [c10Final, ha, Bool.false_eq_true, ↓reduceIte, PMF.mem_support_pure_iff] using ho
    simp [he] at win
  · obtain ⟨hf, hm, hs, hn⟩ := (session_final_admits_iff session).mp ha
    exact ⟨hf, hm, hs, hn, by simpa only [c10Final, ha, ↓reduceIte] using ho⟩

theorem c10_driver_true_support [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client C10Forgery fuel)
    (qr qs : ℕ) (table : Memo K Digest) (out : Bool × Memo K Digest)
    (ho : out ∈ (c10Driver encode cfg client qr qs table).support) (win : out.1 = true) :
    ∃ session ∈ (c10Session encode cfg client qr qs emptySessionLedger table).support,
      session.1.ledger.failed = false ∧ session.1.value.1.length = 32 ∧
      C10SignatureWellFormed session.1.value.2 ∧ session.1.value.1 ∉ session.1.ledger.signedMessages ∧
      out ∈ (c10Verify (encode ∘ Sum.inl) session.2 cfg.seed cfg.root
        session.1.value.1 session.1.value.2).support := by
  rw [c10Driver, PMF.mem_support_bind_iff] at ho
  obtain ⟨session, hs, hv⟩ := ho
  exact ⟨session, hs, c10_final_true_support encode cfg session.1 session.2 out hv win⟩

end
end C10Probability

import C10Probability.SessionProgram

/-! State invariants follow from executed clients, including exhausted and
refused calls. The message ledger records successful signatures only. -/
namespace C10Probability
noncomputable section

variable {K R : Type*}

theorem session_after_sign_prefix (ledger : C10SessionLedger) (message : ByteKey)
    (reply : Option C10Signature) :
    ledger.signedMessages.IsPrefix (sessionAfterSign ledger message reply).signedMessages := by
  cases reply <;> simp [sessionAfterSign]

theorem session_after_sign_failed (ledger : C10SessionLedger) (message : ByteKey)
    (reply : Option C10Signature) (hf : ledger.failed = true) :
    (sessionAfterSign ledger message reply).failed = true := by
  cases reply <;> simp [sessionAfterSign, hf]

theorem session_after_sign_length (ledger : C10SessionLedger) (message : ByteKey)
    (reply : Option C10Signature) :
    (sessionAfterSign ledger message reply).signedMessages.length ≤ ledger.signedMessages.length + 1 := by
  cases reply <;> simp [sessionAfterSign]

theorem c10_session_state [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client R fuel)
    (qr qs : ℕ) (ledger : C10SessionLedger) (table : Memo K Digest)
    (out : C10SessionResult R × Memo K Digest)
    (ho : out ∈ (c10Session encode cfg client qr qs ledger table).support) :
    out.1.rawRemaining ≤ qr ∧ out.1.signRemaining ≤ qs ∧
      ledger.signedMessages.IsPrefix out.1.ledger.signedMessages ∧
      (ledger.failed = true → out.1.ledger.failed = true) ∧
      out.1.ledger.signedMessages.length + out.1.signRemaining ≤ ledger.signedMessages.length + qs := by
  induction client generalizing qr qs ledger table out with
  | done value =>
      have he : out = (⟨value, ledger, qr, qs⟩, table) := by simpa [c10Session] using ho
      simp [he]
  | hash key next ih =>
      cases qr with
      | zero => exact ih 0 0 qs ledger table out ho
      | succ qr =>
          rw [c10Session, PMF.mem_support_bind_iff] at ho
          obtain ⟨reply, _, ho⟩ := ho
          obtain ⟨hraw, hsign, hp, hf, hl⟩ := ih reply.1 qr qs ledger reply.2 out ho
          exact ⟨by omega, hsign, hp, hf, hl⟩
  | sign req next ih =>
      cases qs with
      | zero => exact ih none qr 0 ledger table out ho
      | succ qs =>
          cases ha : sessionAdmits ledger req
          · simp only [c10Session, ha, Bool.false_eq_true, ↓reduceIte] at ho
            exact ih none qr (qs + 1) ledger table out ho
          · simp only [c10Session, ha, ↓reduceIte, PMF.mem_support_bind_iff] at ho
            obtain ⟨reply, _, ho⟩ := ho
            obtain ⟨hraw, hsign, hp, hf, hl⟩ := ih reply.1 qr qs
              (sessionAfterSign ledger req.message reply.1) reply.2 out ho
            have len := session_after_sign_length ledger req.message reply.1
            exact ⟨hraw, by omega, (session_after_sign_prefix ledger req.message reply.1).trans hp,
              fun h => hf (session_after_sign_failed ledger req.message reply.1 h), by omega⟩

theorem c10_session_message_widths [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client R fuel)
    (qr qs : ℕ) (ledger : C10SessionLedger) (table : Memo K Digest)
    (initial : ∀ msg ∈ ledger.signedMessages, msg.length = 32)
    (out : C10SessionResult R × Memo K Digest)
    (ho : out ∈ (c10Session encode cfg client qr qs ledger table).support) :
    ∀ msg ∈ out.1.ledger.signedMessages, msg.length = 32 := by
  induction client generalizing qr qs ledger table out with
  | done value =>
      have he : out = (⟨value, ledger, qr, qs⟩, table) := by simpa [c10Session] using ho
      simpa only [he] using initial
  | hash key next ih =>
      cases qr with
      | zero => exact ih 0 0 qs ledger table initial out ho
      | succ qr =>
          rw [c10Session, PMF.mem_support_bind_iff] at ho
          obtain ⟨reply, _, ho⟩ := ho
          exact ih reply.1 qr qs ledger reply.2 initial out ho
  | sign req next ih =>
      cases qs with
      | zero => exact ih none qr 0 ledger table initial out ho
      | succ qs =>
          cases ha : sessionAdmits ledger req
          · simp only [c10Session, ha, Bool.false_eq_true, ↓reduceIte] at ho
            exact ih none qr (qs + 1) ledger table initial out ho
          · simp only [c10Session, ha, ↓reduceIte, PMF.mem_support_bind_iff] at ho
            obtain ⟨reply, _, ho⟩ := ho
            apply ih reply.1 qr qs (sessionAfterSign ledger req.message reply.1) reply.2 ?_ out ho
            cases hreply : reply.1 with
            | none => exact initial
            | some sig =>
                intro msg hm
                rcases List.mem_append.mp hm with old | last
                · exact initial msg old
                · simpa only [List.mem_singleton.mp last] using
                    ((session_admits_iff ledger req).mp ha).2.1

end
end C10Probability

import C10Probability.RSessionProgram

/-! State invariants follow from executed clients, including exhausted and
refused calls. The ordered context ledger records successful searches only, including repeats. -/
namespace C10Probability
noncomputable section

variable {K R : Type*}

theorem r_session_after_grind_prefix (ledger : RGrindLedger) (context : RContext)
    (reply : Option RSearchResult) :
    ledger.contexts.IsPrefix (rSessionAfterGrind ledger context reply).contexts := by
  cases reply <;> simp [rSessionAfterGrind]

theorem r_session_after_grind_failed (ledger : RGrindLedger) (context : RContext)
    (reply : Option RSearchResult) (hf : ledger.failed = true) :
    (rSessionAfterGrind ledger context reply).failed = true := by
  cases reply <;> simp [rSessionAfterGrind, hf]

theorem r_session_after_grind_length (ledger : RGrindLedger) (context : RContext)
    (reply : Option RSearchResult) :
    (rSessionAfterGrind ledger context reply).contexts.length ≤ ledger.contexts.length + 1 := by
  cases reply <;> simp [rSessionAfterGrind]

theorem r_session_state [DecidableEq K] (encode : Sum ByteKey ByteKey → K)
    (cfg : RSessionConfig) {fuel : ℕ} (client : RGrindClient R fuel)
    (qr qs : ℕ) (ledger : RGrindLedger) (table : Memo K Digest)
    (out : RGrindResult R × Memo K Digest)
    (ho : out ∈ (rSession encode cfg client qr qs ledger table).support) :
    out.1.rawRemaining ≤ qr ∧ out.1.grindRemaining ≤ qs ∧
      ledger.contexts.IsPrefix out.1.ledger.contexts ∧
      (ledger.failed = true → out.1.ledger.failed = true) ∧
      out.1.ledger.contexts.length + out.1.grindRemaining ≤ ledger.contexts.length + qs := by
  induction client generalizing qr qs ledger table out with
  | done value =>
      have he : out = (⟨value, ledger, qr, qs⟩, table) := by simpa [rSession] using ho
      simp [he]
  | hash key next ih =>
      cases qr with
      | zero => exact ih 0 0 qs ledger table out ho
      | succ qr =>
          rw [rSession, PMF.mem_support_bind_iff] at ho
          obtain ⟨reply, _, ho⟩ := ho
          obtain ⟨hraw, hsign, hp, hf, hl⟩ := ih reply.1 qr qs ledger reply.2 out ho
          exact ⟨by omega, hsign, hp, hf, hl⟩
  | grind context next ih =>
      cases qs with
      | zero => exact ih none qr 0 ledger table out ho
      | succ qs =>
          cases ha : rSessionAdmits ledger context
          · simp only [rSession, ha, Bool.false_eq_true, ↓reduceIte] at ho
            exact ih none qr (qs + 1) ledger table out ho
          · simp only [rSession, ha, ↓reduceIte, PMF.mem_support_bind_iff] at ho
            obtain ⟨reply, _, ho⟩ := ho
            obtain ⟨hraw, hsign, hp, hf, hl⟩ := ih reply.1 qr qs
              (rSessionAfterGrind ledger context reply.1) reply.2 out ho
            have len := r_session_after_grind_length ledger context reply.1
            exact ⟨hraw, by omega, (r_session_after_grind_prefix ledger context reply.1).trans hp,
              fun h => hf (r_session_after_grind_failed ledger context reply.1 h), by omega⟩

theorem r_session_context_validity [DecidableEq K] (encode : Sum ByteKey ByteKey → K)
    (cfg : RSessionConfig) {fuel : ℕ} (client : RGrindClient R fuel)
    (qr qs : ℕ) (ledger : RGrindLedger) (table : Memo K Digest)
    (initial : ∀ context ∈ ledger.contexts, validRContext context)
    (out : RGrindResult R × Memo K Digest)
    (ho : out ∈ (rSession encode cfg client qr qs ledger table).support) :
    ∀ context ∈ out.1.ledger.contexts, validRContext context := by
  induction client generalizing qr qs ledger table out with
  | done value =>
      have he : out = (⟨value, ledger, qr, qs⟩, table) := by simpa [rSession] using ho
      simpa only [he] using initial
  | hash key next ih =>
      cases qr with
      | zero => exact ih 0 0 qs ledger table initial out ho
      | succ qr =>
          rw [rSession, PMF.mem_support_bind_iff] at ho
          obtain ⟨reply, _, ho⟩ := ho
          exact ih reply.1 qr qs ledger reply.2 initial out ho
  | grind context next ih =>
      cases qs with
      | zero => exact ih none qr 0 ledger table initial out ho
      | succ qs =>
          cases ha : rSessionAdmits ledger context
          · simp only [rSession, ha, Bool.false_eq_true, ↓reduceIte] at ho
            exact ih none qr (qs + 1) ledger table initial out ho
          · simp only [rSession, ha, ↓reduceIte, PMF.mem_support_bind_iff] at ho
            obtain ⟨reply, _, ho⟩ := ho
            apply ih reply.1 qr qs (rSessionAfterGrind ledger context reply.1) reply.2 ?_ out ho
            cases hreply : reply.1 with
            | none => exact initial
            | some sig =>
                intro msg hm
                rcases List.mem_append.mp hm with old | last
                · exact initial msg old
                · simpa only [List.mem_singleton.mp last] using
                    ((r_session_admits_iff ledger context).mp ha).2

end
end C10Probability

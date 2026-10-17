import C10Probability.ObservedSession

/-! The observations count admitted calls, preserve chronological successful
returns and agree exactly with the existing message ledger. Exhaustion spends
a signing allowance without adding a successful exposure. -/
namespace C10Probability
noncomputable section

variable {K R : Type*}

def exposureMessages (entries : List C10Exposure) : List ByteKey :=
  entries.map (fun entry => entry.request.message)

theorem c10_observed_accounting [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client R fuel) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table : Memo K Digest)
    (out : C10ObservedSession R × Memo K Digest)
    (ho : out ∈ (c10ObservedSession encode cfg client qr qs ledger table).support) :
    out.1.queries.length + out.1.session.rawRemaining = qr ∧
      out.1.exposures.length + out.1.session.signRemaining ≤ qs ∧
      out.1.session.ledger.signedMessages =
        ledger.signedMessages ++ exposureMessages out.1.exposures := by
  induction client generalizing qr qs ledger table out with
  | done value =>
    have he : out = (⟨⟨value, ledger, qr, qs⟩, [], []⟩, table) := by
      simpa only [c10ObservedSession, PMF.mem_support_pure_iff] using ho
    simp [he, exposureMessages]
  | hash key next ih =>
    cases qr with
    | zero => exact ih 0 0 qs ledger table out ho
    | succ qr =>
      rw [c10ObservedSession, PMF.mem_support_bind_iff] at ho
      obtain ⟨reply, _, ho⟩ := ho
      rw [PMF.mem_support_map_iff] at ho
      obtain ⟨rest, hr, rfl⟩ := ho
      obtain ⟨hq, hs, hm⟩ := ih reply.1 qr qs ledger reply.2 rest hr
      simp only [observeHash, List.length_cons]
      exact ⟨by omega, hs, hm⟩
  | sign req next ih =>
    cases qs with
    | zero => exact ih none qr 0 ledger table out ho
    | succ qs =>
      cases ha : sessionAdmits ledger req
      · simp only [c10ObservedSession, ha, Bool.false_eq_true, ↓reduceIte] at ho
        exact ih none qr (qs + 1) ledger table out ho
      · simp only [c10ObservedSession, ha, ↓reduceIte, PMF.mem_support_bind_iff] at ho
        obtain ⟨reply, _, ho⟩ := ho
        rw [PMF.mem_support_map_iff] at ho
        obtain ⟨rest, hr, rfl⟩ := ho
        obtain ⟨hq, hs, hm⟩ := ih reply.1 qr qs
          (sessionAfterSign ledger req.message reply.1) reply.2 rest hr
        cases he : reply.1 with
        | none =>
          simp only [he, observeSign, sessionAfterSign] at hm ⊢
          exact ⟨hq, by omega, hm⟩
        | some sig =>
          simp only [he, observeSign, sessionAfterSign, List.length_cons] at hm ⊢
          refine ⟨hq, by omega, ?_⟩
          simpa only [exposureMessages, List.map_cons, List.append_assoc,
            List.singleton_append] using hm

theorem c10_observed_query_count [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client R fuel) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table : Memo K Digest)
    (out : C10ObservedSession R × Memo K Digest)
    (ho : out ∈ (c10ObservedSession encode cfg client qr qs ledger table).support) :
    out.1.queries.length ≤ qr := by
  have h := (c10_observed_accounting encode cfg client qr qs ledger table out ho).1
  omega

theorem c10_observed_exposure_count [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client R fuel) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table : Memo K Digest)
    (out : C10ObservedSession R × Memo K Digest)
    (ho : out ∈ (c10ObservedSession encode cfg client qr qs ledger table).support) :
    out.1.exposures.length ≤ qs := by
  have h := (c10_observed_accounting encode cfg client qr qs ledger table out ho).2.1
  omega

theorem c10_observed_empty_ledger [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client R fuel) (qr qs : ℕ)
    (table : Memo K Digest) (out : C10ObservedSession R × Memo K Digest)
    (ho : out ∈ (c10ObservedSession encode cfg client qr qs emptySessionLedger table).support) :
    out.1.session.ledger.signedMessages = exposureMessages out.1.exposures := by
  simpa only [emptySessionLedger, List.nil_append] using
    (c10_observed_accounting encode cfg client qr qs emptySessionLedger table out ho).2.2

theorem c10_observed_fresh_message [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client R fuel) (qr qs : ℕ)
    (table : Memo K Digest) (out : C10ObservedSession R × Memo K Digest)
    (ho : out ∈ (c10ObservedSession encode cfg client qr qs emptySessionLedger table).support)
    (message : ByteKey) (fresh : message ∉ out.1.session.ledger.signedMessages) :
    ∀ entry ∈ out.1.exposures, message ≠ entry.request.message := by
  rw [c10_observed_empty_ledger encode cfg client qr qs table out ho] at fresh
  intro entry he hsame
  apply fresh
  exact List.mem_map.mpr ⟨entry, he, hsame.symm⟩

end
end C10Probability

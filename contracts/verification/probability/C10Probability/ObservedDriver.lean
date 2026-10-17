import C10Probability.ObservedAccounting
import C10Probability.SessionDriver

/-! The final output and all passive session observations are retained through
the existing guarded verifier. Erasure preserves both its Boolean and cache. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

structure C10ObservedDriver where
  session : C10ObservedSession C10Forgery
  accepted : Bool

def c10ObservedDriver [DecidableEq K] (encode : WotsQuery → K) (cfg : C10SessionConfig)
    {fuel : ℕ} (client : C10Client C10Forgery fuel) (qr qs : ℕ) (table : Memo K Digest) :
    PMF (C10ObservedDriver × Memo K Digest) :=
  (c10ObservedSession encode cfg client qr qs emptySessionLedger table).bind (fun observed =>
    (c10Final encode cfg observed.1.session observed.2).map
      (fun result => (⟨observed.1, result.1⟩, result.2)))

theorem c10_observed_driver_erases [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client C10Forgery fuel)
    (qr qs : ℕ) (table : Memo K Digest) :
    (c10ObservedDriver encode cfg client qr qs table).map
      (fun out => (out.1.accepted, out.2)) = c10Driver encode cfg client qr qs table := by
  rw [c10ObservedDriver, PMF.map_bind, c10Driver,
    ← c10_observed_session_erases encode cfg client qr qs emptySessionLedger table, PMF.bind_map]
  congr 1
  funext observed
  simp only [PMF.map_comp, Function.comp_def]
  change (c10Final encode cfg observed.1.session observed.2).map id = _
  exact PMF.map_id _

theorem c10_observed_driver_support [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client C10Forgery fuel)
    (qr qs : ℕ) (table : Memo K Digest) (out : C10ObservedDriver × Memo K Digest)
    (ho : out ∈ (c10ObservedDriver encode cfg client qr qs table).support) :
    ∃ sessionTable,
      (out.1.session, sessionTable) ∈
        (c10ObservedSession encode cfg client qr qs emptySessionLedger table).support ∧
      (out.1.accepted, out.2) ∈
        (c10Final encode cfg out.1.session.session sessionTable).support := by
  rw [c10ObservedDriver, PMF.mem_support_bind_iff] at ho
  obtain ⟨observed, hs, ho⟩ := ho
  rw [PMF.mem_support_map_iff] at ho
  obtain ⟨verified, hv, rfl⟩ := ho
  exact ⟨observed.2, hs, hv⟩

theorem c10_observed_driver_extends [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client C10Forgery fuel)
    (qr qs : ℕ) (table : Memo K Digest) (out : C10ObservedDriver × Memo K Digest)
    (ho : out ∈ (c10ObservedDriver encode cfg client qr qs table).support) :
    MemoExtends table out.2 := by
  apply eval_program_extends digestDraw (c10DriverProgram encode cfg client qr qs)
    table (out.1.accepted, out.2)
  rw [c10_driver_eval, ← c10_observed_driver_erases encode cfg client qr qs table,
    PMF.mem_support_map_iff]
  exact ⟨out, ho, rfl⟩

theorem c10_observed_driver_accounting [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client C10Forgery fuel)
    (qr qs : ℕ) (table : Memo K Digest) (out : C10ObservedDriver × Memo K Digest)
    (ho : out ∈ (c10ObservedDriver encode cfg client qr qs table).support) :
    out.1.session.queries.length + out.1.session.session.rawRemaining = qr ∧
      out.1.session.exposures.length + out.1.session.session.signRemaining ≤ qs ∧
      out.1.session.session.ledger.signedMessages = exposureMessages out.1.session.exposures := by
  obtain ⟨sessionTable, hs, _⟩ := c10_observed_driver_support encode cfg client qr qs table out ho
  simpa only [emptySessionLedger, List.nil_append] using
    c10_observed_accounting encode cfg client qr qs emptySessionLedger table
      (out.1.session, sessionTable) hs

end
end C10Probability

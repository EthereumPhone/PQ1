import C10Probability.ObservedSession

/-! Branch equations for passive observations. Exhaustion consumes an
admitted attempt but contributes no successful exposure. -/
namespace C10Probability
noncomputable section

variable {K R : Type*}

theorem c10_observed_sign_refused [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (req : C10SignRequest)
    (next : Option C10Signature → C10Client R fuel) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table : Memo K Digest) (ha : sessionAdmits ledger req = false) :
    c10ObservedSession encode cfg (.sign req next) qr qs ledger table =
      c10ObservedSession encode cfg (next none) qr qs ledger table := by
  cases qs <;> simp only [c10ObservedSession, ha, Bool.false_eq_true, ↓reduceIte]

theorem c10_observed_sign_exhausted [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (req : C10SignRequest)
    (next : Option C10Signature → C10Client R fuel) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table finalTable : Memo K Digest)
    (ha : sessionAdmits ledger req = true)
    (execution : c10Sign encode table req.random req.message cfg.seed cfg.root req.shuffle
      cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound = PMF.pure (none, finalTable)) :
    c10ObservedSession encode cfg (.sign req next) qr (qs + 1) ledger table =
      c10ObservedSession encode cfg (next none) qr qs ⟨ledger.signedMessages, true⟩ finalTable := by
  simp only [c10ObservedSession, ha, ↓reduceIte, execution, PMF.pure_bind, sessionAfterSign,
    observe_sign_none]
  change (c10ObservedSession encode cfg (next none) qr qs
    ⟨ledger.signedMessages, true⟩ finalTable).map id = _
  exact PMF.map_id _

theorem c10_observed_sign_returned [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (req : C10SignRequest)
    (next : Option C10Signature → C10Client R fuel) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table finalTable : Memo K Digest) (sig : C10Signature)
    (ha : sessionAdmits ledger req = true)
    (execution : c10Sign encode table req.random req.message cfg.seed cfg.root req.shuffle
      cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound = PMF.pure (some sig, finalTable)) :
    c10ObservedSession encode cfg (.sign req next) qr (qs + 1) ledger table =
      (c10ObservedSession encode cfg (next (some sig)) qr qs
        ⟨ledger.signedMessages ++ [req.message], ledger.failed⟩ finalTable).map
          (fun out => (observeSign req (some sig) out.1, out.2)) := by
  simp only [c10ObservedSession, ha, ↓reduceIte, execution, PMF.pure_bind, sessionAfterSign]

end
end C10Probability

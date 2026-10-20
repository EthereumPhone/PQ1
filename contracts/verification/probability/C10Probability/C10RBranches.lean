import C10Probability.C10RSession

/-! Direct observer equations for the original refusal and admitted-call
boundaries. These retain full results and tables, rather than only event mass. -/
namespace C10Probability
noncomputable section

variable {K R : Type*} [DecidableEq K] {fuel : ℕ}

theorem c10_r_session_hash_capped (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (key : ByteKey) (next : Digest → C10Client R fuel) (qs : ℕ)
    (ledger : C10SessionLedger) (table : Memo K Digest) :
    c10RSession encode cfg (.hash key next) 0 qs ledger table =
      c10RSession encode cfg (next 0) 0 qs ledger table := by rfl

theorem c10_r_session_sign_capped (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (req : C10SignRequest) (next : Option C10Signature → C10Client R fuel) (qr : ℕ)
    (ledger : C10SessionLedger) (table : Memo K Digest) :
    c10RSession encode cfg (.sign req next) qr 0 ledger table =
      c10RSession encode cfg (next none) qr 0 ledger table := by rfl

theorem c10_r_session_sign_refused (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (req : C10SignRequest) (next : Option C10Signature → C10Client R fuel) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table : Memo K Digest)
    (refused : sessionAdmits ledger req = false) :
    c10RSession encode cfg (.sign req next) qr (qs + 1) ledger table =
      c10RSession encode cfg (next none) qr (qs + 1) ledger table := by
  simp only [c10RSession, refused, Bool.false_eq_true, ↓reduceIte]

theorem c10_r_session_sign_observed (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (req : C10SignRequest) (next : Option C10Signature → C10Client R fuel) (qr qs : ℕ)
    (ledger : C10SessionLedger) (before after : Memo K Digest)
    (reply : Option C10Signature) (failed : Bool)
    (admitted : sessionAdmits ledger req = true)
    (executed : c10RSign encode before req.random req.message cfg.seed cfg.root req.shuffle
      cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound = PMF.pure ((reply, failed), after)) :
    c10RSession encode cfg (.sign req next) qr (qs + 1) ledger before =
      (c10RSession encode cfg (next reply) qr qs (sessionAfterSign ledger req.message reply) after).map
        (fun out => (addC10RFlag failed out.1, out.2)) := by
  simp only [c10RSession, admitted, ↓reduceIte, executed, PMF.pure_bind]

end
end C10Probability

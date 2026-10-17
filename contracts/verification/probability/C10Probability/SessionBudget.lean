import C10Probability.SessionProgram

/-! Accepted-call caps bound every reply-dependent continuation. The selected
physical domain includes private R inputs; it is not the public-call budget. -/
namespace C10Probability
noncomputable section

variable {R : Type*}

theorem c10_session_public (cfg : C10SessionConfig) {fuel : ℕ}
    (client : C10Client R fuel) (qr qs : ℕ) (ledger : C10SessionLedger) :
    PublicBudget (c10SessionProgram id cfg client qr qs ledger)
      (qr + qs * sessionSignPublic cfg) := by
  induction client generalizing qr qs ledger with
  | done value => simp only [c10SessionProgram, PublicBudget]
  | hash key next ih =>
      cases qr with
      | zero => simpa only [c10SessionProgram] using ih 0 0 qs ledger
      | succ qr =>
          simp only [c10SessionProgram, publicBudget_cast, id_eq, PublicBudget]
          refine ⟨by omega, fun reply => ?_⟩
          simpa only [show qr + 1 + qs * sessionSignPublic cfg - 1 =
            qr + qs * sessionSignPublic cfg by omega] using ih reply qr qs ledger
  | sign req next ih =>
      cases qs with
      | zero => simpa only [c10SessionProgram] using ih none qr 0 ledger
      | succ qs =>
          cases h : sessionAdmits ledger req
          · simpa only [c10SessionProgram, h, Bool.false_eq_true, ↓reduceIte] using
              ih none qr (qs + 1) ledger
          · simp only [c10SessionProgram, h, ↓reduceIte, publicBudget_cast]
            rw [show qr + (qs + 1) * sessionSignPublic cfg =
              sessionSignPublic cfg + (qr + qs * sessionSignPublic cfg) by ring]
            apply publicBudget_bind _ _ _ _ (c10_sign_public _ _ _ _ _ _ _ _ _)
            intro reply
            exact ih reply qr qs (sessionAfterSign ledger req.message reply)

theorem c10_session_selected (secret : Digest) (cfg : C10SessionConfig) {fuel : ℕ}
    (client : C10Client R fuel) (qr qs : ℕ) (ledger : C10SessionLedger)
    (hs : cfg.seed.length = 32) (hr : cfg.root.length = 32) :
    SelectedBudget nodeQuery (c10SessionProgram (privateKey prefixedPrivateInput secret)
      cfg client qr qs ledger) (qr + qs * sessionSignSelected cfg) := by
  induction client generalizing qr qs ledger with
  | done value => simp only [c10SessionProgram, SelectedBudget]
  | hash key next ih =>
      cases qr with
      | zero => simpa only [c10SessionProgram] using ih 0 0 qs ledger
      | succ qr =>
          simp only [c10SessionProgram, selectedBudget_cast]
          rw [show qr + 1 + qs * sessionSignSelected cfg =
            (qr + qs * sessionSignSelected cfg) + 1 by omega]
          exact selectedBudget_query _ _ _ _ (fun reply => ih reply qr qs ledger)
  | sign req next ih =>
      cases qs with
      | zero => simpa only [c10SessionProgram] using ih none qr 0 ledger
      | succ qs =>
          cases h : sessionAdmits ledger req
          · simpa only [c10SessionProgram, h, Bool.false_eq_true, ↓reduceIte] using
              ih none qr (qs + 1) ledger
          · simp only [c10SessionProgram, h, ↓reduceIte, selectedBudget_cast]
            rw [show qr + (qs + 1) * sessionSignSelected cfg =
              sessionSignSelected cfg + (qr + qs * sessionSignSelected cfg) by ring]
            apply selectedBudget_bind _ _ _ _ _
              (c10_sign_selected secret _ _ _ _ _ _ _ _ _ hs hr
                ((session_admits_iff ledger req).mp h).2.1)
            intro reply
            exact ih reply qr qs (sessionAfterSign ledger req.message reply)

end
end C10Probability

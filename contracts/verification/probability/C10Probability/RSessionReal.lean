import C10Probability.RSessionTransfer

/-! Real-valued availability charges retain both memoized-R collision terms
and shared-prefix guessing. Finiteness is established before conversion. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem r_exhaustion_charge_ne_top (history trials : ℕ) :
    rExhaustionCharge history trials ≠ ⊤ := by
  have finite : rejectMass digestDraw (forsAccept ∘ forsOfDigest) ≠ ⊤ :=
    ne_top_of_le_ne_top (by simp) (rejectMass_le_one _ _)
  unfold rExhaustionCharge
  finiteness

theorem r_exhaustion_charge_real (history trials : ℕ) :
    (rExhaustionCharge history trials).toReal =
      (1 - (1 : ℝ) / 2048) ^ trials + (collisionPairs history trials : ℝ) / 2 ^ 128 := by
  have finite : rejectMass digestDraw (forsAccept ∘ forsOfDigest) ≠ ⊤ :=
    ne_top_of_le_ne_top (by simp) (rejectMass_le_one _ _)
  unfold rExhaustionCharge
  rw [ENNReal.toReal_add (by finiteness) (by finiteness), ENNReal.toReal_pow,
    rejectMass_real, digest_fors_acceptance]
  simp only [ENNReal.toReal_inv, ENNReal.toReal_ofNat, ENNReal.toReal_div,
    ENNReal.toReal_natCast, ENNReal.toReal_pow, one_div]

theorem r_session_charge_ne_top (cfg : RSessionConfig) (qr qs : ℕ) :
    rSessionCharge cfg qr qs ≠ ⊤ := by
  have finite := r_exhaustion_charge_ne_top (qr + qs * cfg.trials) cfg.trials
  unfold rSessionCharge
  finiteness

def rSessionChargeReal (cfg : RSessionConfig) (qr qs : ℕ) : ℝ :=
  (qs : ℝ) * ((1 - (1 : ℝ) / 2048) ^ cfg.trials +
    (collisionPairs (qr + qs * cfg.trials) cfg.trials : ℝ) / 2 ^ 128) +
      ((qr + qs * cfg.trials : ℕ) : ℝ) / 2 ^ 256

theorem r_session_charge_real (cfg : RSessionConfig) (qr qs : ℕ) :
    (rSessionCharge cfg qr qs).toReal = rSessionChargeReal cfg qr qs := by
  have finite := r_exhaustion_charge_ne_top (qr + qs * cfg.trials) cfg.trials
  unfold rSessionCharge rSessionChargeReal
  rw [ENNReal.toReal_add (by finiteness) (by finiteness)]
  simp only [ENNReal.toReal_mul, ENNReal.toReal_natCast, r_exhaustion_charge_real,
    ENNReal.toReal_div, ENNReal.toReal_pow, ENNReal.toReal_ofNat]

theorem r_shared_session_exhaustion_real (cfg : RSessionConfig) {R : Type*} {fuel : ℕ}
    (clients : PMF (RGrindClient R fuel)) (qr qs : ℕ) :
    (((rSharedSession cfg clients qr qs).map rSessionFailure) true).toReal ≤
      rSessionChargeReal cfg qr qs := by
  simpa only [r_session_charge_real] using ENNReal.toReal_mono
    (r_session_charge_ne_top cfg qr qs) (r_shared_session_exhaustion cfg clients qr qs)

theorem r_shared_session_exhaustion_real_capped (cfg : RSessionConfig)
    {R : Type*} {fuel : ℕ} (clients : PMF (RGrindClient R fuel)) (qr qs : ℕ) :
    (((rSharedSession cfg clients qr qs).map rSessionFailure) true).toReal ≤
      min 1 (rSessionChargeReal cfg qr qs) := by
  apply le_min
  · simpa only [ENNReal.toReal_one] using ENNReal.toReal_mono
      (by simp : (1 : ℝ≥0∞) ≠ ⊤)
      (PMF.coe_le_one ((rSharedSession cfg clients qr qs).map rSessionFailure) true)
  · exact r_shared_session_exhaustion_real cfg clients qr qs

def rSigningSessionConfig (seed root : ByteKey) : RSessionConfig :=
  ⟨seed, root, signingBudget, signing_counter_fits⟩

theorem r_signing_session_exhaustion_real (seed root : ByteKey)
    {R : Type*} {fuel : ℕ} (clients : PMF (RGrindClient R fuel)) (qr qs : ℕ) :
    (((rSharedSession (rSigningSessionConfig seed root) clients qr qs).map
      rSessionFailure) true).toReal ≤
      min 1 ((qs : ℝ) * ((1 - (1 : ℝ) / 2048) ^ signingBudget +
        (collisionPairs (qr + qs * signingBudget) signingBudget : ℝ) / 2 ^ 128) +
          ((qr + qs * signingBudget : ℕ) : ℝ) / 2 ^ 256) := by
  exact r_shared_session_exhaustion_real_capped (rSigningSessionConfig seed root) clients qr qs

end
end C10Probability

import C10Probability.RSessionReal

/-! A conservative concrete availability bound for the modeled R session.
The geometric tail is bounded in blocks, avoiding expansion of the deployed
ten-million-trial exponent. This is not a full C10 signing-availability claim. -/
namespace C10Probability
noncomputable section

theorem r_rejection_block_bound :
    (1 - (1 : ℝ) / 2048) ^ 2048 ≤ (1 : ℝ) / 2 := by
  have lower : (2 : ℝ) ≤ (1 + (1 : ℝ) / 2047) ^ 2048 :=
    le_trans (show (2 : ℝ) ≤ 1 + (2048 : ℝ) * (1 / 2047) by norm_num)
      (one_add_mul_le_pow (by norm_num : (-2 : ℝ) ≤ 1 / 2047) 2048)
  have product : (1 + (1 : ℝ) / 2047) ^ 2048 * (1 - (1 : ℝ) / 2048) ^ 2048 = 1 := by
    rw [← mul_pow, show (1 + (1 : ℝ) / 2047) * (1 - (1 : ℝ) / 2048) = 1 by norm_num,
      one_pow]
  have multiplied := mul_le_mul_of_nonneg_right lower
    (pow_nonneg (by norm_num : (0 : ℝ) ≤ 1 - 1 / 2048) 2048)
  rw [product] at multiplied
  generalize (1 - (1 : ℝ) / 2048) ^ 2048 = tail at multiplied ⊢
  linarith only [multiplied]

theorem r_signing_geometric_bound :
    (1 - (1 : ℝ) / 2048) ^ signingBudget ≤ (2 : ℝ)⁻¹ ^ 64 := by
  calc
    _ ≤ (1 - (1 : ℝ) / 2048) ^ (2048 * 64) :=
      pow_le_pow_of_le_one (by norm_num) (by norm_num) (by decide +kernel)
    _ = ((1 - (1 : ℝ) / 2048) ^ 2048) ^ 64 := pow_mul _ _ _
    _ ≤ ((1 : ℝ) / 2) ^ 64 :=
      pow_le_pow_left₀ (pow_nonneg (by norm_num) _) r_rejection_block_bound _
    _ = _ := by rw [one_div]

theorem r_session_charge_of_tail_bound (cfg : RSessionConfig) (qr qs : ℕ)
    (tail : ℝ) (bounded : (1 - (1 : ℝ) / 2048) ^ cfg.trials ≤ tail) :
    rSessionChargeReal cfg qr qs ≤
      (qs : ℝ) * (tail + (collisionPairs (qr + qs * cfg.trials) cfg.trials : ℝ) / 2 ^ 128) +
        ((qr + qs * cfg.trials : ℕ) : ℝ) / 2 ^ 256 := by
  exact add_le_add (mul_le_mul_of_nonneg_left
    (add_le_add bounded le_rfl) (Nat.cast_nonneg qs)) le_rfl

theorem r_session_charge_quota_bound (seed root : ByteKey) :
    rSessionChargeReal (rSigningSessionConfig seed root) (2 ^ 32) (2 ^ 20) ≤
      (2 : ℝ)⁻¹ ^ 40 := by
  apply (r_session_charge_of_tail_bound (rSigningSessionConfig seed root)
    (2 ^ 32) (2 ^ 20) ((2 : ℝ)⁻¹ ^ 64) r_signing_geometric_bound).trans
  simp only [rSigningSessionConfig]
  rw [collision_pairs_formula]
  norm_num [signingBudget]

theorem r_signing_session_concrete_exhaustion (seed root : ByteKey)
    {R : Type*} {fuel : ℕ} (clients : PMF (RGrindClient R fuel)) :
    (((rSharedSession (rSigningSessionConfig seed root) clients (2 ^ 32) (2 ^ 20)).map
      rSessionFailure) true).toReal ≤ (2 : ℝ)⁻¹ ^ 40 := by
  exact (r_shared_session_exhaustion_real (rSigningSessionConfig seed root) clients _ _).trans
    (r_session_charge_quota_bound seed root)

end
end C10Probability

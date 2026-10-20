import C10Probability.WotsDomainReal

/-! The actual WOTS acceptance mass exceeds 1/30720. A conservative block
bound absorbs the union over all 256 variable input bits at ten million trials.
This theorem bounds a cache event; complete signing availability is composed
separately from actual failure provenance. -/
namespace C10Probability
noncomputable section

theorem wots_rejection_mass_lower_surrogate :
    0 ≤ 1 - (22169393903687611906220091621190388 : ℝ) / 8 ^ 43 ∧
    1 - (22169393903687611906220091621190388 : ℝ) / 8 ^ 43 ≤ 1 - (1 : ℝ) / 30720 := by
  norm_num

theorem wots_rejection_block_bound :
    (1 - (1 : ℝ) / 30720) ^ 30720 ≤ (1 : ℝ) / 2 := by
  have lower : (2 : ℝ) ≤ (1 + (1 : ℝ) / 30719) ^ 30720 :=
    le_trans (show (2 : ℝ) ≤ 1 + (30720 : ℝ) * (1 / 30719) by norm_num)
      (one_add_mul_le_pow (by norm_num : (-2 : ℝ) ≤ 1 / 30719) 30720)
  have product :
      (1 + (1 : ℝ) / 30719) ^ 30720 * (1 - (1 : ℝ) / 30720) ^ 30720 = 1 := by
    rw [← mul_pow,
      show (1 + (1 : ℝ) / 30719) * (1 - (1 : ℝ) / 30720) = 1 by norm_num, one_pow]
  have multiplied := mul_le_mul_of_nonneg_right lower
    (pow_nonneg (by norm_num : (0 : ℝ) ≤ 1 - 1 / 30720) 30720)
  rw [product] at multiplied
  generalize (1 - (1 : ℝ) / 30720) ^ 30720 = tail at multiplied ⊢
  linarith only [multiplied]

theorem wots_signing_rejection_tail :
    (1 - (22169393903687611906220091621190388 : ℝ) / 8 ^ 43) ^ signingBudget ≤
      (2 : ℝ)⁻¹ ^ 320 := by
  calc
    _ ≤ (1 - (1 : ℝ) / 30720) ^ signingBudget :=
      pow_le_pow_left₀ wots_rejection_mass_lower_surrogate.1
        wots_rejection_mass_lower_surrogate.2 _
    _ ≤ (1 - (1 : ℝ) / 30720) ^ (30720 * 320) :=
      pow_le_pow_of_le_one (by norm_num) (by norm_num) (by decide +kernel)
    _ = ((1 - (1 : ℝ) / 30720) ^ 30720) ^ 320 := pow_mul _ _ _
    _ ≤ ((1 : ℝ) / 2) ^ 320 :=
      pow_le_pow_left₀ (pow_nonneg (by norm_num) _) wots_rejection_block_bound _
    _ = _ := by rw [one_div]

theorem wots_signing_domain_charge_bound :
    wotsDomainChargeReal signingBudget ≤ (2 : ℝ)⁻¹ ^ 64 := by
  calc
    _ ≤ (2 : ℝ) ^ 256 * ((2 : ℝ)⁻¹ ^ 320) :=
      mul_le_mul_of_nonneg_left wots_signing_rejection_tail (by positivity)
    _ = _ := by
      rw [show 320 = 256 + 64 from rfl, pow_add, ← mul_assoc, ← mul_pow,
        mul_inv_cancel₀ (by norm_num : (2 : ℝ) ≠ 0), one_pow, one_mul]

theorem randomized_wots_signing_domain_bound {R : Type*} {budget : ℕ}
    (clients : PMF (QueryProgram ByteKey Digest R budget)) (seed : ByteKey) :
    ((randomizedProgram digestDraw clients (fun _ => none)).toOuterMeasure
      {out | WotsDomainExhausted seed signingBudget signing_counter_fits out.2}).toReal ≤
        (2 : ℝ)⁻¹ ^ 64 := by
  exact (randomized_wots_domain_bound_real clients seed signingBudget signing_counter_fits).trans
    wots_signing_domain_charge_bound

end
end C10Probability

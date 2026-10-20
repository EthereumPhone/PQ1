import C10Probability.WotsCountDomain

/-! Finite and real forms of the initialized adaptive WOTS schedule bound.
The finite union is conservative and covers the full serialized field widths. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def wotsDomainChargeReal (trials : ℕ) : ℝ :=
  2 ^ 256 *
    (1 - (22169393903687611906220091621190388 : ℝ) / 8 ^ 43) ^ trials

theorem wots_domain_charge_ne_top (trials : ℕ) : wotsDomainCharge trials ≠ ⊤ := by
  unfold wotsDomainCharge
  exact ENNReal.mul_ne_top (by finiteness)
    (ENNReal.pow_ne_top (ne_top_of_le_ne_top ENNReal.one_ne_top (rejectMass_le_one _ _)))

theorem wots_domain_charge_real (trials : ℕ) :
    (wotsDomainCharge trials).toReal = wotsDomainChargeReal trials := by
  rw [wotsDomainCharge, ENNReal.toReal_mul, ENNReal.toReal_pow, ENNReal.toReal_ofNat,
    ENNReal.toReal_pow, rejectMass_real, digest_wots_acceptance_exact]
  simp only [ENNReal.toReal_div, ENNReal.toReal_ofNat, ENNReal.toReal_pow, wotsDomainChargeReal]

theorem randomized_wots_domain_bound_real {R : Type*} {budget : ℕ}
    (clients : PMF (QueryProgram ByteKey Digest R budget)) (seed : ByteKey)
    (trials : ℕ) (bounded : trials ≤ 2 ^ 32) :
    ((randomizedProgram digestDraw clients (fun _ => none)).toOuterMeasure
      {out | WotsDomainExhausted seed trials bounded out.2}).toReal ≤
        wotsDomainChargeReal trials := by
  simpa only [wots_domain_charge_real] using
    ENNReal.toReal_mono (wots_domain_charge_ne_top trials)
      (randomized_wots_domain_bound clients seed trials bounded)

theorem randomized_wots_domain_bound_capped {R : Type*} {budget : ℕ}
    (clients : PMF (QueryProgram ByteKey Digest R budget)) (seed : ByteKey)
    (trials : ℕ) (bounded : trials ≤ 2 ^ 32) :
    (randomizedProgram digestDraw clients (fun _ => none)).toOuterMeasure
      {out | WotsDomainExhausted seed trials bounded out.2} ≤ min 1 (wotsDomainCharge trials) := by
  exact le_min (event_mass_le_one _ _)
    (randomized_wots_domain_bound clients seed trials bounded)

end
end C10Probability

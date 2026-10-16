import C10Probability.AcceptedCollision

/-! The accepted-encoding component for C10's actual low-129-bit projection
inside the uniform-digest PMF model. The acceptance mass remains an exact
finite cardinality. No numerical enumeration or EasyCrypt theorem is imported,
and this component is not a full forgery-game bound. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem digest_wots_acceptance_mass :
    acceptMass digestDraw (fun digest => wotsAccept (wotsOfDigest digest)) =
      (Nat.card AcceptedWots : ℝ≥0∞) / 8 ^ 43 := by
  rw [acceptMass_map, digest_uniform_wots, wots_mass_count]

theorem digest_program_accepted_wots_bound {R : Type*} {n : ℕ}
    (client : PMF (QueryProgram ByteKey Digest R n)) :
    (randomizedProgram digestDraw client (fun _ => none)).toOuterMeasure
      {out | ¬ AcceptedCollisionFree wotsOfDigest wotsAccept out.2} ≤
        (n.choose 2 : ℝ≥0∞) * ((Nat.card AcceptedWots : ℝ≥0∞) / 8 ^ 43) / 8 ^ 43 := by
  have h := randomizedProgram_accepted_collision_bound digestDraw wotsOfDigest wotsAccept
    digest_uniform_wots client emptyView (emptyAcceptedView_valid wotsOfDigest wotsAccept) rfl
  have hc : Fintype.card WotsWord = 8 ^ 43 := by
    simp only [WotsWord, Fintype.card_fun, Fintype.card_fin]
  simpa only [emptyView, Finset.card_empty, acceptedCollisionCharge,
    Nat.cast_zero, mul_zero, zero_add, digest_wots_acceptance_mass, hc,
    Nat.cast_pow, Nat.cast_ofNat] using h

theorem digest_program_accepted_wots_bound_real {R : Type*} {n : ℕ}
    (client : PMF (QueryProgram ByteKey Digest R n)) :
    ((randomizedProgram digestDraw client (fun _ => none)).toOuterMeasure
      {out | ¬ AcceptedCollisionFree wotsOfDigest wotsAccept out.2}).toReal ≤
        (n.choose 2 : ℝ) * ((Nat.card AcceptedWots : ℝ) / (8 : ℝ) ^ 43) / (8 : ℝ) ^ 43 := by
  have h := randomizedProgram_accepted_collision_bound_real digestDraw wotsOfDigest wotsAccept
    digest_uniform_wots client emptyView (emptyAcceptedView_valid wotsOfDigest wotsAccept) rfl
  have hc : Fintype.card WotsWord = 8 ^ 43 := by
    simp only [WotsWord, Fintype.card_fun, Fintype.card_fin]
  simpa only [emptyView, Finset.card_empty, Nat.cast_zero, mul_zero, zero_add,
    digest_wots_acceptance_mass, hc, Nat.cast_pow, Nat.cast_ofNat,
    ENNReal.toReal_div, ENNReal.toReal_natCast, ENNReal.toReal_pow,
    ENNReal.toReal_ofNat] using h

theorem digest_program_accepted_wots_129_bound {R : Type*} {n : ℕ}
    (client : PMF (QueryProgram ByteKey Digest R n)) :
    ((randomizedProgram digestDraw client (fun _ => none)).toOuterMeasure
      {out | ¬ AcceptedCollisionFree wotsOfDigest wotsAccept out.2}).toReal ≤
        (n.choose 2 : ℝ) * ((Nat.card AcceptedWots : ℝ) / (8 : ℝ) ^ 43) / (2 : ℝ) ^ 129 := by
  have hpow : (8 : ℝ) ^ 43 = (2 : ℝ) ^ 129 := by norm_num
  simpa only [hpow] using digest_program_accepted_wots_bound_real client

end
end C10Probability

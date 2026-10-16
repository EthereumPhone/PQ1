import C10Probability.WotsCount
import C10Probability.AcceptedWots

/-! Numeric substitutions into the existing actual PMF laws. Fresh independent
sampling, memoized adaptive collision events and individual digest atoms retain
their distinct semantics and all existing premises. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem wots_mass_exact :
    acceptMass wotsDraw wotsAccept =
      (22169393903687611906220091621190388 : ℝ≥0∞) / 8 ^ 43 := by
  simpa only [accepted_wots_card_exact, Nat.cast_ofNat] using wots_mass_count

theorem wots_mass_exact_real :
    (acceptMass wotsDraw wotsAccept).toReal =
      (22169393903687611906220091621190388 : ℝ) / (8 : ℝ) ^ 43 := by
  simpa only [accepted_wots_card_exact, Nat.cast_ofNat] using wots_mass_real

theorem wots_exhaustion_exact_real :
    (grind wotsDraw wotsAccept 0 signingBudget none).toReal =
      (1 - (22169393903687611906220091621190388 : ℝ) / (8 : ℝ) ^ 43) ^ signingBudget := by
  simpa only [accepted_wots_card_exact, Nat.cast_ofNat] using wots_exhaustion_real

theorem wots_first_hit_exact (i : ℕ) (word : WotsWord) :
    (grind wotsDraw wotsAccept 0 signingBudget (some (i, word))).toReal =
      if i < signingBudget ∧ wotsAccept word = true then
        (1 - (22169393903687611906220091621190388 : ℝ) / (8 : ℝ) ^ 43) ^ i /
          (8 : ℝ) ^ 43 else 0 := by
  simpa only [accepted_wots_card_exact, Nat.cast_ofNat] using wots_first_hit i word

theorem digest_wots_acceptance_exact :
    acceptMass digestDraw (wotsAccept ∘ wotsOfDigest) =
      (22169393903687611906220091621190388 : ℝ≥0∞) / 8 ^ 43 := by
  simpa only [accepted_wots_card_exact, Nat.cast_ofNat] using digest_wots_acceptance

theorem wots_digest_exhaustion_exact_real :
    (grind digestDraw (wotsAccept ∘ wotsOfDigest) 0 signingBudget none).toReal =
      (1 - (22169393903687611906220091621190388 : ℝ) / (8 : ℝ) ^ 43) ^ signingBudget := by
  simpa only [accepted_wots_card_exact, Nat.cast_ofNat] using wots_digest_exhaustion_real

/-- A specified full digest still has a 256-bit atom denominator. -/
theorem wots_digest_first_hit_exact (i : ℕ) (d : Digest) :
    (grind digestDraw (wotsAccept ∘ wotsOfDigest) 0 signingBudget (some (i, d))).toReal =
      if i < signingBudget ∧ wotsAccept (wotsOfDigest d) = true then
        (1 - (22169393903687611906220091621190388 : ℝ) / (8 : ℝ) ^ 43) ^ i /
          (2 : ℝ) ^ 256 else 0 := by
  simpa only [accepted_wots_card_exact, Nat.cast_ofNat] using wots_digest_first_hit i d

theorem digest_program_accepted_wots_exact_bound {R : Type*} {n : ℕ}
    (client : PMF (QueryProgram ByteKey Digest R n)) :
    (randomizedProgram digestDraw client (fun _ => none)).toOuterMeasure
      {out | ¬ AcceptedCollisionFree wotsOfDigest wotsAccept out.2} ≤
        (n.choose 2 : ℝ≥0∞) *
          ((22169393903687611906220091621190388 : ℝ≥0∞) / 8 ^ 43) / 8 ^ 43 := by
  simpa only [accepted_wots_card_exact, Nat.cast_ofNat] using
    digest_program_accepted_wots_bound client

theorem digest_program_accepted_wots_exact_129_bound {R : Type*} {n : ℕ}
    (client : PMF (QueryProgram ByteKey Digest R n)) :
    ((randomizedProgram digestDraw client (fun _ => none)).toOuterMeasure
      {out | ¬ AcceptedCollisionFree wotsOfDigest wotsAccept out.2}).toReal ≤
        (n.choose 2 : ℝ) *
          ((22169393903687611906220091621190388 : ℝ) / (8 : ℝ) ^ 43) / (2 : ℝ) ^ 129 := by
  simpa only [accepted_wots_card_exact, Nat.cast_ofNat] using
    digest_program_accepted_wots_129_bound client

end
end C10Probability

import C10Probability.ForsCoordinateLaw
import C10Probability.Returned

/-! Exact fresh-draw event masses and bounded independent search. Exhaustion
is retained in the success factor. Events are fixed before these draws. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem fresh_fors_event_factor (event : Digest → Bool) :
    acceptMass digestDraw (fun d => forsAccept (forsOfDigest d) && event d) =
      (2048 : ℝ≥0∞)⁻¹ * acceptMass acceptedForsDraw event := by
  rw [acceptMass, acceptMass, ← ENNReal.tsum_mul_left]
  apply tsum_congr
  intro d
  rw [accepted_fors_atom]
  by_cases ha : forsAccept (forsOfDigest d) = true <;>
    by_cases he : event d = true
  · simp only [ha, he, Bool.and_self, ↓reduceIte, digestDraw,
      PMF.uniformOfFintype_apply, Digest, Fintype.card_fin, Nat.cast_pow, Nat.cast_ofNat]
    rw [← ENNReal.mul_inv (Or.inl (by norm_num)) (Or.inl (by norm_num))]
    norm_num
  · simp [ha, he]
  · simp [ha, he]
  · simp [ha, he]

theorem returned_fors_event_real (event : Digest → Bool) (budget : ℕ) :
    (returnedMass digestDraw (forsAccept ∘ forsOfDigest) event budget).toReal =
      (1 - (1 - (1 : ℝ) / 2048) ^ budget) *
        (acceptMass acceptedForsDraw event).toReal := by
  rw [returnedMass_real digestDraw (forsAccept ∘ forsOfDigest) event budget
    (by simp [digest_fors_acceptance])]
  rw [digest_fors_acceptance]
  simp only [Function.comp_def]
  rw [fresh_fors_event_factor, ENNReal.toReal_mul]
  norm_num

theorem returned_fors_event_bound (event : Digest → Bool) (budget : ℕ) :
    (returnedMass digestDraw (forsAccept ∘ forsOfDigest) event budget).toReal ≤
      (acceptMass acceptedForsDraw event).toReal := by
  rw [returned_fors_event_real]
  apply mul_le_of_le_one_left ENNReal.toReal_nonneg
  have h : 0 ≤ (1 - (1 : ℝ) / 2048) ^ budget := by positivity
  linarith

theorem returned_fors_coordinates_real (address : HypertreeField)
    (opened : Fin 12 → Finset ForsField) (budget : ℕ) :
    (returnedMass digestDraw (forsAccept ∘ forsOfDigest)
      (fun d => decide (forsCoordinates d ∈ forsCoordinateSet address opened)) budget).toReal =
      (1 - (1 - (1 : ℝ) / 2048) ^ budget) *
        ((∏ i, ((opened i).card : ℝ)) / ((2 : ℝ) ^ 18 * 2048 ^ 12)) := by
  rw [returned_fors_event_real, acceptMass_event]
  simp only [decide_eq_true_eq]
  rw [accepted_fors_coordinate_mass]
  simp only [ENNReal.toReal_div, ENNReal.toReal_prod, ENNReal.toReal_natCast,
    ENNReal.toReal_mul, ENNReal.toReal_pow, ENNReal.toReal_ofNat]

end
end C10Probability

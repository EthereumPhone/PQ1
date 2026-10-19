import C10Probability.ForsAccepted

/-! Split a fresh full digest into its actual acceptance bit and the
corresponding conditional distribution. This does not resample cache hits. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def rejectedForsWitness : Digest :=
  forsDigestEquiv.symm (((0, 0), 1), fun _ => 0)

theorem rejected_fors_witness :
    forsAccept (forsOfDigest rejectedForsWitness) = false := by
  rw [← fors_fields_acceptance]
  simp only [rejectedForsWitness, fors_fields_equiv_roundtrip]
  decide

def rejectedForsDraw : PMF Digest :=
  digestDraw.filter {d | forsAccept (forsOfDigest d) = false}
    ⟨rejectedForsWitness, rejected_fors_witness,
      PMF.mem_support_uniformOfFintype rejectedForsWitness⟩

def forsAcceptanceCoin : PMF Bool :=
  PMF.bernoulli (1 / 2048) (by exact_mod_cast (show (1 : ℝ) / 2048 ≤ 1 by norm_num))

theorem fors_acceptance_coin_true :
    forsAcceptanceCoin true = (2048 : ℝ≥0∞)⁻¹ := by
  norm_num [forsAcceptanceCoin]

theorem fors_acceptance_coin_false :
    forsAcceptanceCoin false = (2047 : ℝ≥0∞) / 2048 := by
  have h : (1 : NNReal) - 1 / 2048 = 2047 / 2048 := by
    apply NNReal.coe_injective
    rw [NNReal.coe_sub (by exact_mod_cast (show (1 : ℝ) / 2048 ≤ 1 by norm_num))]
    norm_num
  rw [forsAcceptanceCoin, PMF.bernoulli_apply]
  change (↑((1 : NNReal) - 1 / 2048) : ℝ≥0∞) = _
  rw [h, ENNReal.coe_div (by norm_num)]
  norm_num

theorem rejected_fors_mass :
    rejectMass digestDraw (forsAccept ∘ forsOfDigest) = (2047 : ℝ≥0∞) / 2048 := by
  have partition := mass_partition digestDraw (forsAccept ∘ forsOfDigest)
  rw [digest_fors_acceptance] at partition
  apply (ENNReal.add_right_inj (by norm_num : (2048 : ℝ≥0∞)⁻¹ ≠ ⊤)).mp
  apply partition.trans
  calc
    1 = (2048 : ℝ≥0∞) * 2048⁻¹ :=
      (ENNReal.mul_inv_cancel (by norm_num) (by norm_num)).symm
    _ = 2048⁻¹ + 2047 / 2048 := by rw [div_eq_mul_inv]; ring

theorem rejected_fors_atom (d : Digest) :
    rejectedForsDraw d = if forsAccept (forsOfDigest d) = true then 0
      else digestDraw d * ((2047 : ℝ≥0∞) / 2048)⁻¹ := by
  rw [rejectedForsDraw, PMF.filter_apply]
  have mass : (∑' x : Digest,
      ({d | forsAccept (forsOfDigest d) = false} : Set Digest).indicator digestDraw x) =
      rejectMass digestDraw (forsAccept ∘ forsOfDigest) := by
    apply tsum_congr
    intro x
    cases h : forsAccept (forsOfDigest x) <;> simp [Set.indicator, h]
  rw [mass, rejected_fors_mass]
  cases h : forsAccept (forsOfDigest d) <;> simp [Set.indicator, h]

theorem rejected_fors_support (d : Digest) :
    d ∈ rejectedForsDraw.support ↔ forsAccept (forsOfDigest d) = false := by
  rw [rejectedForsDraw, PMF.mem_support_filter_iff]
  simp only [Set.mem_setOf_eq, digestDraw, PMF.mem_support_uniformOfFintype, and_true]

theorem digest_fors_acceptance_split :
    forsAcceptanceCoin.bind (fun accepted =>
      if accepted then acceptedForsDraw else rejectedForsDraw) = digestDraw := by
  ext d
  rw [PMF.bind_apply, tsum_fintype]
  simp only [Fintype.sum_bool, Bool.false_eq_true, ↓reduceIte,
    fors_acceptance_coin_false, fors_acceptance_coin_true,
    accepted_fors_atom, rejected_fors_atom]
  cases h : forsAccept (forsOfDigest d)
  · simp only [Bool.false_eq_true, ↓reduceIte, mul_zero, zero_add]
    rw [mul_comm (digestDraw d), ← mul_assoc,
      ENNReal.mul_inv_cancel (by simp [div_eq_mul_inv])
        (ENNReal.div_ne_top (by norm_num) (by norm_num)), one_mul]
  · simp only [↓reduceIte, mul_zero, add_zero]
    simp only [digestDraw, PMF.uniformOfFintype_apply, Digest, Fintype.card_fin,
      Nat.cast_pow, Nat.cast_ofNat]
    rw [show (2 : ℝ≥0∞) ^ 256 = 2048 * 2 ^ 245 by norm_num,
      ENNReal.mul_inv (Or.inl (by norm_num)) (Or.inl (by norm_num))]

end
end C10Probability

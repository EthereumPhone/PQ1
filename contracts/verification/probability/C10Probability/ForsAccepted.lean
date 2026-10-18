import C10Probability.ForsCoordinates
import C10Probability.DigestGrind

/-! The full accepted-digest distribution, including its unused high bits.
Conditioning is on the actual eleven-bit FORS acceptance predicate only.
This law does not identify a cached or adaptive oracle reply with a fresh draw. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

abbrev AcceptedForsDigest := {d : Digest // forsAccept (forsOfDigest d) = true}
abbrev AcceptedForsFields := (Fin (2 ^ 95) × HypertreeField) × ForestWord

instance : Nonempty AcceptedForsDigest := ⟨⟨0, by decide⟩⟩

def acceptedForsEquiv : AcceptedForsDigest ≃ AcceptedForsFields where
  toFun d := ((forsDigestEquiv d.val).1.1, (forsDigestEquiv d.val).2)
  invFun fields := ⟨forsDigestEquiv.symm ((fields.1, 0), fields.2), by
    rw [← fors_fields_acceptance, fors_fields_equiv_roundtrip]
    rfl⟩
  left_inv d := by
    apply Subtype.ext
    apply forsDigestEquiv.injective
    rw [fors_fields_equiv_roundtrip]
    have guard : (forsDigestEquiv d.val).1.2 = 0 := by
      simpa only [fors_fields_acceptance, forsAccept, decide_eq_true_eq] using d.property
    rw [← guard]
  right_inv fields := by
    simp only [fors_fields_equiv_roundtrip]

def acceptedForsDraw : PMF Digest :=
  (PMF.uniformOfFintype AcceptedForsDigest).map Subtype.val

theorem accepted_fors_cardinality : Fintype.card AcceptedForsDigest = 2 ^ 245 := by
  rw [Fintype.card_congr acceptedForsEquiv]
  simp only [AcceptedForsFields, ForestWord, HypertreeField, ForsField,
    Fintype.card_prod, Fintype.card_fin, Fintype.card_fun]
  norm_num

theorem accepted_fors_atom (d : Digest) :
    acceptedForsDraw d =
      if forsAccept (forsOfDigest d) = true then ((2 : ℝ≥0∞) ^ 245)⁻¹ else 0 := by
  classical
  by_cases ha : forsAccept (forsOfDigest d) = true
  · rw [if_pos ha, acceptedForsDraw, PMF.map_apply,
      tsum_eq_single (⟨d, ha⟩ : AcceptedForsDigest)]
    · simp only [↓reduceIte, PMF.uniformOfFintype_apply, accepted_fors_cardinality,
        Nat.cast_pow, Nat.cast_ofNat]
    · intro other different
      have unequal : d ≠ other.val := by
        intro same
        exact different (Subtype.ext same.symm)
      simp only [unequal, ↓reduceIte]
  · rw [if_neg ha, acceptedForsDraw, PMF.map_apply]
    apply ENNReal.tsum_eq_zero.mpr
    intro other
    have unequal : d ≠ other.val := by
      intro same
      exact ha (same.symm ▸ other.property)
    simp only [unequal, ↓reduceIte]

theorem accepted_fors_support (d : Digest) :
    d ∈ acceptedForsDraw.support ↔ forsAccept (forsOfDigest d) = true := by
  rw [PMF.mem_support_iff, accepted_fors_atom]
  split <;> simp_all

theorem accepted_fors_conditioning :
    acceptedForsDraw = digestDraw.filter {d | forsAccept (forsOfDigest d) = true}
      ⟨0, by decide, PMF.mem_support_uniformOfFintype 0⟩ := by
  ext d
  rw [accepted_fors_atom, PMF.filter_apply]
  have mass : (∑' x : Digest,
      ({d | forsAccept (forsOfDigest d) = true} : Set Digest).indicator digestDraw x) =
      (2048 : ℝ≥0∞)⁻¹ := by
    rw [← digest_fors_acceptance, acceptMass]
    apply tsum_congr
    intro x
    by_cases accepted : forsAccept (forsOfDigest x) = true <;>
      simp [Set.indicator, accepted]
  rw [mass]
  by_cases ha : forsAccept (forsOfDigest d) = true
  · simp only [ha, ↓reduceIte, Set.indicator_of_mem, Set.mem_setOf_eq,
      digestDraw, PMF.uniformOfFintype_apply, Digest, Fintype.card_fin,
      Nat.cast_pow, Nat.cast_ofNat, inv_inv]
    rw [show (2 : ℝ≥0∞) ^ 256 = 2 ^ 245 * 2048 by norm_num,
      ENNReal.mul_inv (Or.inl (by norm_num)) (Or.inl (by norm_num)),
      ENNReal.inv_mul_cancel_right (by norm_num) (by norm_num)]
  · simp [Set.indicator, ha]

end
end C10Probability

import C10Probability.ForsInputs
import C10Probability.LayerInputs

/-! Joint full-digest coordinates for FORS. All 256 bits are retained by
the equivalence: 95 unused high bits, 18 hypertree bits, the 11-bit
acceptance field, and twelve ordinary 11-bit indices. -/
namespace C10Probability
noncomputable section

abbrev ForestWord := Fin 12 → ForsField
abbrev HypertreeField := Fin (2 ^ 18)
abbrev ForsDigestFields := ((Fin (2 ^ 95) × HypertreeField) × ForsField) × ForestWord

def forsDigestEquiv : Digest ≃ ForsDigestFields :=
  (finCongr (show 2 ^ 256 = ((2 ^ 95 * 2 ^ 18) * 2048) * 2048 ^ 12 by norm_num)).trans
    ((finProdFinEquiv (m := (2 ^ 95 * 2 ^ 18) * 2048) (n := 2048 ^ 12)).symm.trans
      (Equiv.prodCongr
        ((finProdFinEquiv (m := 2 ^ 95 * 2 ^ 18) (n := 2048)).symm.trans
          (Equiv.prodCongr (finProdFinEquiv (m := 2 ^ 95) (n := 2 ^ 18)).symm
            (Equiv.refl ForsField)))
        (finFunctionFinEquiv (m := 2048) (n := 12)).symm))

theorem fors_digest_equiv_roundtrip (d : Digest) :
    forsDigestEquiv.symm (forsDigestEquiv d) = d := by
  exact forsDigestEquiv.symm_apply_apply d

theorem fors_fields_equiv_roundtrip (fields : ForsDigestFields) :
    forsDigestEquiv (forsDigestEquiv.symm fields) = fields := by
  exact forsDigestEquiv.apply_symm_apply fields

theorem digest_uniform_fors_fields :
    digestDraw.map forsDigestEquiv = PMF.uniformOfFintype ForsDigestFields := by
  exact uniform_map_equiv forsDigestEquiv

theorem fors_fields_ordinary (d : Digest) (i : Fin 12) :
    ((forsDigestEquiv d).2 i).val = forestIndex d i.val := by
  change d.val % 2048 ^ 12 / 2048 ^ i.val % 2048 = _
  rw [radix_digit_after_mod 2048 12 i.val d.val i.isLt]
  unfold forestIndex
  congr 2
  rw [show (2048 : ℕ) = 2 ^ 11 by decide, ← pow_mul]

theorem fors_fields_acceptance (d : Digest) :
    (forsDigestEquiv d).1.2 = forsOfDigest d := by
  apply Fin.ext
  change d.val / 2048 ^ 12 % 2048 = d.val / 2 ^ 132 % 2048
  norm_num

theorem fors_fields_hypertree (d : Digest) :
    (forsDigestEquiv d).1.1.2.val = hypertreeIndex d := by
  change d.val / 2048 ^ 12 / 2048 % 2 ^ 18 = d.val / 2 ^ 143 % 2 ^ 18
  rw [Nat.div_div_eq_div_mul]
  norm_num

end
end C10Probability

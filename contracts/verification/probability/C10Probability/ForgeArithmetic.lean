import C10Probability.SharedForgeBound

/-! Real-valued formulas retain every finite charge and the FORS minimum. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem fors_coverage_charge_real (n : ℕ) :
    (forsCoverageCharge n).toReal = ∑ j ∈ Finset.Icc 1 12,
      (n : ℝ) * ((n - 1).descFactorial j : ℝ) * (Nat.stirlingSecond 12 j : ℝ) /
        (2 : ℝ) ^ (132 + 18 * j) := by
  rw [forsCoverageCharge, ENNReal.toReal_sum (by intros; finiteness)]
  simp only [ENNReal.toReal_mul, ENNReal.toReal_natCast, ENNReal.toReal_inv,
    ENNReal.toReal_pow, ENNReal.toReal_ofNat, div_eq_mul_inv]

theorem independent_forge_charge_real (cfg : C10SessionConfig) (qr qs : ℕ) :
    (independentForgeCharge cfg qr qs).toReal =
      ((sessionGameSelected cfg qr qs).choose 2 : ℝ) / 2 ^ 128 +
        ((sessionGameRaw cfg qr qs : ℝ) / 2 ^ 128 +
          (((sessionGameRaw cfg qr qs).choose 2 : ℝ) *
              ((22169393903687611906220091621190388 : ℝ) / 8 ^ 43) / 8 ^ 43 +
            ((316237824 : ℝ) * (((155867 + 2 * qr + qs * 364076 : ℕ) : ℝ) / 2 ^ 128) +
              ((6442450944 : ℝ) * min
                (((177526 + qr + qs * 408408 : ℕ) : ℝ) / 2 ^ 128)
                (((177524 + qr + qs * (sessionSignCost cfg + 1) : ℕ) : ℝ) / 2 ^ 128) +
                  (forsCoverageCharge (qr + qs + 1)).toReal)))) := by
  have finite := fors_coverage_charge_ne_top (qr + qs + 1)
  have nodeFinite : ((sessionGameSelected cfg qr qs).choose 2 : ℝ≥0∞) / 2 ^ 128 ≠ ⊤ :=
    ENNReal.div_ne_top (by finiteness) (by simp)
  have zeroFinite : (sessionGameRaw cfg qr qs : ℝ≥0∞) / 2 ^ 128 ≠ ⊤ :=
    ENNReal.div_ne_top (by finiteness) (by simp)
  have forestFinite := ENNReal.add_ne_top.mpr ⟨ordinary_fors_opening_charge_ne_top cfg qr qs, finite⟩
  have openingsFinite := ENNReal.add_ne_top.mpr ⟨ordinary_wots_opening_charge_ne_top qr qs, forestFinite⟩
  have acceptedFinite := accepted_wots_game_charge_ne_top (sessionGameRaw cfg qr qs)
  have restFinite := ENNReal.add_ne_top.mpr ⟨acceptedFinite, openingsFinite⟩
  rw [independentForgeCharge, ENNReal.toReal_add nodeFinite (ENNReal.add_ne_top.mpr ⟨zeroFinite, restFinite⟩),
    ENNReal.toReal_add zeroFinite restFinite, ENNReal.toReal_add acceptedFinite openingsFinite,
    ENNReal.toReal_add (ordinary_wots_opening_charge_ne_top qr qs) forestFinite,
    ENNReal.toReal_add (ordinary_fors_opening_charge_ne_top cfg qr qs) finite]
  unfold acceptedWotsGameCharge ordinaryWotsOpeningCharge
    wotsCutCharge ordinaryForsOpeningCharge forsOpeningCharge
  have first : ((177526 + qr + qs * 408408 : ℕ) : ℝ≥0∞) / 2 ^ 128 ≠ ⊤ :=
    ENNReal.div_ne_top (by finiteness) (by simp)
  have second : ((177524 + qr + qs * (sessionSignCost cfg + 1) : ℕ) : ℝ≥0∞) / 2 ^ 128 ≠ ⊤ :=
    ENNReal.div_ne_top (by finiteness) (by simp)
  simp only [ENNReal.toReal_mul, ENNReal.toReal_min first second,
    ENNReal.toReal_div, ENNReal.toReal_natCast, ENNReal.toReal_pow,
    ENNReal.toReal_ofNat]

end
end C10Probability

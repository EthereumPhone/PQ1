import C10Probability.RSessionProgram

/-! Support-sensitive averaging for the first-exhaustion induction. A failed
search pays its actual marginal mass once; successful branches pay only the
remaining-session bound. No independence of adaptive continuations is assumed. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {α β γ : Type*}

theorem r_bind_flag_bound (p : PMF α) (next : α → PMF β) (flag : β → Bool)
    (bound : ℝ≥0∞)
    (bounded : ∀ value ∈ p.support, ((next value).map flag) true ≤ bound) :
    ((p.bind next).map flag) true ≤ bound := by
  simp only [PMF.map_bind, PMF.bind_apply]
  calc
    _ ≤ ∑' value, p value * bound := by
      apply ENNReal.tsum_le_tsum
      intro value
      by_cases supported : value ∈ p.support
      · exact mul_le_mul_right (bounded value supported) _
      · simp [(p.apply_eq_zero_iff value).mpr supported]
    _ = bound := by rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]

theorem r_bind_first_none_bound (p : PMF (Option α × β))
    (next : (Option α × β) → PMF γ) (flag : γ → Bool) (future : ℝ≥0∞)
    (bounded : ∀ value state, (some value, state) ∈ p.support →
      ((next (some value, state)).map flag) true ≤ future) :
    ((p.bind next).map flag) true ≤ (p.map Prod.fst) none + future := by
  classical
  simp only [PMF.map_bind, PMF.bind_apply]
  calc
    _ ≤ ∑' out, p out * ((if out.1 = none then 1 else 0) + future) := by
      apply ENNReal.tsum_le_tsum
      intro out
      by_cases supported : out ∈ p.support
      · apply mul_le_mul_right
        rcases out with ⟨reply, state⟩
        cases reply with
        | none =>
            simp only [↓reduceIte]
            exact (PMF.coe_le_one _ true).trans (le_add_right le_rfl)
        | some value =>
            simpa only [Option.some_ne_none, ↓reduceIte, zero_add] using
              bounded value state supported
      · simp [(p.apply_eq_zero_iff out).mpr supported]
    _ = (p.map Prod.fst) none + future := by
      simp_rw [mul_add]
      rw [ENNReal.tsum_add, ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]
      congr 1
      simp [PMF.map_apply, mul_ite, eq_comm]

end
end C10Probability

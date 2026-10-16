import C10Probability.Grind
import Mathlib.Probability.Distributions.Uniform
import Mathlib.Logic.Equiv.Fin.Basic

/-! Finite uniform laws used to derive digest projections by explicit bijections. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {α β : Type*} [Fintype α] [Nonempty α] [Fintype β] [Nonempty β]

theorem uniform_map_equiv (e : α ≃ β) :
    (PMF.uniformOfFintype α).map e = PMF.uniformOfFintype β := by
  classical
  ext b
  rw [PMF.map_apply, tsum_eq_single (e.symm b)]
  · simp [PMF.uniformOfFintype_apply, Fintype.card_congr e]
  · intro a ha
    have h : b ≠ e a := by
      intro h
      apply ha
      simpa using (congrArg e.symm h).symm
    simp [h]

theorem uniform_map_snd :
    (PMF.uniformOfFintype (α × β)).map Prod.snd = PMF.uniformOfFintype β := by
  classical
  ext b
  rw [PMF.map_apply, ENNReal.tsum_prod']
  simp only [PMF.uniformOfFintype_apply, Fintype.card_prod, Nat.cast_mul]
  simp only [tsum_fintype, Finset.sum_ite_eq, Finset.mem_univ, ↓reduceIte,
    Finset.sum_const, Finset.card_univ, nsmul_eq_mul]
  rw [ENNReal.mul_inv (Or.inl (by simp)) (Or.inl (by simp)), ← mul_assoc,
    ENNReal.mul_inv_cancel (by simp) (by simp), one_mul]

theorem uniform_map_fst :
    (PMF.uniformOfFintype (α × β)).map Prod.fst = PMF.uniformOfFintype α := by
  have h := congrArg (PMF.map (Prod.snd : β × α → α))
    (uniform_map_equiv (Equiv.prodComm α β))
  simpa only [PMF.map_comp, uniform_map_snd, Function.comp_def,
    Equiv.prodComm_apply] using h

/-- Extract one mixed-radix field, retaining all other fields in the bijection. -/
def radixField (m n k : ℕ) (x : Fin (m * n * k)) : Fin n :=
  ((finProdFinEquiv (m := m) (n := n)).symm
    ((finProdFinEquiv (m := m * n) (n := k)).symm x).1).2

theorem radixField_value (m n k : ℕ) (x : Fin (m * n * k)) :
    (radixField m n k x).val = (x.val / k) % n := by rfl

theorem uniform_radixField (m n k : ℕ) [NeZero m] [NeZero n] [NeZero k] :
    (PMF.uniformOfFintype (Fin (m * n * k))).map (radixField m n k) =
      PMF.uniformOfFintype (Fin n) := by
  have h1 := congrArg (PMF.map (Prod.fst : Fin (m * n) × Fin k → Fin (m * n)))
    (uniform_map_equiv (finProdFinEquiv (m := m * n) (n := k)).symm)
  rw [uniform_map_fst] at h1
  have h2 := congrArg (PMF.map (Prod.snd : Fin m × Fin n → Fin n))
    (uniform_map_equiv (finProdFinEquiv (m := m) (n := n)).symm)
  rw [uniform_map_snd, PMF.map_comp] at h2
  have h3 := congrArg (PMF.map (fun a : Fin (m * n) =>
    ((finProdFinEquiv (m := m) (n := n)).symm a).2)) h1
  simpa only [PMF.map_comp, Function.comp_def, radixField] using h3.trans h2

end
end C10Probability

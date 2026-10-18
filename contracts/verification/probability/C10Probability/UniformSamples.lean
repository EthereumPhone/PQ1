import C10Probability.Uniform

/-! Finite independent uniform samples. The joint event law is proved by
the cardinality of a function space, including an empty index type. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem uniform_samples_event {I A : Type*} [Fintype I] [DecidableEq I]
    [Fintype A] [Nonempty A]
    (events : I → Set A) :
    (PMF.uniformOfFintype (I → A)).toOuterMeasure {samples | ∀ i, samples i ∈ events i} =
      ∏ i, (PMF.uniformOfFintype A).toOuterMeasure (events i) := by
  classical
  rw [PMF.toOuterMeasure_uniformOfFintype_apply]
  have count : Fintype.card ({samples | ∀ i, samples i ∈ events i} : Set (I → A)) =
      ∏ i, Fintype.card (events i) := by
    let e : ({samples | ∀ i, samples i ∈ events i} : Set (I → A)) ≃
        (∀ i, events i) := Equiv.subtypePiEquivPi
    exact (Fintype.card_congr e).trans Fintype.card_pi
  rw [count, Fintype.card_fun]
  simp_rw [PMF.toOuterMeasure_uniformOfFintype_apply]
  rw [ENNReal.prod_div_distrib_of_ne_top (by simp)]
  simp only [Nat.cast_prod, Nat.cast_pow, Finset.prod_const, Finset.card_univ]

theorem uniform_product_bind {A B : Type*} [Fintype A] [Nonempty A]
    [Fintype B] [Nonempty B] :
    PMF.uniformOfFintype (A × B) =
      (PMF.uniformOfFintype A).bind fun a =>
        (PMF.uniformOfFintype B).map fun b => (a, b) := by
  classical
  ext ⟨a, b⟩
  rw [PMF.bind_apply, tsum_eq_single a]
  · rw [PMF.map_apply, tsum_eq_single b]
    · simp only [↓reduceIte, PMF.uniformOfFintype_apply, Fintype.card_prod, Nat.cast_mul]
      exact ENNReal.mul_inv (Or.inl (by simp)) (Or.inl (by simp))
    · intro other different
      simp [Prod.mk.injEq, Ne.symm different]
  · intro other different
    simp [PMF.map_apply, Prod.mk.injEq, Ne.symm different]

end
end C10Probability

import C10Probability.UniformSamples

/-! Selecting distinct positions from finite independent uniform samples.
Injectivity is required; repeating a position is not an independent draw. -/
namespace C10Probability
noncomputable section

theorem uniform_samples_selection {I J A : Type*}
    [Fintype I] [DecidableEq I] [Fintype J] [DecidableEq J]
    [Fintype A] [Nonempty A] (select : I → J) (distinct : Function.Injective select) :
    (PMF.uniformOfFintype (J → A)).map (fun samples i => samples (select i)) =
      PMF.uniformOfFintype (I → A) := by
  classical
  let Complement := {j : J // j ∉ Set.range select}
  let positions : I ⊕ Complement ≃ J :=
    (Equiv.sumCongr (Equiv.ofInjective select distinct) (Equiv.refl Complement)).trans
      (Equiv.Set.sumCompl (Set.range select))
  let split : (J → A) ≃ (I → A) × (Complement → A) :=
    (Equiv.arrowCongr positions.symm (Equiv.refl A)).trans
      (Equiv.sumArrowEquivProdArrow I Complement A)
  have h := congrArg (PMF.map (Prod.fst : (I → A) × (Complement → A) → (I → A)))
    (uniform_map_equiv split)
  rw [uniform_map_fst] at h
  have selected : Prod.fst ∘ split = (fun samples i => samples (select i)) := by
    funext samples i
    rfl
  simpa only [PMF.map_comp, selected] using h

end
end C10Probability

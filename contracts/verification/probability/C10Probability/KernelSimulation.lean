import C10Probability.TerminatingKernel

/-! A step-preserving encoding carries complete finite executions and their
completion probability. Used to place the geometric witness inside the actual
initialized byte game, rather than relying only on a standalone toy kernel. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem kernel_cutoff_simulation {S R T O : Type*} (source : S → PMF (R ⊕ S))
    (target : T → PMF (O ⊕ T)) (result : R → O) (state : S → T)
    (simulation : ∀ s, target (state s) = (source s).map (Sum.map result state))
    (n : ℕ) (s : S) :
    kernelCutoff target n (state s) =
      (kernelCutoff source n s).map (Sum.map result state) := by
  induction n generalizing s with
  | zero => simp only [kernelCutoff, PMF.pure_map, Sum.map_inr]
  | succ n ih =>
    simp only [kernelCutoff, simulation, PMF.bind_map, Function.comp_def, PMF.map_bind]
    apply congrArg (PMF.bind (source s))
    funext out
    cases out with
    | inl r => simp only [Sum.map_inl, PMF.pure_map]
    | inr next => simpa only [Sum.map_inr] using ih next

theorem kernel_finished_probability {S R : Type*} (p : PMF (R ⊕ S)) :
    (p.map Sum.isLeft) true = ∑' r, p (.inl r) := by
  classical
  rw [PMF.map_apply, ENNReal.summable.tsum_sum ENNReal.summable]
  simp

theorem kernel_finished_simulation {S R T O : Type*} (source : S → PMF (R ⊕ S))
    (target : T → PMF (O ⊕ T)) (result : R → O) (state : S → T)
    (simulation : ∀ s, target (state s) = (source s).map (Sum.map result state))
    (n : ℕ) (s : S) :
    (kernelCutoff target n (state s)).map Sum.isLeft =
      (kernelCutoff source n s).map Sum.isLeft := by
  rw [kernel_cutoff_simulation source target result state simulation]
  simp only [PMF.map_comp, Function.comp_def, Sum.isLeft_map]

end
end C10Probability

import C10Probability.TerminatingKernel

/-! Terminal observations can include a probabilistic continuation such as
final verification. Its probabilities are weighted by the completed execution
mass. The limit commutes with the nonnegative sum without a finite-support or
expected-running-time premise. Bounds for concrete clients must still be
derived for their actual finite operational cutoffs. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem kernel_terminal_weight_eq {S R : Type*} (step : S → PMF (R ⊕ S))
    (s : S) (weight : R → ℝ≥0∞) :
    (∑' r, kernelTerminalMass step s r * weight r) =
      ⨆ n, ∑' r, kernelCutoff step n s (.inl r) * weight r := by
  simp only [kernelTerminalMass, ENNReal.iSup_mul]
  apply ennreal_tsum_iSup_monotone
  intro r a b h
  exact mul_le_mul_left (kernel_cutoff_monotone step s r h) (weight r)

theorem kernel_terminal_weight_bound {S R : Type*} (step : S → PMF (R ⊕ S))
    (s : S) (weight : R → ℝ≥0∞) (bound : ℝ≥0∞)
    (bounded : ∀ n, (∑' r, kernelCutoff step n s (.inl r) * weight r) ≤ bound) :
    (∑' r, kernelTerminalMass step s r * weight r) ≤ bound := by
  rw [kernel_terminal_weight_eq]
  exact iSup_le bounded

theorem kernel_terminal_pmf_continuation {S R O : Type*} (step : S → PMF (R ⊕ S))
    (s : S) (terminates : KernelTerminatesAlmostSurely step s)
    (finish : R → PMF O) (event : Set O) :
    ((kernelTerminalPMF step s terminates).bind finish).toOuterMeasure event =
      ∑' r, kernelTerminalMass step s r * (finish r).toOuterMeasure event := by
  rw [PMF.toOuterMeasure_bind_apply]
  rfl

theorem kernel_terminal_pmf_continuation_bound {S R O : Type*} (step : S → PMF (R ⊕ S))
    (s : S) (terminates : KernelTerminatesAlmostSurely step s)
    (finish : R → PMF O) (event : Set O) (bound : ℝ≥0∞)
    (bounded : ∀ n, (∑' r, kernelCutoff step n s (.inl r) * (finish r).toOuterMeasure event) ≤ bound) :
    ((kernelTerminalPMF step s terminates).bind finish).toOuterMeasure event ≤ bound := by
  rw [kernel_terminal_pmf_continuation]
  exact kernel_terminal_weight_bound step s _ bound bounded

theorem kernel_cutoff_completed_le_observation {S R : Type*} (step : S → PMF (R ⊕ S))
    (s : S) (n : ℕ) (observe : R ⊕ S → R) (completed : ∀ r, observe (.inl r) = r)
    (event : Set R) :
    (∑' r, kernelCutoff step n s (.inl r) * (PMF.pure r).toOuterMeasure event) ≤
      ((kernelCutoff step n s).map observe).toOuterMeasure event := by
  classical
  rw [PMF.toOuterMeasure_map_apply, PMF.toOuterMeasure_apply]
  have bound := ENNReal.tsum_comp_le_tsum_of_injective Sum.inl_injective
    ((observe ⁻¹' event).indicator (kernelCutoff step n s))
  simpa only [Set.indicator_apply, Set.mem_preimage, completed,
    PMF.toOuterMeasure_pure_apply, mul_ite, mul_one, mul_zero] using bound

theorem kernel_terminal_pmf_observation_bound {S R : Type*} (step : S → PMF (R ⊕ S))
    (s : S) (terminates : KernelTerminatesAlmostSurely step s)
    (observe : R ⊕ S → R) (completed : ∀ r, observe (.inl r) = r)
    (event : Set R) (bound : ℝ≥0∞)
    (bounded : ∀ n, ((kernelCutoff step n s).map observe).toOuterMeasure event ≤ bound) :
    (kernelTerminalPMF step s terminates).toOuterMeasure event ≤ bound := by
  have result := kernel_terminal_pmf_continuation_bound step s terminates PMF.pure event bound
    (fun n => (kernel_cutoff_completed_le_observation step s n observe completed event).trans
      (bounded n))
  simpa only [PMF.bind_pure] using result

end
end C10Probability

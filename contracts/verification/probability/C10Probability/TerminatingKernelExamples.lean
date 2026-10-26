import C10Probability.TerminatingKernel
import Mathlib.Analysis.SpecificLimits.Basic
import Mathlib.Tactic.NormNum

/-! Fresh coin flips give an almost-surely terminating computation with a
positive chance of running beyond every finite cutoff. The loop countermodel
in TerminatingKernel distinguishes this from unconditional normalization. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def geometricKernel (_ : Unit) : PMF (Unit ⊕ Unit) :=
  (PMF.bernoulli (1 / 2) (by norm_num)).map
    (fun stop => if stop then Sum.inl () else Sum.inr ())

theorem geometric_kernel_running (n : ℕ) :
    kernelCutoff geometricKernel n () (.inr ()) = (1 / 2 : ℝ≥0∞) ^ n := by
  induction n with
  | zero => simp [kernelCutoff]
  | succ n ih =>
    norm_num [kernelCutoff, geometricKernel, PMF.bind_map, Function.comp_def,
      PMF.bind_apply, tsum_fintype, PMF.bernoulli_apply, PMF.pure_apply, ih, pow_succ,
      mul_comm, Sum.inr_ne_inl]

theorem geometric_kernel_no_fixed_horizon (n : ℕ) :
    0 < kernelCutoff geometricKernel n () (.inr ()) := by
  rw [geometric_kernel_running]
  exact pos_iff_ne_zero.mpr (pow_ne_zero n (by norm_num))

theorem geometric_kernel_completed (n : ℕ) :
    kernelCutoff geometricKernel n () (.inl ()) = 1 - (1 / 2 : ℝ≥0∞) ^ n := by
  have total := (kernelCutoff geometricKernel n ()).tsum_coe
  simp only [tsum_fintype, Fintype.sum_sum_type, Fintype.sum_unique] at total
  change kernelCutoff geometricKernel n () (.inl ()) +
    kernelCutoff geometricKernel n () (.inr ()) = 1 at total
  rw [geometric_kernel_running] at total
  exact ENNReal.eq_sub_of_add_eq (by finiteness) total

theorem geometric_kernel_terminates : KernelTerminatesAlmostSurely geometricKernel () := by
  have tends := ENNReal.tendsto_pow_atTop_nhds_zero_of_lt_one
    (show (1 / 2 : ℝ≥0∞) < 1 by norm_num)
  have infimum : (⨅ n : ℕ, (1 / 2 : ℝ≥0∞) ^ n) = 0 :=
    iInf_eq_of_tendsto (antitone_nat_of_succ_le (fun n => by
      rw [pow_succ]
      exact mul_le_of_le_one_right (zero_le _) (by norm_num))) tends
  simp only [KernelTerminatesAlmostSurely, tsum_fintype, Fintype.sum_unique]
  change (⨆ n, kernelCutoff geometricKernel n () (.inl ())) = 1
  simp only [geometric_kernel_completed, ← ENNReal.sub_iInf, infimum, tsub_zero]

theorem geometric_kernel_terminal_pmf :
    kernelTerminalPMF geometricKernel () geometric_kernel_terminates = PMF.pure () := by
  apply PMF.ext
  intro r
  have total := (kernelTerminalPMF geometricKernel () geometric_kernel_terminates).tsum_coe
  simpa only [tsum_fintype, Fintype.sum_unique, PMF.pure_apply_self] using total

end
end C10Probability

import C10Probability.PMFFiniteFamily
import Mathlib.Topology.Algebra.InfiniteSum.ENNReal
import Mathlib.Data.ENNReal.BigOperators

/-! Operational semantics of a stateful discrete probabilistic computation.
One step either returns a result or chooses its next state. Finite cutoffs retain
unfinished states, so stopping and exhaustion remain distinct. Completed masses
increase to a subprobability law. A normalized terminal PMF requires completed
mass tending to one; no conditional renormalization or expected-time bound is
used. Client and oracle state can be separated by a more specific interpreter. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def kernelCutoff {S R : Type*} (step : S → PMF (R ⊕ S)) : ℕ → S → PMF (R ⊕ S)
  | 0, s => PMF.pure (.inr s)
  | n + 1, s => (step s).bind fun out => match out with
      | .inl result => PMF.pure (.inl result)
      | .inr next => kernelCutoff step n next

theorem kernel_cutoff_succ_le {S R : Type*} (step : S → PMF (R ⊕ S))
    (n : ℕ) (s : S) (r : R) :
    kernelCutoff step n s (.inl r) ≤ kernelCutoff step (n + 1) s (.inl r) := by
  induction n generalizing s with
  | zero => simp [kernelCutoff, PMF.pure_apply]
  | succ n ih =>
    simp only [kernelCutoff, PMF.bind_apply]
    apply ENNReal.tsum_le_tsum
    intro out
    apply mul_le_mul_right
    cases out with
    | inl result => exact le_rfl
    | inr next => exact ih next

theorem kernel_cutoff_monotone {S R : Type*} (step : S → PMF (R ⊕ S)) (s : S) (r : R) :
    Monotone (fun n => kernelCutoff step n s (.inl r)) := by
  exact monotone_nat_of_le_succ (fun n => kernel_cutoff_succ_le step n s r)

theorem ennreal_tsum_iSup_monotone {X : Type*} (f : ℕ → X → ℝ≥0∞)
    (h : ∀ x, Monotone (fun n => f n x)) :
    (∑' x, ⨆ n, f n x) = ⨆ n, ∑' x, f n x := by
  rw [ENNReal.tsum_eq_iSup_sum]
  simp_rw [ENNReal.finsetSum_iSup_of_monotone h]
  rw [iSup_comm]
  congr 1
  funext n
  exact ENNReal.tsum_eq_iSup_sum.symm

def kernelTerminalMass {S R : Type*} (step : S → PMF (R ⊕ S)) (s : S) (r : R) : ℝ≥0∞ :=
  ⨆ n, kernelCutoff step n s (.inl r)

theorem kernel_terminal_mass_total {S R : Type*} (step : S → PMF (R ⊕ S)) (s : S) :
    (∑' r, kernelTerminalMass step s r) = ⨆ n, ∑' r, kernelCutoff step n s (.inl r) := by
  exact ennreal_tsum_iSup_monotone _ (fun r => kernel_cutoff_monotone step s r)

theorem kernel_cutoff_total_le_one {S R : Type*} (step : S → PMF (R ⊕ S)) (n : ℕ) (s : S) :
    (∑' r, kernelCutoff step n s (.inl r)) ≤ 1 := by
  simpa only [PMF.tsum_coe] using
    ENNReal.tsum_comp_le_tsum_of_injective Sum.inl_injective (kernelCutoff step n s)

theorem kernel_terminal_total_le_one {S R : Type*} (step : S → PMF (R ⊕ S)) (s : S) :
    (∑' r, kernelTerminalMass step s r) ≤ 1 := by
  rw [kernel_terminal_mass_total]
  exact iSup_le (fun n => kernel_cutoff_total_le_one step n s)

def KernelTerminatesAlmostSurely {S R : Type*} (step : S → PMF (R ⊕ S)) (s : S) : Prop :=
  (⨆ n, ∑' r, kernelCutoff step n s (.inl r)) = 1

def kernelTerminalPMF {S R : Type*} (step : S → PMF (R ⊕ S)) (s : S)
    (terminates : KernelTerminatesAlmostSurely step s) : PMF R :=
  ⟨kernelTerminalMass step s,
    ENNReal.summable.hasSum_iff.mpr ((kernel_terminal_mass_total step s).trans terminates)⟩

theorem kernel_terminal_pmf_apply {S R : Type*} (step : S → PMF (R ⊕ S)) (s : S)
    (terminates : KernelTerminatesAlmostSurely step s) (r : R) :
    kernelTerminalPMF step s terminates r = kernelTerminalMass step s r := by
  rfl

theorem kernel_terminal_event_bound {S R : Type*} (step : S → PMF (R ⊕ S)) (s : S)
    (event : R → Prop) (bound : ℝ≥0∞)
    (bounded : ∀ n, (∑' r : {r : R // event r}, kernelCutoff step n s (.inl r.val)) ≤ bound) :
    (∑' r : {r : R // event r}, kernelTerminalMass step s r.val) ≤ bound := by
  simp only [kernelTerminalMass]
  rw [ennreal_tsum_iSup_monotone
    (fun n (r : {r : R // event r}) => kernelCutoff step n s (.inl r.val))
    (fun r => kernel_cutoff_monotone step s r.val)]
  exact iSup_le bounded

theorem kernel_loop_cutoff {S R : Type*} (n : ℕ) (s : S) :
    kernelCutoff (fun x : S => PMF.pure (Sum.inr (α := R) x)) n s = PMF.pure (.inr s) := by
  induction n with
  | zero => rfl
  | succ n ih => simp only [kernelCutoff, PMF.pure_bind, ih]

theorem kernel_loop_no_terminal_mass {S R : Type*} (s : S) (r : R) :
    kernelTerminalMass (fun x : S => PMF.pure (Sum.inr (α := R) x)) s r = 0 := by
  simp [kernelTerminalMass, kernel_loop_cutoff, PMF.pure_apply]

theorem kernel_loop_not_terminating {S R : Type*} (s : S) :
    ¬ KernelTerminatesAlmostSurely (fun x : S => PMF.pure (Sum.inr (α := R) x)) s := by
  simp [KernelTerminatesAlmostSurely, kernel_loop_cutoff, PMF.pure_apply]

end
end C10Probability

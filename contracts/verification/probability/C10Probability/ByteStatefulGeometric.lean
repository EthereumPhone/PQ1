import C10Probability.ByteStatefulBounds
import C10Probability.TerminatingKernelExamples
import C10Probability.KernelSimulation

/-! An inhabited whole initialized C10 game outside every uniform interaction
horizon. The client draws fresh private coins and eventually returns malformed
bytes. It exercises initialization and the actual final-refusal path, while
proving liveness without changing the oracle, cache or signing assumptions. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def byteGeometricStep (_ : Unit) : PMF (C10ByteAction Unit C10ByteForgery) :=
  (PMF.bernoulli (1 / 2) (by norm_num)).map
    (fun stop => if stop then .done ([], []) else .tick ())

theorem byte_geometric_step_simulation (cfg : C10SessionConfig)
    (sampler : PMF (Digest × C10StatefulByteAdversary Unit)) (initialQr initialQs : ℕ)
    (secret : Digest) (key : ByteKey × ByteKey) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table : Memo ByteKey Digest) (s : Unit) :
    c10StatefulByteGameStep cfg byteGeometricStep sampler initialQr initialQs
        (.run secret key ⟨s, qr, qs, ledger, table⟩) =
      (geometricKernel s).map (Sum.map (fun _ => (false, ⟨([], []), ledger, qr, qs⟩))
        (fun next => .run secret key ⟨next, qr, qs, ledger, table⟩)) := by
  simp only [c10StatefulByteGameStep, c10StatefulByteStep, byteGeometricStep, geometricKernel,
    PMF.bind_map, PMF.bind_bind, Function.comp_def, PMF.map_comp]
  rw [PMF.map]
  apply congrArg (PMF.bind (PMF.bernoulli (1 / 2) (by norm_num)))
  funext stop
  cases stop with
  | false => simp only [Function.comp_def, Bool.false_eq_true, ↓reduceIte, PMF.pure_bind, Sum.map_inr]
  | true =>
    simp only [Function.comp_def, ↓reduceIte, PMF.pure_bind, mapSessionValue, Sum.map_inl]
    have refused := c10_byte_cutoff_finish_pending (privateKey prefixedPrivateInput secret)
      (sessionConfigAt cfg key) qr qs ledger table
    simpa only [c10ByteCutoffFinish, mapSessionValue, byteOptionalForgery,
      Option.getD, PMF.pure_map] using
      congrArg (fun p => p.map (fun out => Sum.inl (β := C10ByteGameState Unit) out.1)) refused

theorem byte_geometric_finished_running (cfg : C10SessionConfig)
    (sampler : PMF (Digest × C10StatefulByteAdversary Unit)) (initialQr initialQs : ℕ)
    (secret : Digest) (key : ByteKey × ByteKey) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table : Memo ByteKey Digest) (n : ℕ) (s : Unit) :
    (kernelCutoff (c10StatefulByteGameStep cfg byteGeometricStep sampler initialQr initialQs) n
        (.run secret key ⟨s, qr, qs, ledger, table⟩)).map Sum.isLeft =
      (kernelCutoff geometricKernel n s).map Sum.isLeft := by
  exact   kernel_finished_simulation geometricKernel
    (c10StatefulByteGameStep cfg byteGeometricStep sampler initialQr initialQs)
    (fun _ => (false, ⟨([], []), ledger, qr, qs⟩))
    (fun next => .run secret key ⟨next, qr, qs, ledger, table⟩)
    (byte_geometric_step_simulation cfg sampler initialQr initialQs secret key qr qs ledger table) n s

theorem geometric_kernel_cutoff_state (n : ℕ) (s : Unit) :
    kernelCutoff geometricKernel n s = kernelCutoff geometricKernel n () := by
  cases s
  rfl

theorem byte_geometric_initialized_finished (cfg : C10SessionConfig)
    (sampler : PMF (Digest × C10StatefulByteAdversary Unit)) (qr qs n : ℕ) :
    (kernelCutoff (c10StatefulByteGameStep cfg byteGeometricStep sampler qr qs) (n + 1)
      .initialize).map Sum.isLeft = (kernelCutoff geometricKernel n ()).map Sum.isLeft := by
  simp only [kernelCutoff, c10StatefulByteGameStep, PMF.bind_bind, PMF.bind_map,
    Function.comp_def, PMF.map_bind, byte_geometric_finished_running,
    geometric_kernel_cutoff_state, PMF.bind_const]

theorem byte_geometric_initialized_completed (cfg : C10SessionConfig)
    (sampler : PMF (Digest × C10StatefulByteAdversary Unit)) (qr qs n : ℕ) :
    (∑' out, kernelCutoff (c10StatefulByteGameStep cfg byteGeometricStep sampler qr qs) (n + 1)
      .initialize (.inl out)) = 1 - (1 / 2 : ℝ≥0∞) ^ n := by
  rw [← kernel_finished_probability, byte_geometric_initialized_finished,
    kernel_finished_probability]
  simp only [tsum_fintype, Fintype.sum_unique]
  exact geometric_kernel_completed n

theorem byte_geometric_initialized_terminates (cfg : C10SessionConfig)
    (sampler : PMF (Digest × C10StatefulByteAdversary Unit)) (qr qs : ℕ) :
    C10StatefulByteTerminates cfg byteGeometricStep sampler qr qs := by
  change (⨆ n, ∑' out, kernelCutoff
    (c10StatefulByteGameStep cfg byteGeometricStep sampler qr qs) n .initialize (.inl out)) = 1
  apply le_antisymm
  · exact iSup_le (fun n => kernel_cutoff_total_le_one _ n _)
  · have complete := geometric_kernel_terminates
    simp only [KernelTerminatesAlmostSurely, tsum_fintype, Fintype.sum_unique] at complete
    change (⨆ n, kernelCutoff geometricKernel n () (.inl ())) = 1 at complete
    rw [← complete]
    refine iSup_le (fun n => ?_)
    rw [geometric_kernel_completed, ← byte_geometric_initialized_completed cfg sampler qr qs n]
    exact le_iSup (fun m : ℕ => ∑' out : C10ByteGameOutput,
      kernelCutoff (c10StatefulByteGameStep cfg byteGeometricStep sampler qr qs) m
        .initialize (.inl out)) (n + 1)

theorem byte_geometric_no_fixed_horizon (cfg : C10SessionConfig)
    (sampler : PMF (Digest × C10StatefulByteAdversary Unit)) (qr qs n : ℕ) :
    (∑' out, kernelCutoff (c10StatefulByteGameStep cfg byteGeometricStep sampler qr qs) n
      .initialize (.inl out)) < 1 := by
  cases n with
  | zero => simp [kernelCutoff, PMF.pure_apply]
  | succ n =>
    rw [byte_geometric_initialized_completed]
    exact ENNReal.sub_lt_self (by simp) (by simp) (pow_ne_zero n (by norm_num))

theorem byte_geometric_forge_bound (cfg : C10SessionConfig)
    (sampler : PMF (Digest × C10StatefulByteAdversary Unit)) (qr qs : ℕ) :
    (c10StatefulByteInitialized cfg byteGeometricStep sampler qr qs
      (byte_geometric_initialized_terminates cfg sampler qr qs)).toOuterMeasure
        {out | out.1 = true} ≤ min 1 (sharedForgeCharge cfg qr qs) := by
  exact c10_stateful_byte_forge_bound cfg byteGeometricStep sampler qr qs
    (byte_geometric_initialized_terminates cfg sampler qr qs)

end
end C10Probability

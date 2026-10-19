import C10Probability.HmsgPool
import C10Probability.SampleCompletion
import C10Probability.ForsCoverageBound

/-! A completion potential bounds the actual memoized accepted pool. Only
fresh selected accepted replies advance the sample pool; all other random
draws and cache hits retain their original interpreter semantics. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem pmf_weighted_bound {α : Type*} (p : PMF α) (f g : α → ℝ≥0∞)
    (bound : ∀ value ∈ p.support, f value ≤ g value) :
    (∑' value, p value * f value) ≤ ∑' value, p value * g value := by
  apply ENNReal.tsum_le_tsum
  intro value
  by_cases supported : value ∈ p.support
  · exact mul_le_mul_right (bound value supported) _
  · simp only [(p.apply_eq_zero_iff value).mpr supported, zero_mul, le_refl]

theorem hmsg_pool_completion_bound {K R : Type*} [DecidableEq K]
    (select : K → Bool) {n : ℕ} (program : QueryProgram K Digest R n)
    (table : Memo K Digest) (cap : ℕ) (event : List Digest → Prop)
    (closed : SampleExtensionClosed event) (pool : List Digest) :
    (hmsgPoolProgram select program table).toOuterMeasure
      {out | (pool ++ out.entries.map Prod.snd).length ≤ cap ∧
        event (pool ++ out.entries.map Prod.snd)} ≤
      sampleCompletion acceptedForsDraw cap event pool := by
  classical
  induction program generalizing table pool with
  | done value =>
    simpa only [hmsgPoolProgram, PMF.toOuterMeasure_pure_apply,
      Set.mem_setOf_eq, List.map_nil, List.append_nil] using
      sample_completion_dominates acceptedForsDraw cap event closed pool
  | query key next ih =>
    cases cached : table key with
    | some value =>
      rw [hmsg_pool_program_cached select key next table value cached]
      exact ih value table pool
    | none =>
      rw [hmsg_pool_program_fresh select key next table cached]
      cases selected : select key with
      | false =>
        rw [PMF.toOuterMeasure_bind_apply]
        calc
          _ ≤ ∑' value, digestDraw value *
              sampleCompletion acceptedForsDraw cap event pool := by
            apply pmf_weighted_bound
            intro value _
            rw [PMF.toOuterMeasure_map_apply]
            simpa only [Set.preimage_setOf_eq,
              hmsg_pool_prepend_other select key value _ (Or.inl selected)] using
              ih value (Function.update table key (some value)) pool
          _ = _ := by rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]
      | true =>
        rw [← digest_fors_acceptance_split, PMF.bind_bind,
          PMF.toOuterMeasure_bind_apply]
        calc
          _ ≤ ∑' accepted, forsAcceptanceCoin accepted *
              sampleCompletion acceptedForsDraw cap event pool := by
            apply pmf_weighted_bound
            intro accepted _
            cases accepted with
            | false =>
              simp only [Bool.false_eq_true, ↓reduceIte]
              rw [PMF.toOuterMeasure_bind_apply]
              calc
                _ ≤ ∑' value, rejectedForsDraw value *
                    sampleCompletion acceptedForsDraw cap event pool := by
                  apply pmf_weighted_bound
                  intro value supported
                  have rejected := (rejected_fors_support value).mp supported
                  rw [PMF.toOuterMeasure_map_apply]
                  simpa only [Set.preimage_setOf_eq,
                    hmsg_pool_prepend_other select key value _ (Or.inr rejected)] using
                    ih value (Function.update table key (some value)) pool
                _ = _ := by rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]
            | true =>
              simp only [↓reduceIte]
              rw [PMF.toOuterMeasure_bind_apply]
              calc
                _ ≤ ∑' value, acceptedForsDraw value *
                    sampleCompletion acceptedForsDraw cap event (pool ++ [value]) := by
                  apply pmf_weighted_bound
                  intro value supported
                  have accepted := (accepted_fors_support value).mp supported
                  rw [PMF.toOuterMeasure_map_apply]
                  simpa only [Set.preimage_setOf_eq,
                    hmsg_pool_prepend_selected select key value _ selected accepted,
                    List.map_cons, List.append_assoc, List.singleton_append] using
                    ih value (Function.update table key (some value)) (pool ++ [value])
                _ ≤ _ := sample_completion_step acceptedForsDraw cap event pool
          _ = _ := by rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]

theorem hmsg_pool_prefix_bound {K R : Type*} [DecidableEq K]
    (select : K → Bool) {n : ℕ} (program : QueryProgram K Digest R n)
    (table : Memo K Digest) (cap : ℕ) (event : List Digest → Prop)
    (closed : SampleExtensionClosed event) :
    (hmsgPoolProgram select program table).toOuterMeasure
      {out | out.entries.length ≤ cap ∧ event (out.entries.map Prod.snd)} ≤
      (iidSampleList acceptedForsDraw cap).toOuterMeasure {xs | event xs} := by
  simpa only [List.nil_append, List.length_map, sample_completion_empty] using
    hmsg_pool_completion_bound select program table cap event closed []

theorem hmsg_pool_coverage_bound {K R : Type*} [DecidableEq K]
    (select : K → Bool) {n : ℕ} (program : QueryProgram K Digest R n)
    (table : Memo K Digest) (cap : ℕ) :
    (hmsgPoolProgram select program table).toOuterMeasure
      {out | out.entries.length ≤ cap ∧ ForsListCoverage (out.entries.map Prod.snd)} ≤
      forsCoverageCharge cap := by
  have transfer := hmsg_pool_prefix_bound select program table cap ForsListCoverage
    fors_list_coverage_extension
  rw [← accepted_fors_samples_list, PMF.toOuterMeasure_map_apply] at transfer
  simp only [Set.preimage_setOf_eq, fors_list_coverage_ofFn] at transfer
  exact transfer.trans (iid_fors_coverage_bound cap)

theorem randomized_hmsg_pool_coverage_bound {K R : Type*} [DecidableEq K]
    (select : K → Bool) {n : ℕ} (client : PMF (QueryProgram K Digest R n))
    (table : Memo K Digest) (cap : ℕ) :
    (client.bind (fun program => hmsgPoolProgram select program table)).toOuterMeasure
      {out | out.entries.length ≤ cap ∧ ForsListCoverage (out.entries.map Prod.snd)} ≤
      forsCoverageCharge cap := by
  rw [PMF.toOuterMeasure_bind_apply]
  calc
    _ ≤ ∑' program, client program * forsCoverageCharge cap := by
      apply pmf_weighted_bound
      intro program _
      exact hmsg_pool_coverage_bound select program table cap
    _ = _ := by rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]

theorem randomized_hmsg_pool_coverage_bound_real {K R : Type*} [DecidableEq K]
    (select : K → Bool) {n : ℕ} (client : PMF (QueryProgram K Digest R n))
    (table : Memo K Digest) (cap : ℕ) :
    ((client.bind (fun program => hmsgPoolProgram select program table)).toOuterMeasure
      {out | out.entries.length ≤ cap ∧ ForsListCoverage (out.entries.map Prod.snd)}).toReal ≤
      (forsCoverageCharge cap).toReal := by
  exact ENNReal.toReal_mono (fors_coverage_charge_ne_top cap)
    (randomized_hmsg_pool_coverage_bound select client table cap)

end
end C10Probability

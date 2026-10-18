import C10Probability.SamplePrefix

/-! Actual finite adaptive executions distinguish stopping, observed caps and
events that are not preserved by extending a sample history. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def stopOnTrueSample : SampleProgram Bool Unit 2 :=
  .sample fun first => if first then .done () else .sample fun _ => .done ()

theorem sample_contains_true_extension :
    SampleExtensionClosed (fun xs : List Bool => true ∈ xs) := by
  intro before after h
  exact List.mem_append_left after h

theorem sample_exact_length_not_extension :
    ¬ SampleExtensionClosed (fun xs : List Bool => xs.length = 1) := by
  intro closed
  have impossible := closed [true] [false] rfl
  simp at impossible

theorem adaptive_sample_one_cap_mass :
    (evalSampleProgram fairReply stopOnTrueSample).toOuterMeasure
      {out | out.2.length ≤ 1 ∧ true ∈ out.2} = (2 : ℝ≥0∞)⁻¹ := by
  norm_num [evalSampleProgram, stopOnTrueSample, fairReply, PMF.toOuterMeasure_bind_apply,
    PMF.toOuterMeasure_map_apply, tsum_fintype]

theorem adaptive_sample_two_cap_mass :
    (evalSampleProgram fairReply stopOnTrueSample).toOuterMeasure
      {out | out.2.length ≤ 2 ∧ true ∈ out.2} = (3 : ℝ≥0∞) / 4 := by
  norm_num [evalSampleProgram, stopOnTrueSample, fairReply, PMF.toOuterMeasure_bind_apply,
    PMF.toOuterMeasure_map_apply, tsum_fintype]
  apply (ENNReal.toReal_eq_toReal_iff' (by finiteness) (by finiteness)).mp
  rw [ENNReal.toReal_add (by finiteness) (by finiteness)]
  norm_num [ENNReal.toReal_mul]

theorem stopped_sample_exact_length_mass :
    (evalSampleProgram fairReply stopOnTrueSample).toOuterMeasure {out | out.2.length = 1} =
      (2 : ℝ≥0∞)⁻¹ := by
  norm_num [evalSampleProgram, stopOnTrueSample, fairReply, PMF.toOuterMeasure_bind_apply,
    PMF.toOuterMeasure_map_apply, tsum_fintype]

theorem iid_two_sample_exact_length_mass :
    (iidSampleList fairReply 2).toOuterMeasure {xs | xs.length = 1} = 0 := by
  norm_num [iidSampleList, fairReply, PMF.toOuterMeasure_bind_apply,
    PMF.toOuterMeasure_map_apply, tsum_fintype]

end
end C10Probability

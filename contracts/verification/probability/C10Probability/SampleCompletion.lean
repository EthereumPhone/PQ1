import C10Probability.SamplePrefix

/-! Completion potential for a partially observed fresh sample pool.
Internal random choices may preserve this potential without adding a sample. -/
namespace C10Probability
open scoped ENNReal
noncomputable section
attribute [local instance] Classical.propDecidable

def sampleCompletion {α : Type*} (p : PMF α) (cap : ℕ)
    (event : List α → Prop) (pool : List α) : ℝ≥0∞ :=
  if pool.length ≤ cap then
    (iidSampleList p (cap - pool.length)).toOuterMeasure
      {more | event (pool ++ more)}
  else 0

theorem sample_completion_empty {α : Type*} (p : PMF α) (cap : ℕ)
    (event : List α → Prop) :
    sampleCompletion p cap event [] = (iidSampleList p cap).toOuterMeasure {xs | event xs} := by
  simp only [sampleCompletion, List.length_nil, Nat.zero_le, ↓reduceIte,
    Nat.sub_zero, List.nil_append]

theorem sample_completion_over_cap {α : Type*} (p : PMF α) (cap : ℕ)
    (event : List α → Prop) (pool : List α) (tooLong : cap < pool.length) :
    sampleCompletion p cap event pool = 0 := by
  simp only [sampleCompletion, not_le_of_gt tooLong, ↓reduceIte]

theorem sample_completion_full {α : Type*} (p : PMF α) (event : List α → Prop)
    (pool : List α) :
    sampleCompletion p pool.length event pool = if event pool then 1 else 0 := by
  classical
  simp [sampleCompletion, iidSampleList]

theorem sample_completion_step {α : Type*} (p : PMF α) (cap : ℕ)
    (event : List α → Prop) (pool : List α) :
    (∑' value, p value * sampleCompletion p cap event (pool ++ [value])) ≤
      sampleCompletion p cap event pool := by
  classical
  by_cases room : pool.length < cap
  · have le : pool.length ≤ cap := Nat.le_of_lt room
    have nextle : pool.length + 1 ≤ cap := room
    have split : cap - pool.length = (cap - (pool.length + 1)) + 1 := by omega
    have equation : sampleCompletion p cap event pool =
        ∑' value, p value * sampleCompletion p cap event (pool ++ [value]) := by
      simp only [sampleCompletion, List.length_append, List.length_singleton,
        le, nextle, ↓reduceIte]
      rw [split, iidSampleList, PMF.toOuterMeasure_bind_apply]
      apply tsum_congr
      intro value
      rw [PMF.toOuterMeasure_map_apply]
      simp only [Set.preimage_setOf_eq, List.append_assoc, List.singleton_append]
    exact le_of_eq equation.symm
  · have past : ∀ value : α, cap < (pool ++ [value]).length := by
      intro value
      simp only [List.length_append, List.length_singleton]
      omega
    simp only [sample_completion_over_cap p cap event _ (past _), mul_zero, tsum_zero]
    exact zero_le _

theorem sample_completion_dominates {α : Type*} (p : PMF α) (cap : ℕ)
    (event : List α → Prop) (closed : SampleExtensionClosed event) (pool : List α) :
    (if pool.length ≤ cap ∧ event pool then 1 else 0) ≤
      sampleCompletion p cap event pool := by
  classical
  by_cases hit : pool.length ≤ cap ∧ event pool
  · have certain : (iidSampleList p (cap - pool.length)).toOuterMeasure
        {more | event (pool ++ more)} = 1 := by
      apply (PMF.toOuterMeasure_apply_eq_one_iff _ _).2
      intro more _
      exact closed pool more hit.2
    rw [if_pos hit, sampleCompletion, if_pos hit.1, certain]
  · simp only [hit, ↓reduceIte]
    exact zero_le _

end
end C10Probability

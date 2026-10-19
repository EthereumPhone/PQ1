import C10Probability.HmsgSession
import C10Probability.HmsgPoolOrigin

/-! Distinct selected accepted cache keys supply distinct pool positions.
Cache hits and repeated signing records cannot create extra sample positions. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def HmsgCacheCoverage {K : Type*} (select : K → Bool) (table : Memo K Digest) : Prop :=
  ∃ targetKey target, select targetKey = true ∧ forsAccept (forsOfDigest target) = true ∧
    table targetKey = some target ∧ ∀ coordinate : Fin 12, ∃ key value,
      key ≠ targetKey ∧ select key = true ∧ forsAccept (forsOfDigest value) = true ∧
      table key = some value ∧ hypertreeIndex value = hypertreeIndex target ∧
      forestIndex value coordinate.val = forestIndex target coordinate.val

theorem hmsg_pool_cache_coverage {K R : Type*} [DecidableEq K] (select : K → Bool)
    {n : ℕ} (program : QueryProgram K Digest R n) (out : HmsgPoolOutput K R)
    (supported : out ∈ (hmsgPoolProgram select program (fun _ => none)).support)
    (covered : HmsgCacheCoverage select out.cache) :
    ForsListCoverage (out.entries.map Prod.snd) := by
  obtain ⟨targetKey, target, selected, accepted, lookup, witnesses⟩ := covered
  have targetMember := hmsg_pool_empty_complete select program out supported targetKey target
    selected accepted lookup
  obtain ⟨targetIndex, targetEqual⟩ := List.mem_iff_get.mp targetMember
  let targetPosition : Fin (out.entries.map Prod.snd).length :=
    ⟨targetIndex.val, by simpa only [List.length_map] using targetIndex.isLt⟩
  have targetDigest : (out.entries.map Prod.snd)[targetPosition] = target := by
    simpa only [Fin.getElem_fin, List.getElem_map, targetPosition, ← List.get_eq_getElem] using
      congrArg Prod.snd targetEqual
  refine ⟨targetPosition, ?_⟩
  intro coordinate
  obtain ⟨key, value, different, keySelected, valueAccepted, valueLookup, address, index⟩ :=
    witnesses coordinate
  have member := hmsg_pool_empty_complete select program out supported key value
    keySelected valueAccepted valueLookup
  obtain ⟨position, positionEqual⟩ := List.mem_iff_get.mp member
  let witnessPosition : Fin (out.entries.map Prod.snd).length :=
    ⟨position.val, by simpa only [List.length_map] using position.isLt⟩
  have witnessDigest : (out.entries.map Prod.snd)[witnessPosition] = value := by
    simpa only [Fin.getElem_fin, List.getElem_map, witnessPosition, ← List.get_eq_getElem] using
      congrArg Prod.snd positionEqual
  refine ⟨witnessPosition, ?_, ?_, ?_⟩
  · intro same
    have indices : position = targetIndex := Fin.ext
      (congrArg (fun i : Fin (out.entries.map Prod.snd).length => i.val) same)
    rw [indices] at positionEqual
    exact different (congrArg Prod.fst (positionEqual.symm.trans targetEqual))
  · simpa only [witnessDigest, targetDigest] using address
  · simpa only [witnessDigest, targetDigest] using index

theorem c10_observed_cache_coverage_bound (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    (c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure
      {out | HmsgCacheCoverage hmsgQuery out.2} ≤ forsCoverageCharge (qr + qs + 1) := by
  rw [← c10_observed_pool_erases cfg sampler qr qs, PMF.toOuterMeasure_map_apply]
  apply (PMF.toOuterMeasure_mono _ ?_).trans (c10_observed_pool_coverage_bound cfg sampler qr qs)
  intro out hit
  obtain ⟨covered, supported⟩ := hit
  rw [c10ObservedPool, PMF.mem_support_bind_iff] at supported
  obtain ⟨input, _, supported⟩ := supported
  exact hmsg_pool_cache_coverage hmsgQuery
    (c10ObservedGameProgram id cfg input.1 input.2 qr qs) out supported covered

theorem c10_observed_cache_coverage_bound_real (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    ((c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure
      {out | HmsgCacheCoverage hmsgQuery out.2}).toReal ≤
      (forsCoverageCharge (qr + qs + 1)).toReal := by
  exact ENNReal.toReal_mono (fors_coverage_charge_ne_top _)
    (c10_observed_cache_coverage_bound cfg sampler qr qs)

end
end C10Probability

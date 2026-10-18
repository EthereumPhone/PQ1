import C10Probability.ObservedForestDescent
import C10Probability.ExposureExamples

/-! Finite boundary witnesses, including actual recovery-default behavior.
Synthetic records below test coordinate coverage only; they are not claimed
to be valid signing histories or initialized winning games. -/
namespace C10Probability
noncomputable section
set_option maxRecDepth 4096

def forestRecordFixture (digest : Digest) : C10SigningRecord :=
  { exposureRecordFixture 0 0 0 with digest := digest }

theorem forest_coverage_empty (digest : Digest) (i : Fin 12) :
    ¬ ForestIndexCovered [] digest i := by
  simp only [ForestIndexCovered, List.not_mem_nil, false_and, exists_false, not_false_eq_true]

theorem forest_coverage_duplicates (records : List C10SigningRecord) (digest : Digest) (i : Fin 12) :
    ForestIndexCovered (records ++ records) digest i ↔ ForestIndexCovered records digest i := by
  simp only [ForestIndexCovered, List.mem_append, or_self]

theorem forest_coverage_can_mix_prior_signatures :
    (∀ i : Fin 12, ForestIndexCovered [forestRecordFixture 1, forestRecordFixture 2048] 0 i) ∧
      (∀ prior ∈ [forestRecordFixture 1, forestRecordFixture 2048], prior.digest ≠ 0) := by
  constructor
  · intro i
    fin_cases i <;>
      simp only [ForestIndexCovered, List.mem_cons, exists_eq_or_imp] <;> decide +kernel
  · simp only [List.mem_cons, forall_eq_or_imp, forestRecordFixture]
    decide +kernel

theorem forest_coverage_needs_full_hypertree :
    let first := exposureRecordFixture 513 0 0
    let second := exposureRecordFixture 1025 0 0
    hypertreeLeaf (hypertreeIndex first.digest) = hypertreeLeaf (hypertreeIndex second.digest) ∧
      forestIndex first.digest 0 = forestIndex second.digest 0 ∧
      ¬ ForestIndexCovered [first] second.digest 0 := by
  simp only [ForestIndexCovered, List.mem_singleton, exists_eq_left]
  decide +kernel

theorem forest_compression_preserves_order :
    forsPkInput [] 0 (1 :: List.replicate 12 0) ≠
      forsPkInput [] 0 (List.replicate 12 0 ++ [1]) := by
  intro equal
  have roots := fors_pk_input_injective [] 0 equal
  have first := congrArg (fun values : List Randomizer => values[0]?) roots
  contradiction

theorem forest_last_root_is_separate_position :
    ((List.replicate 13 (0 : Randomizer)).set 12 1)[12]? = some 1 ∧
      (∀ i : Fin 12, ((List.replicate 13 (0 : Randomizer)).set 12 1)[i.val]? = some 0) ∧
      ¬ (12 < 12) := by
  decide +kernel

theorem forest_missing_arrays_use_defaults :
    replayProgram (fun _ : ByteKey => some (0 : Digest))
      (forestRecoverProgram id [] 0 0 [] []) = some 0 := by
  rfl

theorem forest_unmatched_can_have_populated_cache :
    ForestHistoryUnmatched id (fun _ : WotsQuery => some (0 : Digest)) [] 0 [0] ∧
      (fun _ : WotsQuery => some (0 : Digest)) (.inr (forsPrivateTail 0 0 0)) = some 0 := by
  refine ⟨⟨0, ?_, 0, rfl, rfl⟩, rfl⟩
  intro prior member
  cases member

end
end C10Probability

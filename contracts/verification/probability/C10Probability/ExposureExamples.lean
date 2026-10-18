import C10Probability.C10ExposureMinimum

/-! Nonconstant accepted words expose the failure of an arbitrary mixed-word
minimum argument. Synthetic records below test address filtering and occurrence
order only; they are not claimed to be valid signing executions. -/
namespace C10Probability
noncomputable section
set_option maxRecDepth 4096

def exposureTail (i : Fin 43) : Fin 8 :=
  if i.val < 29 then 7 else if i.val = 29 then 4 else 0

def exposureWordA : WotsWord := fun i =>
  if i.val < 4 then (if i.val % 2 = 0 then 7 else 6) else exposureTail i

def exposureWordB : WotsWord := fun i =>
  if i.val < 4 then (if i.val % 2 = 1 then 7 else 6) else exposureTail i

def exposureWordMix : WotsWord := fun i =>
  if i.val < 4 then (if i.val = 0 ∨ i.val = 3 then 7 else 6) else exposureTail i

theorem exposure_three_words_accepted :
    wotsAccept exposureWordA = true ∧ wotsAccept exposureWordB = true ∧
      wotsAccept exposureWordMix = true := by decide +kernel

theorem exposure_mixed_minimum_sum :
    (∑ i, wotsExposureMinimum [exposureWordA, exposureWordB] i) = 203 := by decide +kernel

theorem exposure_mixture_never_below_minimum :
    ¬ ∃ i, (exposureWordMix i).val < wotsExposureMinimum [exposureWordA, exposureWordB] i := by
  decide +kernel

theorem exposure_mixture_differs_from_both :
    exposureWordMix ≠ exposureWordA ∧ exposureWordMix ≠ exposureWordB := by
  constructor
  · intro equal
    have same := congrFun equal (2 : Fin 43)
    contradiction
  · intro equal
    have same := congrFun equal (0 : Fin 43)
    contradiction

theorem exposure_comparison_needs_uniformity :
    ¬ ((∃ prior ∈ [exposureWordA, exposureWordB], exposureWordMix = prior) ∨
      ∃ i, (exposureWordMix i).val < wotsExposureMinimum [exposureWordA, exposureWordB] i) := by
  obtain ⟨notA, notB⟩ := exposure_mixture_differs_from_both
  intro claimed
  rcases claimed with ⟨prior, member, equal⟩ | earlier
  · rcases List.mem_cons.mp member with same | last
    · exact notA (equal.trans same)
    · exact notB (equal.trans (List.mem_singleton.mp last))
  · exact exposure_mixture_never_below_minimum earlier

theorem exposure_minimum_retains_all_words :
    [wotsExposureMinimum [exposureWordA, exposureWordB, exposureWordA] 0,
      wotsExposureMinimum [exposureWordA, exposureWordB, exposureWordA] 1] = [6, 6] := by
  decide +kernel

theorem exposure_repeated_word_minimum :
    ∀ i, wotsExposureMinimum [exposureWordA, exposureWordA, exposureWordA] i =
      (exposureWordA i).val := by decide +kernel

theorem exposure_empty_minimum_endpoint :
    ∀ i, wotsExposureMinimum [] i = 7 := by decide +kernel

def exposureRecordFixture (ht : ℕ) (lower upper : Digest) : C10SigningRecord :=
  ⟨0, ⟨(ht * 2 ^ 143) % 2 ^ 256, Nat.mod_lt _ (by decide)⟩,
    ⟨[], [], 0⟩, emptyLayerSignature, emptyLayerSignature,
    0, 0, lower, upper⟩

def exposureRecordFixtures : List C10SigningRecord :=
  [exposureRecordFixture 513 1 2, exposureRecordFixture 1025 3 4,
    exposureRecordFixture 514 5 6, exposureRecordFixture 513 7 0]

theorem exposure_lower_filter_keeps_tree_leaf_and_order :
    (lowerExposureWords exposureRecordFixtures 1 1).map (fun word => (word 0).val) = [1, 7] := by
  decide +kernel

theorem exposure_upper_filter_uses_parent_coordinate :
    (upperExposureWords exposureRecordFixtures 1).map (fun word => (word 0).val) = [2, 6, 0] := by
  decide +kernel

theorem exposure_filter_retains_repeated_occurrences :
    (upperExposureWords [exposureRecordFixture 513 1 2, exposureRecordFixture 513 1 2] 1).length = 2 := by
  decide +kernel

theorem exposure_unseen_address_has_endpoint_minimum :
    upperExposureWords exposureRecordFixtures 9 = [] ∧
      wotsExposureMinimum (upperExposureWords exposureRecordFixtures 9) 0 = 7 := by
  decide +kernel

end
end C10Probability

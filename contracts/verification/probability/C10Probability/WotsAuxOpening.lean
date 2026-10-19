import C10Probability.WotsLeafOpening
import C10Probability.OpeningGrind

/-! Count and shuffle calls are kept as ordinary full-digest queries. Their
actual byte widths separate them from the selected chain input. Count calls
also have zero variable-candidate charge, independently of their cached state. -/
namespace C10Probability
noncomputable section

theorem wots_public_width_ne_incoming (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (key : ByteKey) (different : key.length ≠ seed.length + 64) :
    (.inl key : WotsQuery) ≠ wotsCutIncoming seed target previous := by
  intro equal
  by_cases zero : target.2.val = 0
  · rw [wots_cut_incoming_zero seed target previous zero] at equal
    exact wots_target_not_public target.1 _ equal
  · rw [wots_cut_incoming_positive seed target previous (by omega)] at equal
    have lengths := congrArg List.length (Sum.inl.inj equal)
    simp only [wotsChainInput, List.length_append, c10_address_length,
      List.length_ofFn, List.length_replicate] at lengths
    apply different
    omega

theorem wots_count_ne_incoming (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (layer tree kp : ℕ) (message : ByteKey) (nonce : Counter) :
    (.inl (counterKey (wotsCountStem seed layer tree kp message) nonce) : WotsQuery) ≠
      wotsCutIncoming seed target previous := by
  apply wots_public_width_ne_incoming
  simp only [counter_key_length, wotsCountStem, List.length_append, c10_address_length,
    List.length_replicate]
  omega

theorem wots_count_opening_sealed (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (layer tree kp : ℕ) (message : ByteKey)
    (start n : ℕ) (hb : start + n ≤ 2 ^ 32) :
    OpeningSealed (wotsCutIncoming seed target previous)
      (liftOpening (P := Unit) (H := Digest) (mapProgram Sum.inl
        (wotsCountProgram seed layer tree kp message start n hb))) := by
  apply query_exclusion_sealed
  rw [queryExclusion_map, wotsCountProgram, queryExclusion_cast]
  apply queryExclusion_count
  intro key member
  obtain ⟨i, rfl⟩ := List.mem_ofFn.mp member
  exact decide_eq_false (wots_count_ne_incoming seed target previous layer tree kp message _)

theorem wots_count_opening_budget (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (start n : ℕ) (hb : start + n ≤ 2 ^ 32) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (liftOpening (P := Unit) (H := Digest) (mapProgram Sum.inl
        (wotsCountProgram seed layer tree kp message start n hb)))) 0 := by
  rw [redact_opening_lift, selectedBudget_mapReturn, selectedBudget_map]
  apply query_exclusion_selected
  rw [queryExclusion_map, wotsCountProgram, queryExclusion_cast]
  apply queryExclusion_count
  intro key member
  obtain ⟨i, rfl⟩ := List.mem_ofFn.mp member
  exact node_counter_candidate_fixed _ _

theorem wots_shuffle_blocks_cut_excluded (seed shuffle : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (width : shuffle.length = 32) (start n : ℕ) :
    QueryExclusion (fun key => decide (key = wotsCutIncoming seed target previous)) (fun _ => True)
      (shuffleBlocksProgram Sum.inl shuffle start n) := by
  induction n generalizing start with
  | zero => trivial
  | succ n ih =>
    refine ⟨?_, fun reply => ?_⟩
    · apply decide_eq_false
      apply wots_public_width_ne_incoming
      rw [shuffle_block_input_length shuffle start width]
      omega
    · rw [queryExclusion_mapReturn]
      exact ih (start + 1)

theorem wots_shuffle_opening_sealed (seed shuffle : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (width : shuffle.length = 32) :
    OpeningSealed (wotsCutIncoming seed target previous)
      (liftOpening (P := Unit) (H := Digest) (wotsShuffleProgram Sum.inl shuffle)) := by
  apply query_exclusion_sealed
  by_cases zero : shuffle = List.replicate 32 0
  · rw [wotsShuffleProgram, if_pos zero]
    trivial
  · rw [wotsShuffleProgram, if_neg zero, queryExclusion_mapReturn]
    exact wots_shuffle_blocks_cut_excluded seed shuffle target previous width 0 4

end
end C10Probability

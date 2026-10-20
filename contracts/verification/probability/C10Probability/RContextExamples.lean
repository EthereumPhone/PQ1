import C10Probability.RSessionExamples

/-! Independent byte-layout and refusal witnesses. A malformed message can
move bytes across the optional-randomness boundary; admission excludes it.
The nonce is a u32 value encoded in the model's full 32-byte big-endian field. -/
namespace C10Probability
noncomputable section

theorem r_context_tail_zero_vector :
    rContextTail rExampleContext 0 =
      [82, 95, 103, 114, 105, 110, 100] ++ List.replicate 64 0 := by decide +kernel

theorem r_context_tail_max_vector :
    rContextTail rExampleContext ⟨2 ^ 32 - 1, by decide⟩ =
      [82, 95, 103, 114, 105, 110, 100] ++ List.replicate 60 0 ++
        [255, 255, 255, 255] := by decide +kernel

theorem r_context_optional_randomness_vectors :
    (rContextTail rExampleContext 0).length = 71 ∧
    (rContextTail (List.replicate 16 7, List.replicate 32 0) 0).length = 87 ∧
    rContextTail rExampleContext 0 ≠
      rContextTail (List.replicate 16 7, List.replicate 32 0) 0 := by decide +kernel

theorem r_context_malformed_resegmentation :
    rContextTail ([], List.replicate 48 0) 0 =
      rContextTail (List.replicate 16 0, List.replicate 32 0) 0 ∧
    rSessionAdmits emptyRGrindLedger ([], List.replicate 48 0) = false ∧
    rSessionAdmits emptyRGrindLedger (List.replicate 16 0, List.replicate 32 0) = true := by
  decide +kernel

theorem r_context_distinct_message_vector :
    rContextTail ([], List.replicate 32 0) 0 ≠
      rContextTail ([], List.replicate 32 1) 0 := by decide +kernel

end
end C10Probability

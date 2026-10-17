import C10Probability.WotsFillReplay
import C10Probability.WotsSigning

/-! Successful signing supplies the actual accepted count-program result
and every positional private-seeded prefix, including shuffled fill order.
No premise asserts that a returned signature verifies correctly. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem replay_wots_accepted_fill_positions (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (word : WotsWord)
    (accepted : wotsAccept word = true) (order : WotsOrder) (sigma : WotsSigma)
    (recorded : replayProgram table
      (wotsAcceptedFillProgram encode seed layer tree kp word accepted order) = some sigma) :
    ∀ i, replayProgram table (wotsSeedChainProgram encode seed layer tree kp i.val
      (word i).val) = some (sigma i) := by
  rw [wotsAcceptedFillProgram, replay_program_cast] at recorded
  have positions := (replay_wots_fill_positions encode table seed layer tree kp
    (fun i => (word i).val) order.val wotsZeroSigma sigma recorded).1
  intro i
  apply positions i
  exact order.property.mem_iff.mpr (by simp only [wotsIndices, List.mem_ofFn]; exact ⟨i, rfl⟩)

theorem replay_wots_sign_after_success (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (shuffle : ByteKey)
    (selected : Option (ℕ × Digest)) (sigma : WotsSigma) (count : ℕ)
    (recorded : replayProgram table
      (wotsSignAfterProgram encode seed layer tree kp shuffle selected) = some (some (sigma, count))) :
    ∃ digest, selected = some (count, digest) ∧ wotsAccept (wotsOfDigest digest) = true ∧
      ∀ i, replayProgram table (wotsSeedChainProgram encode seed layer tree kp i.val
        (wotsOfDigest digest i).val) = some (sigma i) := by
  cases selected with
  | none => simp only [wotsSignAfterProgram, replayProgram, Option.some.injEq] at recorded; cases recorded
  | some selected =>
    obtain ⟨chosenCount, digest⟩ := selected
    by_cases accepted : wotsAccept (wotsOfDigest digest) = true
    · simp only [wotsSignAfterProgram, accepted, ↓reduceDIte, replay_program_bind,
        replay_program_map_return] at recorded
      cases order : replayProgram table (wotsShuffleProgram (fun key => encode (.inl key)) shuffle) with
      | none => simp only [order, Option.bind_none] at recorded; cases recorded
      | some visit =>
        simp only [order, Option.bind_some] at recorded
        cases filled : replayProgram table
          (wotsAcceptedFillProgram encode seed layer tree kp (wotsOfDigest digest) accepted visit) with
        | none => simp only [filled, Option.map_none] at recorded; cases recorded
        | some result =>
          simp only [filled, Option.map_some, Option.some.injEq, Prod.mk.injEq] at recorded
          obtain ⟨rfl, rfl⟩ := recorded
          exact ⟨digest, rfl, accepted,
            replay_wots_accepted_fill_positions encode table seed layer tree kp
              (wotsOfDigest digest) accepted visit result filled⟩
    · rw [wotsSignAfterProgram, dif_neg accepted] at recorded
      cases recorded

theorem replay_wots_sign_witness (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (message shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) (sigma : WotsSigma) (count : ℕ)
    (recorded : replayProgram table
      (wotsSignProgram encode seed layer tree kp message shuffle n bound) = some (some (sigma, count))) :
    ∃ digest, replayProgram table (mapProgram (fun key => encode (.inl key))
      (wotsCountProgram seed layer tree kp message 0 n (by simpa using bound))) =
        some (some (count, digest)) ∧
      wotsAccept (wotsOfDigest digest) = true ∧
      ∀ i, replayProgram table (wotsSeedChainProgram encode seed layer tree kp i.val
        (wotsOfDigest digest i).val) = some (sigma i) := by
  rw [wotsSignProgram, replay_program_cast, replay_program_bind] at recorded
  cases counted : replayProgram table (mapProgram (fun key => encode (.inl key))
    (wotsCountProgram seed layer tree kp message 0 n (by simpa using bound))) with
  | none => simp only [counted, Option.bind_none] at recorded; cases recorded
  | some selected =>
    simp only [counted, Option.bind_some] at recorded
    obtain ⟨digest, choice, accepted, positions⟩ := replay_wots_sign_after_success encode table
      seed layer tree kp shuffle selected sigma count recorded
    exact ⟨digest, congrArg some choice, accepted, positions⟩

end
end C10Probability

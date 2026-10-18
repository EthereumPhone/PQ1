import C10Probability.QueryReplay
import C10Probability.WotsRecoveryUnder

/-! An actual successful bounded count search records its selected input and
accepted digest. The returned index and its full-width recovery encoding are
derived from the executed schedule, without a fresh-query premise. -/
namespace C10Probability
noncomputable section

variable {K J α : Type*}

theorem replay_count_success (encode : K → J) (table : Memo J α)
    (accept : α → Bool) (start : ℕ) (keys : List K) (count : ℕ) (reply : α)
    (recorded : replayProgram table (mapProgram encode (countProgram accept start keys)) =
      some (some (count, reply))) :
    ∃ i : Fin keys.length, count = start + i.val ∧
      table (encode keys[i.val]) = some reply ∧ accept reply = true := by
  induction keys generalizing start with
  | nil => cases recorded
  | cons key keys ih =>
    cases cached : table (encode key) with
    | none =>
      simp only [countProgram, mapProgram, replayProgram, cached, Option.bind_none] at recorded
      cases recorded
    | some digest =>
      simp only [countProgram, mapProgram, replayProgram, cached, Option.bind_some] at recorded
      by_cases accepted : accept digest = true
      · simp only [accepted, ↓reduceIte, mapProgram, replayProgram, Option.some.injEq,
          Prod.mk.injEq] at recorded
        obtain ⟨rfl, rfl⟩ := recorded
        exact ⟨⟨0, by simp⟩, by simp, by simpa using cached, accepted⟩
      · simp only [accepted] at recorded
        obtain ⟨i, value, lookup, valid⟩ := ih (start + 1) recorded
        refine ⟨⟨i.val + 1, Nat.succ_lt_succ i.isLt⟩, ?_, ?_, valid⟩
        · change count = start + (i.val + 1)
          omega
        · simpa only [List.getElem_cons_succ] using lookup

theorem replay_wots_count_success (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (message : ByteKey)
    (start n : ℕ) (bound : start + n ≤ 2 ^ 32) (count : ℕ) (digest : Digest)
    (recorded : replayProgram table (mapProgram encode
      (wotsCountProgram seed layer tree kp message start n bound)) = some (some (count, digest))) :
    start ≤ count ∧ count < start + n ∧
      table (encode (wotsRecoverCountInput seed layer tree kp message count)) = some digest ∧
      wotsAccept (wotsOfDigest digest) = true := by
  rw [wotsCountProgram, mapProgram_cast, replay_program_cast] at recorded
  obtain ⟨i, value, lookup, accepted⟩ := replay_count_success encode table
    (wotsAccept ∘ wotsOfDigest) start _ count digest recorded
  simp only [Function.comp_def] at accepted
  have indexBound : i.val < n := by simpa only [counter_schedule_length] using i.isLt
  refine ⟨?_, ?_, ?_, accepted⟩
  · calc
      start ≤ start + i.val := Nat.le_add_right start i.val
      _ = count := value.symm
  · calc
      count = start + i.val := value
      _ < start + n := Nat.add_lt_add_left indexBound start
  simp only [counterSchedule, List.getElem_ofFn] at lookup
  rw [value, wots_recover_counter_input seed layer tree kp message
    (⟨start + i.val, lt_of_lt_of_le (Nat.add_lt_add_left indexBound start) bound⟩ : Counter)]
  exact lookup

end
end C10Probability

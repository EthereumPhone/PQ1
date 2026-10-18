import C10Probability.QueryReplay
import C10Probability.RandomizerUnder

/-! A successful actual two-query search retains its private derivation and
accepted public reply in the same cache. No independent-resampling or fresh-R
premise is needed for this functional replay fact. -/
namespace C10Probability
noncomputable section

variable {K J P L α : Type*}

theorem replay_derived_success (relabel : K → J) (table : Memo J α)
    (firstKey : P → K) (derive : α → L) (encode : L → K) (accept : α → Bool)
    (start : ℕ) (keys : List P) (count : ℕ) (label : L) (reply : α)
    (recorded : replayProgram table (mapProgram relabel
      (derivedProgram firstKey derive encode accept start keys)) = some (some (count, label, reply))) :
    ∃ (i : Fin keys.length) (first : α), count = start + i.val ∧
      table (relabel (firstKey keys[i.val])) = some first ∧ label = derive first ∧
      table (relabel (encode label)) = some reply ∧ accept reply = true := by
  induction keys generalizing start with
  | nil => cases recorded
  | cons key keys ih =>
    rw [derivedProgram, mapProgram_cast, replay_program_cast] at recorded
    cases firstLookup : table (relabel (firstKey key)) with
    | none => simp only [mapProgram, replayProgram, firstLookup, Option.bind_none] at recorded; cases recorded
    | some first =>
      simp only [mapProgram, replayProgram, firstLookup, Option.bind_some] at recorded
      cases secondLookup : table (relabel (encode (derive first))) with
      | none => simp only [secondLookup, Option.bind_none] at recorded; cases recorded
      | some second =>
        simp only [secondLookup, Option.bind_some] at recorded
        by_cases accepted : accept second = true
        · simp only [accepted, ↓reduceIte, mapProgram, replayProgram,
            Option.some.injEq, Prod.mk.injEq] at recorded
          obtain ⟨rfl, rfl, rfl⟩ := recorded
          exact ⟨⟨0, by simp⟩, first, by simp, by simpa using firstLookup,
            rfl, secondLookup, accepted⟩
        · simp only [accepted] at recorded
          obtain ⟨i, raw, value, firstRecorded, derived, secondRecorded, valid⟩ := ih (start + 1) recorded
          refine ⟨⟨i.val + 1, Nat.succ_lt_succ i.isLt⟩, raw, ?_, ?_, derived, secondRecorded, valid⟩
          · change count = start + (i.val + 1)
            omega
          · simpa only [List.getElem_cons_succ] using firstRecorded

theorem replay_randomizer_under_success (encode : Sum ByteKey ByteKey → K) (table : Memo K Digest)
    (random message seed root : ByteKey) (m : ℕ) (bound : m ≤ 2 ^ 32)
    (trial : ℕ) (randomizer : Randomizer) (digest : Digest)
    (recorded : replayProgram table (randomizerUnderProgram encode random message seed root m bound) =
      some (some (trial, randomizer, digest))) :
    trial < m ∧
      table (encode (.inl (hmsgRandomizerInput seed root message randomizer))) = some digest ∧
      forsAccept (forsOfDigest digest) = true := by
  rw [randomizerUnderProgram, privateRandomizerProgram, mapProgram_cast, replay_program_cast] at recorded
  obtain ⟨i, _, value, _, _, lookup, accepted⟩ := replay_derived_success encode table Sum.inr
    randomizerOfDigest (Sum.inl ∘ hmsgRandomizerInput seed root message)
    (forsAccept ∘ forsOfDigest) 0 _ trial randomizer digest recorded
  have indexBound : i.val < m := by simpa only [counter_schedule_length] using i.isLt
  simp only [Function.comp_def] at lookup accepted
  refine ⟨?_, lookup, accepted⟩
  simpa only [value, Nat.zero_add] using indexBound

end
end C10Probability

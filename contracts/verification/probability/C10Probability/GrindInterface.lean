import C10Probability.GrindProgram
import C10Probability.PrivateSecret

/-! The existing FORS two-query search as an interleaved private/public client.
Private tails contain the actual tag, optional randomness, message and complete
counter block. Their program never receives the hidden secret. -/
namespace C10Probability
noncomputable section

def rTailStem (random message : ByteKey) : ByteKey :=
  rGrindTag ++ random ++ message

theorem prefixed_tail_counter (secret : Digest) (random message : ByteKey) (nonce : Counter) :
    prefixedPrivateInput secret (counterKey (rTailStem random message) nonce) =
      rDerivationInput (secretBytes secret) random message nonce := by
  simp only [prefixedPrivateInput, counterKey, rTailStem, rDerivationInput,
    rInputStem, List.append_assoc]

theorem prefixed_tail_schedule (secret : Digest) (random message : ByteKey)
    (start n : ℕ) (hb : start + n ≤ 2 ^ 32) :
    (counterSchedule (rTailStem random message) start n hb).map (prefixedPrivateInput secret) =
      counterSchedule (rInputStem (secretBytes secret) random message) start n hb := by
  simp only [counterSchedule, List.map_ofFn, Function.comp_def, prefixed_tail_counter,
    rDerivationInput]

def privateRandomizerProgram (random message seed root : ByteKey)
    (n : ℕ) (hb : 0 + n ≤ 2 ^ 32) :
    QueryProgram (Sum ByteKey ByteKey) Digest (Option (ℕ × Randomizer × Digest)) (2 * n) :=
  castProgram (by rw [counter_schedule_length])
    (derivedProgram Sum.inr randomizerOfDigest (Sum.inl ∘ hmsgRandomizerInput seed root message)
      (forsAccept ∘ forsOfDigest) 0 (counterSchedule (rTailStem random message) 0 n hb))

def privateRandomizerSearch (table : Memo (Sum ByteKey ByteKey) Digest)
    (random message seed root : ByteKey) (n : ℕ) (hb : 0 + n ≤ 2 ^ 32) :
    PMF (Option (ℕ × Randomizer × Digest) × Memo (Sum ByteKey ByteKey) Digest) :=
  derivedMemoGrind digestDraw randomizerOfDigest (Sum.inl ∘ hmsgRandomizerInput seed root message)
    (forsAccept ∘ forsOfDigest) table 0
      ((counterSchedule (rTailStem random message) 0 n hb).map Sum.inr)

theorem privateRandomizerProgram_shared (secret : Digest) (table : Memo ByteKey Digest)
    (random message seed root : ByteKey) (n : ℕ) (hb : 0 + n ≤ 2 ^ 32) :
    evalProgram digestDraw
      (mapProgram (privateKey prefixedPrivateInput secret)
        (privateRandomizerProgram random message seed root n hb)) table =
      sharedRandomizerSearch table (secretBytes secret) random message seed root n hb := by
  unfold privateRandomizerProgram
  rw [mapProgram_cast, evalProgram_cast, evalProgram_mapped_derived]
  simp only [Function.comp_def, privateKey, prefixed_tail_schedule, sharedRandomizerSearch]

theorem privateRandomizerProgram_independent (table : Memo (Sum ByteKey ByteKey) Digest)
    (random message seed root : ByteKey) (n : ℕ) (hb : 0 + n ≤ 2 ^ 32) :
    evalProgram digestDraw (privateRandomizerProgram random message seed root n hb) table =
      privateRandomizerSearch table random message seed root n hb := by
  unfold privateRandomizerProgram
  rw [evalProgram_cast, evalProgram_derived]
  rfl

theorem privateRandomizerProgram_budget (random message seed root : ByteKey)
    (n : ℕ) (hb : 0 + n ≤ 2 ^ 32) :
    PublicBudget (privateRandomizerProgram random message seed root n hb) n := by
  unfold privateRandomizerProgram
  rw [publicBudget_cast]
  simpa only [counter_schedule_length] using
    private_derived_public_budget randomizerOfDigest (hmsgRandomizerInput seed root message)
      (forsAccept ∘ forsOfDigest) 0 (counterSchedule (rTailStem random message) 0 n hb)

theorem privateRandomizerSearch_zero (table : Memo (Sum ByteKey ByteKey) Digest)
    (random message seed root : ByteKey) (hb : 0 + 0 ≤ 2 ^ 32) :
    privateRandomizerSearch table random message seed root 0 hb = PMF.pure (none, table) := by
  simp [privateRandomizerSearch, counterSchedule, derivedMemoGrind]

end
end C10Probability

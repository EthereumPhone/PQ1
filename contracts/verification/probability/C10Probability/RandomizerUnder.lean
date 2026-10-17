import C10Probability.GrindInterface
import C10Probability.DomainGrind

/-! The actual R/H_msg search under an arbitrary shared-oracle input map.
The direct PMF procedure preserves both replies and the entire cache. Its
selected budget excludes H_msg by its concrete input shape, including hits. -/
namespace C10Probability
noncomputable section

variable {K L α R : Type*}

theorem selectedBudget_map (select : L → Bool) (encode : K → L) {n : ℕ}
    (program : QueryProgram K α R n) (q : ℕ) :
    SelectedBudget select (mapProgram encode program) q =
      SelectedBudget (select ∘ encode) program q := by
  induction program generalizing q with
  | done value => rfl
  | query key next ih =>
    simp only [mapProgram, SelectedBudget, Function.comp_apply, ih]
    rfl

def randomizerUnderProgram (encode : Sum ByteKey ByteKey → K)
    (random message seed root : ByteKey) (m : ℕ) (hm : m ≤ 2 ^ 32) :
    QueryProgram K Digest (Option (ℕ × Randomizer × Digest)) (2 * m) :=
  mapProgram encode (privateRandomizerProgram random message seed root m (by simpa using hm))

attribute [irreducible] randomizerUnderProgram

def randomizerUnder [DecidableEq K] (encode : Sum ByteKey ByteKey → K)
    (table : Memo K Digest) (random message seed root : ByteKey)
    (m : ℕ) (hm : m ≤ 2 ^ 32) :
    PMF (Option (ℕ × Randomizer × Digest) × Memo K Digest) :=
  derivedMemoGrind digestDraw randomizerOfDigest
    (fun r => encode (.inl (hmsgRandomizerInput seed root message r)))
    (forsAccept ∘ forsOfDigest) table 0
    ((counterSchedule (rTailStem random message) 0 m (by simpa using hm)).map
      (fun key => encode (.inr key)))

theorem randomizer_under_eval [DecidableEq K] (encode : Sum ByteKey ByteKey → K)
    (table : Memo K Digest) (random message seed root : ByteKey)
    (m : ℕ) (hm : m ≤ 2 ^ 32) :
    evalProgram digestDraw (randomizerUnderProgram encode random message seed root m hm) table =
      randomizerUnder encode table random message seed root m hm := by
  simp only [randomizerUnderProgram, privateRandomizerProgram, mapProgram_cast,
    evalProgram_cast, evalProgram_mapped_derived, randomizerUnder, Function.comp_def]

theorem randomizer_under_map (encode : K → L) (labels : Sum ByteKey ByteKey → K)
    (random message seed root : ByteKey) (m : ℕ) (hm : m ≤ 2 ^ 32) :
    mapProgram encode (randomizerUnderProgram labels random message seed root m hm) =
      randomizerUnderProgram (encode ∘ labels) random message seed root m hm := by
  simp only [randomizerUnderProgram, mapProgram_comp]

theorem randomizer_under_public (random message seed root : ByteKey)
    (m : ℕ) (hm : m ≤ 2 ^ 32) :
    PublicBudget (randomizerUnderProgram id random message seed root m hm) m := by
  rw [randomizerUnderProgram, mapProgram_id]
  exact privateRandomizerProgram_budget _ _ _ _ _ _

theorem randomizer_under_selected (secret : Digest) (random message seed root : ByteKey)
    (m : ℕ) (hm : m ≤ 2 ^ 32) (hs : seed.length = 32) (hr : root.length = 32)
    (hmsg : message.length = 32) :
    SelectedBudget nodeQuery (randomizerUnderProgram (privateKey prefixedPrivateInput secret)
      random message seed root m hm) m := by
  rw [randomizerUnderProgram, selectedBudget_map, privateRandomizerProgram, selectedBudget_cast]
  have h := derivedProgram_selected_budget (nodeQuery ∘ privateKey prefixedPrivateInput secret)
      Sum.inr randomizerOfDigest (Sum.inl ∘ hmsgRandomizerInput seed root message)
      (forsAccept ∘ forsOfDigest) 0
      (counterSchedule (rTailStem random message) 0 m (by simpa using hm))
      (fun r => node_query_no_hmsg seed root message r hs hr hmsg)
  exact selectedBudget_mono _ _ (le_of_eq (counter_schedule_length _ _ _ _)) h

theorem randomizer_under_shared (secret : Digest) (table : Memo ByteKey Digest)
    (random message seed root : ByteKey) (m : ℕ) (hm : m ≤ 2 ^ 32) :
    randomizerUnder (privateKey prefixedPrivateInput secret) table random message seed root m hm =
      sharedRandomizerSearch table (secretBytes secret) random message seed root m
        (by simpa using hm) := by
  rw [← randomizer_under_eval, randomizerUnderProgram, privateRandomizerProgram_shared]

theorem randomizer_under_zero [DecidableEq K] (encode : Sum ByteKey ByteKey → K)
    (table : Memo K Digest) (random message seed root : ByteKey) (hm : 0 ≤ 2 ^ 32) :
    randomizerUnder encode table random message seed root 0 hm = PMF.pure (none, table) := by
  simp [randomizerUnder, counterSchedule, derivedMemoGrind]

end
end C10Probability

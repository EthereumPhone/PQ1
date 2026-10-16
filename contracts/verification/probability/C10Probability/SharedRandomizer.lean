import C10Probability.DerivedGrind
import C10Probability.Randomizer

/-! The manually transcribed R_grind preimage and one-table R/H_msg experiment.
Local nonce uniqueness and byte-domain separation are proved here. Absence of
the scheduled R inputs from earlier history remains an explicit premise. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def rGrindTag : ByteKey := [82, 95, 103, 114, 105, 110, 100]

def rInputStem (secret random message : ByteKey) : ByteKey :=
  secret ++ rGrindTag ++ random ++ message

def rDerivationInput (secret random message : ByteKey) (nonce : Counter) : ByteKey :=
  counterKey (rInputStem secret random message) nonce

theorem r_input_parts (secret random message : ByteKey) (nonce : Counter) :
    rDerivationInput secret random message nonce =
      secret ++ [82, 95, 103, 114, 105, 110, 100] ++ random ++ message ++
        List.ofFn (counterBytes nonce) := by rfl

theorem r_input_length (secret random message : ByteKey) (nonce : Counter)
    (hs : secret.length = 32) (hm : message.length = 32) :
    (rDerivationInput secret random message nonce).length = 103 + random.length := by
  simp [rDerivationInput, counter_key_length, rInputStem, rGrindTag, hs, hm]
  omega

theorem r_input_injective (secret random message : ByteKey) :
    Function.Injective (rDerivationInput secret random message) := by
  exact counter_key_injective (rInputStem secret random message)

def rInputDomain (key : ByteKey) : Bool := decide (key.length = 103 ∨ key.length = 119)

theorem r_input_hidden (secret random message : ByteKey) (nonce : Counter)
    (hs : secret.length = 32) (hm : message.length = 32)
    (hr : random.length = 0 ∨ random.length = 16) :
    rInputDomain (rDerivationInput secret random message nonce) = true := by
  rcases hr with hr | hr <;>
    simp [rInputDomain, r_input_length secret random message nonce hs hm, hr]

theorem hmsg_input_visible (seed root message : ByteKey) (r : Randomizer)
    (hs : seed.length = 32) (hr : root.length = 32) (hm : message.length = 32) :
    rInputDomain (hmsgRandomizerInput seed root message r) = false := by
  simp [rInputDomain, hmsg_randomizer_length seed root message r hs hr hm]

theorem r_hmsg_input_separate (secret random message seed root : ByteKey)
    (nonce : Counter) (r : Randomizer) (hs : secret.length = 32)
    (hm : message.length = 32) (hr : random.length = 0 ∨ random.length = 16)
    (hseed : seed.length = 32) (hroot : root.length = 32) :
    rDerivationInput secret random message nonce ≠ hmsgRandomizerInput seed root message r := by
  intro he
  have h := r_input_hidden secret random message nonce hs hm hr
  rw [he, hmsg_input_visible seed root message r hseed hroot hm] at h
  cases h

theorem r_schedule_hidden (secret random message : ByteKey) (start n : ℕ)
    (hb : start + n ≤ 2 ^ 32) (hs : secret.length = 32) (hm : message.length = 32)
    (hr : random.length = 0 ∨ random.length = 16) :
    ∀ key ∈ counterSchedule (rInputStem secret random message) start n hb,
      rInputDomain key = true := by
  intro key hk
  obtain ⟨i, rfl⟩ := List.mem_ofFn.mp hk
  exact r_input_hidden secret random message _ hs hm hr

theorem r_deterministic_layout :
    rDerivationInput (List.replicate 32 1) [] (List.replicate 32 3) 4 =
      List.replicate 32 1 ++ [82, 95, 103, 114, 105, 110, 100] ++
        List.replicate 32 3 ++ List.replicate 31 0 ++ [4] := by decide

theorem r_hedged_layout :
    rDerivationInput (List.replicate 32 1) (List.replicate 16 2) (List.replicate 32 3) 4 =
      List.replicate 32 1 ++ [82, 95, 103, 114, 105, 110, 100] ++
        List.replicate 16 2 ++ List.replicate 32 3 ++ List.replicate 31 0 ++ [4] := by decide

theorem hmsg_marked_layout :
    hmsgRandomizerInput (List.replicate 32 1) (List.replicate 32 2)
      (List.replicate 32 4) ⟨3 * 2 ^ 120, by decide⟩ =
        List.replicate 32 1 ++ List.replicate 32 2 ++ [3] ++ List.replicate 31 0 ++
          List.replicate 32 4 ++ List.replicate 32 255 := by decide

def sharedRandomizerSearch (table : Memo ByteKey Digest)
    (secret random message seed root : ByteKey) (n : ℕ) (hb : 0 + n ≤ 2 ^ 32) :
    PMF (Option (ℕ × Randomizer × Digest) × Memo ByteKey Digest) :=
  derivedMemoGrind digestDraw randomizerOfDigest (hmsgRandomizerInput seed root message)
    (forsAccept ∘ forsOfDigest) table 0
      (counterSchedule (rInputStem secret random message) 0 n hb)

theorem sharedRandomizer_refines (table : Memo ByteKey Digest)
    (secret random message seed root : ByteKey) (n : ℕ) (hb : 0 + n ≤ 2 ^ 32)
    (hs : secret.length = 32) (hm : message.length = 32)
    (hr : random.length = 0 ∨ random.length = 16)
    (hseed : seed.length = 32) (hroot : root.length = 32)
    (hf : ∀ key ∈ counterSchedule (rInputStem secret random message) 0 n hb,
      table key = none) :
    (sharedRandomizerSearch table secret random message seed root n hb).map
      (fun out => (out.1, eraseMemo rInputDomain out.2)) =
        labelledMemoGrind randomizerDraw digestDraw (hmsgRandomizerInput seed root message)
          (forsAccept ∘ forsOfDigest) (eraseMemo rInputDomain table) 0 n := by
  simpa only [sharedRandomizerSearch, randomizerDraw, counter_schedule_length] using
    derivedMemoGrind_refines digestDraw randomizerOfDigest
      (hmsgRandomizerInput seed root message) (forsAccept ∘ forsOfDigest) rInputDomain
      (fun r => hmsg_input_visible seed root message r hseed hroot hm) table 0
      (counterSchedule (rInputStem secret random message) 0 n hb)
      (counter_schedule_nodup _ _ _ hb) hf
      (r_schedule_hidden secret random message 0 n hb hs hm hr)

theorem sharedRandomizer_result (table : Memo ByteKey Digest)
    (secret random message seed root : ByteKey) (n : ℕ) (hb : 0 + n ≤ 2 ^ 32)
    (hs : secret.length = 32) (hm : message.length = 32)
    (hr : random.length = 0 ∨ random.length = 16)
    (hseed : seed.length = 32) (hroot : root.length = 32)
    (hf : ∀ key ∈ counterSchedule (rInputStem secret random message) 0 n hb,
      table key = none) :
    (sharedRandomizerSearch table secret random message seed root n hb).map
      (fun out => forgetLabel out.1) =
        (randomizerMemoSearch table seed root message n).map Prod.fst := by
  simpa only [sharedRandomizerSearch, randomizerMemoSearch, randomizerDraw,
    counter_schedule_length] using
    derivedMemoGrind_result digestDraw randomizerOfDigest
      (hmsgRandomizerInput seed root message) (forsAccept ∘ forsOfDigest) rInputDomain
      (fun r => hmsg_input_visible seed root message r hseed hroot hm) table 0
      (counterSchedule (rInputStem secret random message) 0 n hb)
      (counter_schedule_nodup _ _ _ hb) hf
      (r_schedule_hidden secret random message 0 n hb hs hm hr)

theorem sharedRandomizer_event_error (table : Memo ByteKey Digest)
    (secret random message seed root : ByteKey) (n : ℕ) (hb : 0 + n ≤ 2 ^ 32)
    (hs : secret.length = 32) (hm : message.length = 32)
    (hr : random.length = 0 ∨ random.length = 16)
    (hseed : seed.length = 32) (hroot : root.length = 32)
    (hf : ∀ key ∈ counterSchedule (rInputStem secret random message) 0 n hb,
      table key = none) (event : Set (Option (ℕ × Digest))) :
    |(((sharedRandomizerSearch table secret random message seed root n hb).map
      (fun out => forgetLabel out.1)).toOuterMeasure event).toReal -
        ((grind digestDraw (forsAccept ∘ forsOfDigest) 0 n).toOuterMeasure event).toReal| ≤
      (collisionPairs (embeddedHistory table (hmsgRandomizerInput seed root message)).card n : ℝ) /
        (2 : ℝ) ^ 128 := by
  rw [sharedRandomizer_result table secret random message seed root n hb hs hm hr hseed hroot hf]
  exact randomizer_search_error_real table seed root message n event

theorem sharedRandomizer_none (table : Memo ByteKey Digest)
    (secret random message seed root : ByteKey) (n : ℕ) (hb : 0 + n ≤ 2 ^ 32)
    (hs : secret.length = 32) (hm : message.length = 32)
    (hr : random.length = 0 ∨ random.length = 16)
    (hseed : seed.length = 32) (hroot : root.length = 32)
    (hf : ∀ key ∈ counterSchedule (rInputStem secret random message) 0 n hb,
      table key = none) :
    ((sharedRandomizerSearch table secret random message seed root n hb).map Prod.fst) none =
      ((randomizerMemoSearch table seed root message n).map Prod.fst) none := by
  have h := congrArg (fun p => p none)
    (sharedRandomizer_result table secret random message seed root n hb hs hm hr hseed hroot hf)
  rw [← forgetLabel_none_mass
    ((sharedRandomizerSearch table secret random message seed root n hb).map Prod.fst)]
  simpa only [PMF.map_comp, Function.comp_def] using h

theorem sharedRandomizer_exhaustion_error (table : Memo ByteKey Digest)
    (secret random message seed root : ByteKey) (n : ℕ) (hb : 0 + n ≤ 2 ^ 32)
    (hs : secret.length = 32) (hm : message.length = 32)
    (hr : random.length = 0 ∨ random.length = 16)
    (hseed : seed.length = 32) (hroot : root.length = 32)
    (hf : ∀ key ∈ counterSchedule (rInputStem secret random message) 0 n hb,
      table key = none) :
    |(((sharedRandomizerSearch table secret random message seed root n hb).map Prod.fst)
      none).toReal - (1 - (1 : ℝ) / 2048) ^ n| ≤
      (collisionPairs (embeddedHistory table (hmsgRandomizerInput seed root message)).card n : ℝ) /
        (2 : ℝ) ^ 128 := by
  rw [sharedRandomizer_none table secret random message seed root n hb hs hm hr hseed hroot hf]
  exact fors_memo_exhaustion_error table seed root message n

theorem sharedRandomizer_empty_exhaustion (secret random message seed root : ByteKey)
    (n : ℕ) (hb : 0 + n ≤ 2 ^ 32) (hs : secret.length = 32) (hm : message.length = 32)
    (hr : random.length = 0 ∨ random.length = 16)
    (hseed : seed.length = 32) (hroot : root.length = 32) :
    (((sharedRandomizerSearch (fun _ => none) secret random message seed root n hb).map
      Prod.fst) none).toReal ≤
        (1 - (1 : ℝ) / 2048) ^ n + (n.choose 2 : ℝ) / (2 : ℝ) ^ 128 := by
  rw [sharedRandomizer_none _ secret random message seed root n hb hs hm hr hseed hroot
    (by simp)]
  exact fors_empty_memo_exhaustion_bound seed root message n

theorem sharedRandomizer_signing_exhaustion (secret random message seed root : ByteKey)
    (hs : secret.length = 32) (hm : message.length = 32)
    (hr : random.length = 0 ∨ random.length = 16)
    (hseed : seed.length = 32) (hroot : root.length = 32) :
    (((sharedRandomizerSearch (fun _ => none) secret random message seed root
      signingBudget signing_counter_fits).map Prod.fst) none).toReal ≤
        (1 - (1 : ℝ) / 2048) ^ signingBudget +
          (signingBudget.choose 2 : ℝ) / (2 : ℝ) ^ 128 := by
  exact sharedRandomizer_empty_exhaustion secret random message seed root signingBudget
    signing_counter_fits hs hm hr hseed hroot

end
end C10Probability

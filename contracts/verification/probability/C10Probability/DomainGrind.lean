import C10Probability.DomainNodeCharges
import C10Probability.GrindProgram

/-! The existing physical R/H_msg grinder uses one full cache and two raw calls
per trial. H_msg is excluded; R remains in the conservative raw node domain.
No freshness premise or successful-termination assumption is needed for cost. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem derivedProgram_selected_budget {K P L α : Type*} (select : K → Bool)
    (firstKey : P → K) (derive : α → L) (encode : L → K) (accept : α → Bool)
    (start : ℕ) (keys : List P) (excluded : ∀ label, select (encode label) = false) :
    SelectedBudget select (derivedProgram firstKey derive encode accept start keys)
      keys.length := by
  induction keys generalizing start with
  | nil => trivial
  | cons key keys ih =>
    simp only [derivedProgram, selectedBudget_cast, List.length_cons]
    apply selectedBudget_query
    intro first
    simp only [SelectedBudget, excluded, Bool.false_eq_true, ↓reduceIte]
    intro second
    cases ha : accept second
    · simpa only [ha, Bool.false_eq_true, ↓reduceIte] using ih (start + 1)
    · simp only [↓reduceIte, SelectedBudget]

theorem sharedRandomizer_node_bad_bound (secret random message seed root : ByteKey)
    (n : ℕ) (hb : 0 + n ≤ 2 ^ 32) (hs : seed.length = 32)
    (hr : root.length = 32) (hm : message.length = 32) :
    (sharedRandomizerSearch (fun _ => none) secret random message seed root n hb).toOuterMeasure
      {out | DomainNodeBad out.2} ≤
        ((n.choose 2 + 2 * n : ℕ) : ℝ≥0∞) / (2 : ℝ≥0∞) ^ 128 := by
  let keys := counterSchedule (rInputStem secret random message) 0 n hb
  let program := derivedProgram id randomizerOfDigest (hmsgRandomizerInput seed root message)
    (forsAccept ∘ forsOfDigest) 0 keys
  have budget : SelectedBudget nodeQuery program n := by
    simpa only [program, keys, counter_schedule_length] using
      derivedProgram_selected_budget nodeQuery id randomizerOfDigest
        (hmsgRandomizerInput seed root message) (forsAccept ∘ forsOfDigest) 0 keys
        (fun label => node_query_no_hmsg seed root message label hs hr hm)
  have h := digest_program_domain_node_bad_bound (PMF.pure program) n
    (by
      intro actual ha
      have he : actual = program := by simpa using ha
      simpa only [he] using budget)
  simpa only [randomizedProgram_pure, program, evalProgram_derived, List.map_id,
    keys, counter_schedule_length, sharedRandomizerSearch] using h

theorem sharedRandomizer_node_bad_bound_real (secret random message seed root : ByteKey)
    (n : ℕ) (hb : 0 + n ≤ 2 ^ 32) (hs : seed.length = 32)
    (hr : root.length = 32) (hm : message.length = 32) :
    ((sharedRandomizerSearch (fun _ => none) secret random message seed root n hb).toOuterMeasure
      {out | DomainNodeBad out.2}).toReal ≤
        ((n.choose 2 + 2 * n : ℕ) : ℝ) / (2 : ℝ) ^ 128 := by
  have h := ENNReal.toReal_mono (show
      ((n.choose 2 + 2 * n : ℕ) : ℝ≥0∞) / (2 : ℝ≥0∞) ^ 128 ≠ ⊤ by
        exact ENNReal.div_ne_top (by finiteness) (by simp))
    (sharedRandomizer_node_bad_bound secret random message seed root n hb hs hr hm)
  simpa only [ENNReal.toReal_div, ENNReal.toReal_natCast,
    ENNReal.toReal_pow, ENNReal.toReal_ofNat] using h

end
end C10Probability

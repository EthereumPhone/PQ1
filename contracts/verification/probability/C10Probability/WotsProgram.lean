import C10Probability.CountProgram
import C10Probability.AddressBytes
import C10Probability.DomainNodeCharges
import C10Probability.WotsExact

/-! Actual one-query WOTS count search with the C10 byte input. This manually
transcribes RawWots.count, including the unsuccessful return and full cache.
Independent-sampling results still require absence from earlier history. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def wotsCountStem (seed : ByteKey) (layer tree kp : ℕ) (message : ByteKey) : ByteKey :=
  seed ++ c10Address layer tree 0 kp 0 0 0 ++ message ++ List.replicate 16 0

theorem wots_count_key_layout (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (nonce : Counter) :
    counterKey (wotsCountStem seed layer tree kp message) nonce =
      seed ++ c10Address layer tree 0 kp 0 0 0 ++ message ++ List.replicate 16 0 ++
        beBytes 32 nonce.val := by
  rw [be_bytes_counter]
  rfl

theorem wots_count_key_length (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (nonce : Counter) (hs : seed.length = 32)
    (hm : message.length = 16) :
    (counterKey (wotsCountStem seed layer tree kp message) nonce).length = 128 := by
  simp [counter_key_length, wotsCountStem, c10_address_length, hs, hm]

theorem wots_count_key_excluded (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (nonce : Counter) (hs : seed.length = 32)
    (hm : message.length = 16) :
    nodeQuery (counterKey (wotsCountStem seed layer tree kp message) nonce) = false := by
  exact node_query_no_count seed (c10Address layer tree 0 kp 0 0 0) message nonce
    hs (c10_address_length _ _ _ _ _ _ _) hm (c10_address_count_kind layer tree kp)

def wotsCountProgram (seed : ByteKey) (layer tree kp : ℕ) (message : ByteKey)
    (start n : ℕ) (hb : start + n ≤ 2 ^ 32) :
    QueryProgram ByteKey Digest (Option (ℕ × Digest)) n :=
  castProgram (counter_schedule_length _ start n hb)
    (countProgram (wotsAccept ∘ wotsOfDigest) start
      (counterSchedule (wotsCountStem seed layer tree kp message) start n hb))

def wotsCountSearch (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (message : ByteKey) (start n : ℕ) (hb : start + n ≤ 2 ^ 32) :
    PMF (Option (ℕ × Digest) × Memo ByteKey Digest) :=
  memoGrind digestDraw (wotsAccept ∘ wotsOfDigest) table start
    (counterSchedule (wotsCountStem seed layer tree kp message) start n hb)

theorem wots_count_program_eval (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (message : ByteKey) (start n : ℕ) (hb : start + n ≤ 2 ^ 32) :
    evalProgram digestDraw (wotsCountProgram seed layer tree kp message start n hb) table =
      wotsCountSearch table seed layer tree kp message start n hb := by
  rw [wotsCountProgram, evalProgram_cast, evalProgram_count]
  rfl

theorem wots_count_program_selected (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (start n : ℕ) (hb : start + n ≤ 2 ^ 32)
    (hs : seed.length = 32) (hm : message.length = 16) :
    SelectedBudget nodeQuery (wotsCountProgram seed layer tree kp message start n hb) 0 := by
  rw [wotsCountProgram, selectedBudget_cast]
  apply countProgram_selected_zero
  intro key hk
  obtain ⟨i, rfl⟩ := List.mem_ofFn.mp hk
  exact wots_count_key_excluded seed layer tree kp message _ hs hm

theorem wots_count_search_fresh (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (message : ByteKey) (start n : ℕ) (hb : start + n ≤ 2 ^ 32)
    (fresh : ∀ key ∈ counterSchedule (wotsCountStem seed layer tree kp message) start n hb,
      table key = none) :
    (wotsCountSearch table seed layer tree kp message start n hb).map Prod.fst =
      grind digestDraw (wotsAccept ∘ wotsOfDigest) start n := by
  exact counter_grind_fresh _ _ _ _ _ _ _ fresh

theorem wots_count_search_empty (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (start n : ℕ) (hb : start + n ≤ 2 ^ 32) :
    (wotsCountSearch (fun _ => none) seed layer tree kp message start n hb).map Prod.fst =
      grind digestDraw (wotsAccept ∘ wotsOfDigest) start n := by
  exact wots_count_search_fresh _ seed layer tree kp message start n hb (by simp)

theorem wots_count_search_projection (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (message : ByteKey) (start n : ℕ) (hb : start + n ≤ 2 ^ 32)
    (fresh : ∀ key ∈ counterSchedule (wotsCountStem seed layer tree kp message) start n hb,
      table key = none) :
    ((wotsCountSearch table seed layer tree kp message start n hb).map Prod.fst).map
      (projectResult wotsOfDigest) = grind wotsDraw wotsAccept start n := by
  rw [wots_count_search_fresh table seed layer tree kp message start n hb fresh,
    wots_digest_search_projection]

theorem wots_count_signing_exhaustion (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (message : ByteKey)
    (fresh : ∀ key ∈ counterSchedule (wotsCountStem seed layer tree kp message)
      0 signingBudget signing_counter_fits, table key = none) :
    (((wotsCountSearch table seed layer tree kp message 0 signingBudget
      signing_counter_fits).map Prod.fst) none).toReal =
      (1 - (22169393903687611906220091621190388 : ℝ) / (8 : ℝ) ^ 43) ^ signingBudget := by
  rw [wots_count_search_fresh table seed layer tree kp message 0 signingBudget
    signing_counter_fits fresh]
  exact wots_digest_exhaustion_exact_real

theorem wots_count_continuation_budget {R : Type*} {m : ℕ} (seed : ByteKey)
    (layer tree kp : ℕ) (message : ByteKey) (start n : ℕ) (hb : start + n ≤ 2 ^ 32)
    (hs : seed.length = 32) (hm : message.length = 16)
    (after : Option (ℕ × Digest) → QueryProgram ByteKey Digest R m) (q : ℕ)
    (later : ∀ result, SelectedBudget nodeQuery (after result) q) :
    SelectedBudget nodeQuery
      (bindProgram (wotsCountProgram seed layer tree kp message start n hb) after) q := by
  simpa only [zero_add] using selectedBudget_bind nodeQuery
    (wotsCountProgram seed layer tree kp message start n hb) after 0 q
    (wots_count_program_selected seed layer tree kp message start n hb hs hm) later

theorem wots_count_domain_bad_bound (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (start n : ℕ) (hb : start + n ≤ 2 ^ 32)
    (hs : seed.length = 32) (hm : message.length = 16) :
    (wotsCountSearch (fun _ => none) seed layer tree kp message start n hb).toOuterMeasure
      {out | DomainNodeBad out.2} ≤ (n : ℝ≥0∞) / (2 : ℝ≥0∞) ^ 128 := by
  have h := digest_program_domain_node_bad_bound
    (PMF.pure (wotsCountProgram seed layer tree kp message start n hb)) 0 (by
      intro actual ha
      have he : actual = wotsCountProgram seed layer tree kp message start n hb := by
        simpa using ha
      rw [he]
      exact wots_count_program_selected seed layer tree kp message start n hb hs hm)
  simpa only [randomizedProgram_pure, wots_count_program_eval,
    Nat.choose_zero_succ, zero_add] using h

theorem wots_count_domain_bad_bound_real (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (start n : ℕ) (hb : start + n ≤ 2 ^ 32)
    (hs : seed.length = 32) (hm : message.length = 16) :
    ((wotsCountSearch (fun _ => none) seed layer tree kp message start n hb).toOuterMeasure
      {out | DomainNodeBad out.2}).toReal ≤ (n : ℝ) / (2 : ℝ) ^ 128 := by
  have h := ENNReal.toReal_mono (show (n : ℝ≥0∞) / (2 : ℝ≥0∞) ^ 128 ≠ ⊤ by
      exact ENNReal.div_ne_top (by finiteness) (by simp))
    (wots_count_domain_bad_bound seed layer tree kp message start n hb hs hm)
  simpa only [ENNReal.toReal_div, ENNReal.toReal_natCast,
    ENNReal.toReal_pow, ENNReal.toReal_ofNat] using h

end
end C10Probability

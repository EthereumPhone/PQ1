import C10Probability.WotsRemaining
import C10Probability.WotsCompression
import C10Probability.WotsProgram

/-! Complete public WOTS recovery: one count query, actual acceptance, the
ordered 43-chain collection, then compression. Rejection returns the zero
node without an extra query. All interpreter equalities retain the full cache.
The raw index is a worst-case allowance, not a claim that rejection uses 98 calls. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def wotsRecoveryAfter (seed : ByteKey) (layer tree kp : ℕ)
    (sigma : Fin 43 → Randomizer) (digest : Digest) :
    QueryProgram ByteKey Digest Randomizer 97 :=
  if ha : wotsAccept (wotsOfDigest digest) = true then
    bindProgram (wotsAcceptedChainsProgram seed layer tree kp (wotsOfDigest digest) ha sigma)
      (fun values => wotsCompressProgram seed layer tree kp values)
  else .done 0

attribute [irreducible] wotsRecoveryAfter

def wotsRecoveryProgram (seed : ByteKey) (layer tree kp : ℕ) (message : ByteKey)
    (sigma : Fin 43 → Randomizer) (nonce : Counter) :
    QueryProgram ByteKey Digest Randomizer 98 :=
  .query (counterKey (wotsCountStem seed layer tree kp message) nonce)
    (wotsRecoveryAfter seed layer tree kp sigma)

def wotsRecovery (table : Memo ByteKey Digest) (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (sigma : Fin 43 → Randomizer) (nonce : Counter) :
    PMF (Randomizer × Memo ByteKey Digest) :=
  (memoQuery digestDraw table (counterKey (wotsCountStem seed layer tree kp message) nonce)).bind
    (fun counted => if wotsAccept (wotsOfDigest counted.1) then
      (wotsRecoverChains counted.2 seed layer tree kp (wotsOfDigest counted.1) sigma).bind
        (fun chains => wotsCompress chains.2 seed layer tree kp chains.1)
      else PMF.pure (0, counted.2))

theorem wots_recovery_after_eval (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (sigma : Fin 43 → Randomizer) (digest : Digest) :
    evalProgram digestDraw (wotsRecoveryAfter seed layer tree kp sigma digest) table =
      if wotsAccept (wotsOfDigest digest) then
        (wotsRecoverChains table seed layer tree kp (wotsOfDigest digest) sigma).bind
          (fun chains => wotsCompress chains.2 seed layer tree kp chains.1)
      else PMF.pure (0, table) := by
  by_cases ha : wotsAccept (wotsOfDigest digest) = true
  · simp only [wotsRecoveryAfter, ha, ↓reduceDIte, ↓reduceIte, evalProgram_bind,
      wots_accepted_chains_eval, wots_compress_eval]
  · simp only [wotsRecoveryAfter, ha, Bool.false_eq_true, ↓reduceDIte, ↓reduceIte,
      evalProgram]

theorem wots_recovery_eval (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (message : ByteKey) (sigma : Fin 43 → Randomizer) (nonce : Counter) :
    evalProgram digestDraw (wotsRecoveryProgram seed layer tree kp message sigma nonce) table =
      wotsRecovery table seed layer tree kp message sigma nonce := by
  simp only [wotsRecoveryProgram, evalProgram, wots_recovery_after_eval, wotsRecovery]

theorem wots_recovery_rejected_cached (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (message : ByteKey) (sigma : Fin 43 → Randomizer) (nonce : Counter)
    (digest : Digest)
    (cached : table (counterKey (wotsCountStem seed layer tree kp message) nonce) = some digest)
    (reject : wotsAccept (wotsOfDigest digest) = false) :
    wotsRecovery table seed layer tree kp message sigma nonce = PMF.pure (0, table) := by
  rw [wotsRecovery, memoQuery_cached _ _ _ _ cached, PMF.pure_bind]
  simp only [reject, Bool.false_eq_true, ↓reduceIte]

theorem wots_recovery_accepted_cached (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (message : ByteKey) (sigma : Fin 43 → Randomizer) (nonce : Counter)
    (digest : Digest)
    (cached : table (counterKey (wotsCountStem seed layer tree kp message) nonce) = some digest)
    (accept : wotsAccept (wotsOfDigest digest) = true) :
    wotsRecovery table seed layer tree kp message sigma nonce =
      (wotsRecoverChains table seed layer tree kp (wotsOfDigest digest) sigma).bind
        (fun chains => wotsCompress chains.2 seed layer tree kp chains.1) := by
  rw [wotsRecovery, memoQuery_cached _ _ _ _ cached, PMF.pure_bind]
  simp only [accept, ↓reduceIte]

theorem wots_recovery_after_budget (seed : ByteKey) (layer tree kp : ℕ)
    (sigma : Fin 43 → Randomizer) (digest : Digest) :
    SelectedBudget nodeQuery (wotsRecoveryAfter seed layer tree kp sigma digest) 97 := by
  exact selectedBudget_total nodeQuery (n := 97)
    (wotsRecoveryAfter seed layer tree kp sigma digest)

theorem wots_recovery_rejected_trace (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (message : ByteKey) (sigma : Fin 43 → Randomizer) (nonce : Counter)
    (digest : Digest)
    (cached : table (counterKey (wotsCountStem seed layer tree kp message) nonce) = some digest)
    (reject : wotsAccept (wotsOfDigest digest) = false) :
    traceProgram digestDraw (wotsRecoveryProgram seed layer tree kp message sigma nonce) table =
      PMF.pure ⟨0, table, [counterKey (wotsCountStem seed layer tree kp message) nonce]⟩ := by
  rw [wotsRecoveryProgram, traceProgram, memoQuery_cached _ _ _ _ cached, PMF.pure_bind]
  simp only [wotsRecoveryAfter, reject, Bool.false_eq_true, ↓reduceDIte, traceProgram,
    PMF.pure_map]

theorem wots_recovery_selected_budget (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (sigma : Fin 43 → Randomizer) (nonce : Counter)
    (hs : seed.length = 32) (hm : message.length = 16) :
    SelectedBudget nodeQuery (wotsRecoveryProgram seed layer tree kp message sigma nonce) 97 := by
  simp only [wotsRecoveryProgram, SelectedBudget,
    wots_count_key_excluded seed layer tree kp message nonce hs hm,
    Bool.false_eq_true, ↓reduceIte]
  exact fun digest => wots_recovery_after_budget seed layer tree kp sigma digest

theorem wots_recovery_trace_raw (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (message : ByteKey) (sigma : Fin 43 → Randomizer) (nonce : Counter)
    (out : TraceOutput ByteKey Digest Randomizer)
    (ho : out ∈ (traceProgram digestDraw
      (wotsRecoveryProgram seed layer tree kp message sigma nonce) table).support) :
    out.queries.length ≤ 98 := by
  exact traceProgram_length digestDraw
    (wotsRecoveryProgram seed layer tree kp message sigma nonce) table out ho

theorem wots_recovery_trace_selected (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (message : ByteKey) (sigma : Fin 43 → Randomizer) (nonce : Counter)
    (hs : seed.length = 32) (hm : message.length = 16)
    (out : TraceOutput ByteKey Digest Randomizer)
    (ho : out ∈ (traceProgram digestDraw
      (wotsRecoveryProgram seed layer tree kp message sigma nonce) table).support) :
    (out.queries.filter nodeQuery).length ≤ 97 := by
  exact traceProgram_selected_length digestDraw nodeQuery
    (wotsRecoveryProgram seed layer tree kp message sigma nonce) 97
    (wots_recovery_selected_budget seed layer tree kp message sigma nonce hs hm) table out ho

theorem wots_recovery_domain_bad_bound (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (sigma : Fin 43 → Randomizer) (nonce : Counter)
    (hs : seed.length = 32) (hm : message.length = 16) :
    (wotsRecovery (fun _ => none) seed layer tree kp message sigma nonce).toOuterMeasure
      {out | DomainNodeBad out.2} ≤ (4754 : ℝ≥0∞) / (2 : ℝ≥0∞) ^ 128 := by
  have h := digest_program_domain_node_bad_bound
    (PMF.pure (wotsRecoveryProgram seed layer tree kp message sigma nonce)) 97 (by
      intro actual ha
      have he : actual = wotsRecoveryProgram seed layer tree kp message sigma nonce := by
        simpa using ha
      rw [he]
      exact wots_recovery_selected_budget seed layer tree kp message sigma nonce hs hm)
  simpa only [randomizedProgram_pure, wots_recovery_eval,
    show Nat.choose 97 2 + 98 = 4754 by decide] using h

theorem wots_recovery_domain_bad_bound_real (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (sigma : Fin 43 → Randomizer) (nonce : Counter)
    (hs : seed.length = 32) (hm : message.length = 16) :
    ((wotsRecovery (fun _ => none) seed layer tree kp message sigma nonce).toOuterMeasure
      {out | DomainNodeBad out.2}).toReal ≤ (4754 : ℝ) / (2 : ℝ) ^ 128 := by
  have h := ENNReal.toReal_mono
    (show (4754 : ℝ≥0∞) / (2 : ℝ≥0∞) ^ 128 ≠ ⊤ by
      exact ENNReal.div_ne_top (by finiteness) (by simp))
    (wots_recovery_domain_bad_bound seed layer tree kp message sigma nonce hs hm)
  simpa only [ENNReal.toReal_div, ENNReal.toReal_pow, ENNReal.toReal_ofNat] using h

end
end C10Probability

import C10Probability.WotsSigning

/-! Physical relabelling and costs of the complete WOTS signing client.
The selected-domain bound excludes count calls but charges every other call,
including private derivation and shuffle. Zero is charged to all raw calls. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {K L : Type*}

theorem wots_accepted_fill_map (encode : K → L) (labels : WotsQuery → K)
    (seed : ByteKey) (layer tree kp : ℕ) (word : WotsWord)
    (ha : wotsAccept word = true) (order : WotsOrder) :
    mapProgram encode (wotsAcceptedFillProgram labels seed layer tree kp word ha order) =
      wotsAcceptedFillProgram (encode ∘ labels) seed layer tree kp word ha order := by
  rw [wotsAcceptedFillProgram, mapProgram_cast, wots_fill_map, wotsAcceptedFillProgram]

theorem wots_sign_after_map (encode : K → L) (labels : WotsQuery → K)
    (seed : ByteKey) (layer tree kp : ℕ) (shuffle : ByteKey)
    (accepted : Option (ℕ × Digest)) :
    mapProgram encode (wotsSignAfterProgram labels seed layer tree kp shuffle accepted) =
      wotsSignAfterProgram (encode ∘ labels) seed layer tree kp shuffle accepted := by
  cases accepted with
  | none => simp only [wotsSignAfterProgram, mapProgram]
  | some value =>
    rcases value with ⟨count, digest⟩
    by_cases ha : wotsAccept (wotsOfDigest digest) = true
    · simp only [wotsSignAfterProgram, ha, ↓reduceDIte,
        mapProgram_bind, wots_shuffle_map, mapProgram_mapReturn, wots_accepted_fill_map,
        Function.comp_def]
    · rw [wotsSignAfterProgram, wotsSignAfterProgram, dif_neg ha, dif_neg ha]
      rfl

theorem wots_sign_map (encode : K → L) (labels : WotsQuery → K)
    (seed : ByteKey) (layer tree kp : ℕ) (message shuffle : ByteKey)
    (n : ℕ) (hb : n ≤ 2 ^ 32) :
    mapProgram encode (wotsSignProgram labels seed layer tree kp message shuffle n hb) =
      wotsSignProgram (encode ∘ labels) seed layer tree kp message shuffle n hb := by
  simp only [wotsSignProgram, mapProgram_cast, mapProgram_bind, mapProgram_comp,
    wots_sign_after_map, Function.comp_def]

theorem wots_sign_physical_eval (secret : Digest) (table : Memo ByteKey Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (message shuffle : ByteKey)
    (n : ℕ) (hb : n ≤ 2 ^ 32) :
    evalProgram digestDraw
      (mapProgram (privateKey prefixedPrivateInput secret)
        (wotsSignProgram id seed layer tree kp message shuffle n hb)) table =
      wotsSign (privateKey prefixedPrivateInput secret) table seed layer tree kp message shuffle n hb := by
  rw [wots_sign_map]
  exact wots_sign_eval _ _ _ _ _ _ _ _ _ _

theorem wots_sign_selected (secret : Digest) (seed : ByteKey) (layer tree kp : ℕ)
    (message shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32)
    (hs : seed.length = 32) (hm : message.length = 16) :
    SelectedBudget nodeQuery
      (wotsSignProgram (privateKey prefixedPrivateInput secret) seed layer tree kp message shuffle n hb)
      252 := by
  rw [wotsSignProgram, selectedBudget_cast]
  change SelectedBudget nodeQuery
    (bindProgram (mapProgram id (wotsCountProgram seed layer tree kp message 0 n _))
      (wotsSignAfterProgram (privateKey prefixedPrivateInput secret) seed layer tree kp shuffle)) 252
  rw [mapProgram_id]
  exact wots_count_continuation_budget seed layer tree kp message 0 n _ hs hm _ 252
    (fun _ => selectedBudget_total _ _)

theorem wots_sign_raw_trace (secret : Digest) (table : Memo ByteKey Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (message shuffle : ByteKey)
    (n : ℕ) (hb : n ≤ 2 ^ 32) (out : TraceOutput ByteKey Digest WotsSignature)
    (ho : out ∈ (traceProgram digestDraw
      (wotsSignProgram (privateKey prefixedPrivateInput secret) seed layer tree kp message shuffle n hb)
      table).support) : out.queries.length ≤ n + 252 := by
  exact traceProgram_length _ _ _ _ ho

theorem wots_sign_selected_trace (secret : Digest) (table : Memo ByteKey Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (message shuffle : ByteKey)
    (n : ℕ) (hb : n ≤ 2 ^ 32) (hs : seed.length = 32) (hm : message.length = 16)
    (out : TraceOutput ByteKey Digest WotsSignature)
    (ho : out ∈ (traceProgram digestDraw
      (wotsSignProgram (privateKey prefixedPrivateInput secret) seed layer tree kp message shuffle n hb)
      table).support) : (out.queries.filter nodeQuery).length ≤ 252 := by
  exact traceProgram_selected_length _ _ _ 252
    (wots_sign_selected secret seed layer tree kp message shuffle n hb hs hm) _ _ ho

theorem wots_sign_domain_bad_bound (secret : Digest) (seed : ByteKey) (layer tree kp : ℕ)
    (message shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32)
    (hs : seed.length = 32) (hm : message.length = 16) :
    (wotsSign (privateKey prefixedPrivateInput secret) (fun _ => none)
      seed layer tree kp message shuffle n hb).toOuterMeasure {out | DomainNodeBad out.2} ≤
      ((n + 31878 : ℕ) : ℝ≥0∞) / 2 ^ 128 := by
  have h := digest_program_domain_node_bad_bound
    (PMF.pure (wotsSignProgram (privateKey prefixedPrivateInput secret)
      seed layer tree kp message shuffle n hb)) 252 (by
      intro program hp
      have he : program = wotsSignProgram (privateKey prefixedPrivateInput secret)
          seed layer tree kp message shuffle n hb := by simpa using hp
      rw [he]
      exact wots_sign_selected secret seed layer tree kp message shuffle n hb hs hm)
  have hc : Nat.choose 252 2 = 31626 := by
    set_option maxRecDepth 4096 in decide +kernel
  simpa only [randomizedProgram_pure, wots_sign_eval, hc,
    show 31626 + (n + 252) = n + 31878 by omega] using h

theorem wots_sign_domain_bad_bound_real (secret : Digest) (seed : ByteKey) (layer tree kp : ℕ)
    (message shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32)
    (hs : seed.length = 32) (hm : message.length = 16) :
    ((wotsSign (privateKey prefixedPrivateInput secret) (fun _ => none)
      seed layer tree kp message shuffle n hb).toOuterMeasure {out | DomainNodeBad out.2}).toReal ≤
      ((n + 31878 : ℕ) : ℝ) / 2 ^ 128 := by
  have h := ENNReal.toReal_mono (show ((n + 31878 : ℕ) : ℝ≥0∞) / 2 ^ 128 ≠ ⊤ by
      exact ENNReal.div_ne_top (by finiteness) (by simp))
    (wots_sign_domain_bad_bound secret seed layer tree kp message shuffle n hb hs hm)
  simpa only [ENNReal.toReal_div, ENNReal.toReal_natCast,
    ENNReal.toReal_pow, ENNReal.toReal_ofNat] using h

end
end C10Probability

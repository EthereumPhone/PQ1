import C10Probability.WotsLeaf
import C10Probability.WotsShuffle
import C10Probability.WotsProgram

/-! Complete bounded WOTS signing in one memo oracle: count, exact shuffle,
private derivation, digit-length chains and positional writes. The compiler's
unreachable rejected-result branch is discharged from the count procedure's
support, not imposed as a caller premise. -/
namespace C10Probability
noncomputable section

variable {K α β : Type*}

theorem pmf_bind_support_congr (p : PMF α) (f g : α → PMF β)
    (same : ∀ x ∈ p.support, f x = g x) : p.bind f = p.bind g := by
  ext y
  simp only [PMF.bind_apply]
  apply tsum_congr
  intro x
  by_cases hx : p x = 0
  · simp only [hx, zero_mul]
  · rw [same x ((PMF.mem_support_iff _ _).mpr hx)]

theorem memoGrind_result_accepts [DecidableEq K] (p : PMF α) (accept : α → Bool)
    (table : Memo K α) (start : ℕ) (keys : List K)
    (out : Option (ℕ × α) × Memo K α)
    (ho : out ∈ (memoGrind p accept table start keys).support) :
    match out.1 with | none => True | some result => accept result.2 = true := by
  induction keys generalizing table start out with
  | nil =>
    have he : out = (none, table) := by simpa [memoGrind] using ho
    simp [he]
  | cons key keys ih =>
    rw [memoGrind, PMF.mem_support_bind_iff] at ho
    obtain ⟨reply, _, ho⟩ := ho
    cases ha : accept reply.1
    · simp only [ha, Bool.false_eq_true, ↓reduceIte] at ho
      exact ih reply.2 (start + 1) out ho
    · simp only [ha, ↓reduceIte] at ho
      have he : out = (some (start, reply.1), reply.2) := by simpa using ho
      simpa [he] using ha

def wotsCountUnder [DecidableEq K] (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (message : ByteKey)
    (n : ℕ) (hb : n ≤ 2 ^ 32) : PMF (Option (ℕ × Digest) × Memo K Digest) :=
  memoGrind digestDraw (wotsAccept ∘ wotsOfDigest) table 0
    ((counterSchedule (wotsCountStem seed layer tree kp message) 0 n (by simpa using hb)).map encode)

theorem wots_count_under_eval [DecidableEq K] (encode : ByteKey → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree kp : ℕ) (message : ByteKey)
    (n : ℕ) (hb : n ≤ 2 ^ 32) :
    evalProgram digestDraw
      (mapProgram encode (wotsCountProgram seed layer tree kp message 0 n (by simpa using hb))) table =
      wotsCountUnder encode table seed layer tree kp message n hb := by
  rw [wotsCountProgram, mapProgram_cast, evalProgram_cast, evalProgram_mapped_count]
  rfl

theorem wots_order_digit_sum (word : WotsWord) (ha : wotsAccept word = true)
    (order : WotsOrder) : collectionSteps (fun i => (word i).val) order.val = 205 := by
  rw [collectionSteps_perm _ order.property]
  simpa only [collectionSteps, wotsIndices, List.map_ofFn, Function.comp_def,
    id_eq, List.sum_ofFn, wotsAccept, decide_eq_true_eq] using ha

theorem wots_sign_fill_cost (word : WotsWord) (ha : wotsAccept word = true)
    (order : WotsOrder) : collectionSteps (fun i => (word i).val + 1) order.val = 248 := by
  rw [wots_fill_cost, wots_order_digit_sum word ha order, wots_order_length]

def wotsAcceptedFillProgram (encode : WotsQuery → K) (seed : ByteKey)
    (layer tree kp : ℕ) (word : WotsWord) (ha : wotsAccept word = true)
    (order : WotsOrder) : QueryProgram K Digest WotsSigma 248 :=
  castProgram (wots_sign_fill_cost word ha order)
    (wotsFillProgram encode seed layer tree kp (fun i => (word i).val) order.val wotsZeroSigma)

attribute [irreducible] wotsAcceptedFillProgram

theorem wots_accepted_fill_eval [DecidableEq K] (encode : WotsQuery → K)
    (seed : ByteKey) (layer tree kp : ℕ) (word : WotsWord) (ha : wotsAccept word = true)
    (order : WotsOrder) (table : Memo K Digest) :
    evalProgram digestDraw (wotsAcceptedFillProgram encode seed layer tree kp word ha order) table =
      wotsFillLoop encode seed layer tree kp (fun i => (word i).val) order.val wotsZeroSigma table := by
  rw [wotsAcceptedFillProgram, evalProgram_cast, wots_fill_eval]

theorem wots_accepted_fill_public (seed : ByteKey) (layer tree kp : ℕ)
    (word : WotsWord) (ha : wotsAccept word = true) (order : WotsOrder) :
    PublicBudget (wotsAcceptedFillProgram id seed layer tree kp word ha order) 205 := by
  rw [wotsAcceptedFillProgram, publicBudget_cast, ← wots_order_digit_sum word ha order]
  exact wots_fill_public _ _ _ _ _ _ _

abbrev WotsSignature := Option (WotsSigma × ℕ)

def wotsSignAfterProgram (encode : WotsQuery → K) (seed : ByteKey)
    (layer tree kp : ℕ) (shuffle : ByteKey) (accepted : Option (ℕ × Digest)) :
    QueryProgram K Digest WotsSignature 252 :=
  match accepted with
  | none => .done none
  | some (count, digest) =>
    if ha : wotsAccept (wotsOfDigest digest) = true then
      bindProgram (wotsShuffleProgram (fun key => encode (.inl key)) shuffle) (fun order =>
        mapReturnProgram (fun sigma => some (sigma, count))
          (wotsAcceptedFillProgram encode seed layer tree kp (wotsOfDigest digest) ha order))
    else .done none

attribute [irreducible] wotsSignAfterProgram

def wotsSignAfter [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (shuffle : ByteKey)
    (accepted : Option (ℕ × Digest)) : PMF (WotsSignature × Memo K Digest) :=
  match accepted with
  | none => PMF.pure (none, table)
  | some (count, digest) =>
    (wotsShuffle (fun key => encode (.inl key)) shuffle table).bind (fun order =>
      (wotsFillLoop encode seed layer tree kp (fun i => (wotsOfDigest digest i).val)
        order.1.val wotsZeroSigma order.2).map (fun out => (some (out.1, count), out.2)))

theorem wots_sign_after_eval [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree kp : ℕ) (shuffle : ByteKey)
    (accepted : Option (ℕ × Digest))
    (ha : match accepted with | none => True | some result => wotsAccept (wotsOfDigest result.2) = true) :
    evalProgram digestDraw (wotsSignAfterProgram encode seed layer tree kp shuffle accepted) table =
      wotsSignAfter encode table seed layer tree kp shuffle accepted := by
  cases accepted with
  | none => rw [wotsSignAfterProgram]; rfl
  | some value =>
    rcases value with ⟨count, digest⟩
    simp only [wotsSignAfterProgram, ha, ↓reduceDIte, evalProgram_bind, wots_shuffle_eval,
      evalProgram_mapReturn, wots_accepted_fill_eval, wotsSignAfter]

theorem wots_sign_after_public (seed : ByteKey) (layer tree kp : ℕ) (shuffle : ByteKey)
    (accepted : Option (ℕ × Digest)) :
    PublicBudget (wotsSignAfterProgram id seed layer tree kp shuffle accepted) 209 := by
  cases accepted with
  | none => rw [wotsSignAfterProgram]; trivial
  | some value =>
    rcases value with ⟨count, digest⟩
    by_cases ha : wotsAccept (wotsOfDigest digest) = true
    · simp only [wotsSignAfterProgram, ha, ↓reduceDIte]
      apply publicBudget_bind _ _ 4 205 (publicBudget_total _)
      intro order
      rw [publicBudget_mapReturn]
      exact wots_accepted_fill_public _ _ _ _ _ ha _
    · rw [wotsSignAfterProgram, dif_neg ha]
      trivial

def wotsSignProgram (encode : WotsQuery → K) (seed : ByteKey)
    (layer tree kp : ℕ) (message shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32) :
    QueryProgram K Digest WotsSignature (n + 252) :=
  castProgram (Nat.add_comm 252 n)
    (bindProgram (mapProgram (fun key => encode (.inl key))
      (wotsCountProgram seed layer tree kp message 0 n (by simpa using hb)))
      (wotsSignAfterProgram encode seed layer tree kp shuffle))

def wotsSign [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (message shuffle : ByteKey)
    (n : ℕ) (hb : n ≤ 2 ^ 32) : PMF (WotsSignature × Memo K Digest) :=
  (wotsCountUnder (fun key => encode (.inl key)) table seed layer tree kp message n hb).bind
    (fun out => wotsSignAfter encode out.2 seed layer tree kp shuffle out.1)

theorem wots_sign_eval [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (message shuffle : ByteKey)
    (n : ℕ) (hb : n ≤ 2 ^ 32) :
    evalProgram digestDraw (wotsSignProgram encode seed layer tree kp message shuffle n hb) table =
      wotsSign encode table seed layer tree kp message shuffle n hb := by
  rw [wotsSignProgram, evalProgram_cast, evalProgram_bind,
    wots_count_under_eval (fun key => encode (.inl key)) table seed layer tree kp message n hb, wotsSign]
  apply pmf_bind_support_congr
  intro out ho
  refine wots_sign_after_eval encode out.2 seed layer tree kp shuffle out.1 ?_
  have accepted := memoGrind_result_accepts digestDraw (wotsAccept ∘ wotsOfDigest) table 0
      ((counterSchedule (wotsCountStem seed layer tree kp message) 0 n
        (by simpa using hb)).map (fun key => encode (.inl key))) out ho
  rcases out with ⟨result, cache⟩
  cases result with
  | none => trivial
  | some result => simpa only [Function.comp_def] using accepted

theorem wots_sign_public (seed : ByteKey) (layer tree kp : ℕ)
    (message shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32) :
    PublicBudget (wotsSignProgram id seed layer tree kp message shuffle n hb) (n + 209) := by
  rw [wotsSignProgram, publicBudget_cast]
  exact publicBudget_bind _ _ n 209 (publicBudget_total _)
    (wots_sign_after_public seed layer tree kp shuffle)

theorem wots_sign_prefix_error (seed : ByteKey) (layer tree kp : ℕ)
    (message shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32) (event : Set WotsSignature) :
    |((privateShared digestDraw digestDraw prefixedPrivateInput
        (PMF.pure (wotsSignProgram id seed layer tree kp message shuffle n hb))).toOuterMeasure event).toReal -
      ((privateIndependent digestDraw
        (PMF.pure (wotsSignProgram id seed layer tree kp message shuffle n hb))).toOuterMeasure event).toReal| ≤
      ((n + 209 : ℕ) : ℝ) / 2 ^ 256 := by
  apply private_secret_event_error_real _ (n + 209)
  intro program hp
  have he : program = wotsSignProgram id seed layer tree kp message shuffle n hb := by simpa using hp
  rw [he]
  exact wots_sign_public _ _ _ _ _ _ _ _

end
end C10Probability

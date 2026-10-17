import C10Probability.LayerSign
import C10Probability.TreeAccess

/-! Returned counter and authentication bounds come from the executed search
and builder, for arbitrary initial cache. Zero-budget failure retains all work
already performed by the layer before entering its WOTS count search. -/
namespace C10Probability
noncomputable section

variable {K α : Type*}

theorem memoGrind_result_range [DecidableEq K] (p : PMF α) (accept : α → Bool)
    (table : Memo K α) (start : ℕ) (keys : List K) (out : Option (ℕ × α) × Memo K α)
    (ho : out ∈ (memoGrind p accept table start keys).support) :
    match out.1 with
    | none => True
    | some hit => start ≤ hit.1 ∧ hit.1 < start + keys.length := by
  induction keys generalizing start table out with
  | nil =>
    have he : out = (none, table) := by simpa [memoGrind] using ho
    simp [he]
  | cons key keys ih =>
    rw [memoGrind, PMF.mem_support_bind_iff] at ho
    obtain ⟨reply, _, ho⟩ := ho
    cases ha : accept reply.1
    · simp only [ha, Bool.false_eq_true, ↓reduceIte] at ho
      have h := ih reply.2 (start + 1) out ho
      cases hout : out.1 with
      | none => trivial
      | some hit =>
        simp only [hout, List.length_cons] at h ⊢
        omega
    · simp only [ha, ↓reduceIte] at ho
      have he : out = (some (start, reply.1), reply.2) := by simpa using ho
      simp [he]

theorem wots_sign_returned_count [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree leaf : ℕ)
    (message shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32)
    (out : WotsSignature × Memo K Digest)
    (ho : out ∈ (wotsSign encode table seed layer tree leaf message shuffle n hb).support) :
    match out.1 with | none => True | some sig => sig.2 < n := by
  rw [wotsSign, PMF.mem_support_bind_iff] at ho
  obtain ⟨counted, hc, ho⟩ := ho
  have range := memoGrind_result_range digestDraw (wotsAccept ∘ wotsOfDigest) table 0
    ((counterSchedule (wotsCountStem seed layer tree leaf message) 0 n (by simpa using hb)).map
      (fun key => encode (.inl key))) counted hc
  cases hcount : counted.1 with
  | none =>
    have he : out = (none, counted.2) := by simpa [wotsSignAfter, hcount] using ho
    simp [he]
  | some result =>
    rcases result with ⟨count, digest⟩
    rw [hcount, wotsSignAfter, PMF.mem_support_bind_iff] at ho
    obtain ⟨order, _, ho⟩ := ho
    rw [PMF.mem_support_map_iff] at ho
    obtain ⟨filled, _, rfl⟩ := ho
    simp only [hcount, List.length_map, counter_schedule_length, Nat.zero_add] at range
    exact range.2

theorem layer_sign_signature_bound [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree leaf : ℕ)
    (message : Randomizer) (shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32)
    (out : LayerSigned × Memo K Digest)
    (ho : out ∈ (layerSign encode table seed layer tree leaf message shuffle n hb).support) :
    match out.1 with | none => True | some signed => LayerSignatureWellFormed signed.1 := by
  rw [layerSign, PMF.mem_support_bind_iff] at ho
  obtain ⟨built, hbuilt, ho⟩ := ho
  have auth := merkle_build_auth_length encode table seed layer tree leaf built hbuilt
  rw [PMF.mem_support_bind_iff] at ho
  obtain ⟨subseed, _, ho⟩ := ho
  rw [PMF.mem_support_bind_iff] at ho
  obtain ⟨signed, hsigned, ho⟩ := ho
  have count := wots_sign_returned_count encode subseed.2 seed layer tree leaf
    (nodeValueBytes message) subseed.1 n hb signed hsigned
  cases hsig : signed.1 with
  | none =>
    have he : out = (none, signed.2) := by simpa [layerSignAfter, hsig] using ho
    simp [he]
  | some sig =>
    rcases sig with ⟨sigma, nonce⟩
    rw [hsig, layerSignAfter, PMF.mem_support_map_iff] at ho
    obtain ⟨recovered, _, rfl⟩ := ho
    simp only [hsig] at count
    exact ⟨lt_of_lt_of_le count hb, auth⟩

theorem wots_sign_zero_budget [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree leaf : ℕ)
    (message shuffle : ByteKey) (hb : 0 ≤ 2 ^ 32) :
    wotsSign encode table seed layer tree leaf message shuffle 0 hb = PMF.pure (none, table) := by
  simp [wotsSign, wotsCountUnder, counterSchedule, memoGrind, PMF.pure_bind, wotsSignAfter]

theorem layer_sign_zero_budget [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree leaf : ℕ)
    (message : Randomizer) (shuffle : ByteKey) (hb : 0 ≤ 2 ^ 32) :
    layerSign encode table seed layer tree leaf message shuffle 0 hb =
      (merkleBuild encode table seed layer tree leaf).bind (fun built =>
        (shuffleDerive (fun key => encode (.inl key)) shuffle (layerShuffleLabel layer) built.2).map
          (fun out => (none, out.2))) := by
  simp only [layerSign, wots_sign_zero_budget, PMF.pure_bind, layerSignAfter]
  rfl

end
end C10Probability

import C10Probability.RContext
import C10Probability.QueryTrace

/-! The actual memoized search can only create private R entries for its own
request context. Public queries do not create private entries. These are
support properties of the executed cache updates, including exhaustion. -/
namespace C10Probability
noncomputable section

theorem r_context_history_public_query (contexts : Finset RContext)
    (table : Memo (Sum ByteKey ByteKey) Digest) (key : ByteKey)
    (history : RContextHistory contexts table)
    (out : Digest × Memo (Sum ByteKey ByteKey) Digest)
    (supported : out ∈ (memoQuery digestDraw table (.inl key)).support) :
    RContextHistory contexts out.2 := by
  intro context nonce value valid stored
  rcases memoQuery_origin digestDraw table (.inl key)
      (.inr (rContextTail context nonce)) value out supported stored with prior | equal
  · exact history context nonce value valid prior
  · cases equal

theorem r_context_history_private_query (contexts : Finset RContext)
    (table : Memo (Sum ByteKey ByteKey) Digest) (context : RContext)
    (valid : validRContext context) (member : context ∈ contexts) (nonce : Counter)
    (history : RContextHistory contexts table)
    (out : Digest × Memo (Sum ByteKey ByteKey) Digest)
    (supported : out ∈ (memoQuery digestDraw table (.inr (rContextTail context nonce))).support) :
    RContextHistory contexts out.2 := by
  intro requested count value requestValid stored
  rcases memoQuery_origin digestDraw table (.inr (rContextTail context nonce))
      (.inr (rContextTail requested count)) value out supported stored with prior | equal
  · exact history requested count value requestValid prior
  · have same := (r_context_tail_injective requested context count nonce
      requestValid.1 valid.1 (Sum.inr.inj equal)).1
    simpa only [same] using member

theorem r_context_history_derived (contexts : Finset RContext)
    (context : RContext) (valid : validRContext context) (member : context ∈ contexts)
    (seed root : ByteKey) (keys : List ByteKey)
    (origins : ∀ key ∈ keys, ∃ nonce, key = rContextTail context nonce)
    (table : Memo (Sum ByteKey ByteKey) Digest) (history : RContextHistory contexts table)
    (start : ℕ) (out : Option (ℕ × Randomizer × Digest) × Memo (Sum ByteKey ByteKey) Digest)
    (supported : out ∈ (derivedMemoGrind digestDraw randomizerOfDigest
      (Sum.inl ∘ hmsgRandomizerInput seed root context.2) (forsAccept ∘ forsOfDigest)
      table start (keys.map Sum.inr)).support) : RContextHistory contexts out.2 := by
  induction keys generalizing table start out with
  | nil =>
    have equal : out = (none, table) := by
      simpa only [List.map_nil, derivedMemoGrind, PMF.mem_support_pure_iff] using supported
    simpa only [equal] using history
  | cons key keys ih =>
    simp only [List.map_cons, derivedMemoGrind, PMF.mem_support_bind_iff] at supported
    obtain ⟨first, firstSupport, second, secondSupport, supported⟩ := supported
    obtain ⟨nonce, keyEqual⟩ := origins key (by simp)
    have firstHistory : RContextHistory contexts first.2 := by
      apply r_context_history_private_query contexts table context valid member nonce history first
      simpa only [keyEqual] using firstSupport
    have secondHistory := r_context_history_public_query contexts first.2
      (hmsgRandomizerInput seed root context.2 (randomizerOfDigest first.1))
      firstHistory second secondSupport
    cases accepted : forsAccept (forsOfDigest second.1)
    · simp only [Function.comp_apply, accepted, Bool.false_eq_true, ↓reduceIte] at supported
      exact ih (fun other present => origins other (by simp [present]))
        second.2 secondHistory (start + 1) out supported
    · simp only [Function.comp_apply, accepted, ↓reduceIte, PMF.mem_support_pure_iff] at supported
      simpa only [supported] using secondHistory

theorem r_context_history_search (contexts : Finset RContext)
    (context : RContext) (valid : validRContext context) (seed root : ByteKey)
    (n : ℕ) (bound : 0 + n ≤ 2 ^ 32)
    (table : Memo (Sum ByteKey ByteKey) Digest) (history : RContextHistory contexts table)
    (out : Option (ℕ × Randomizer × Digest) × Memo (Sum ByteKey ByteKey) Digest)
    (supported : out ∈
      (privateRandomizerSearch table context.1 context.2 seed root n bound).support) :
    RContextHistory (insert context contexts) out.2 := by
  classical
  apply r_context_history_derived (insert context contexts) context valid (by simp)
    seed root (counterSchedule (rTailStem context.1 context.2) 0 n bound) ?_
    table (r_context_history_mono contexts _ table (Finset.subset_insert _ _) history) 0 out supported
  intro key member
  obtain ⟨nonce, equal, _, _⟩ := r_context_schedule_origin context 0 n bound key member
  exact ⟨nonce, equal⟩

end
end C10Probability

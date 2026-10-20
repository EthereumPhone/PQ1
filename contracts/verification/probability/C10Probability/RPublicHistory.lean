import C10Probability.GrindInterface

/-! Finite public-cache coverage follows from the actual query trace. Private
derivation calls consume no public-history budget; cached public calls may be
counted conservatively. No finite-history assumption is added at empty start. -/
namespace C10Probability
noncomputable section

def RPublicHistory (seen : Finset ByteKey) (table : Memo (Sum ByteKey ByteKey) Digest) : Prop :=
  ∀ key value, table (.inl key) = some value → key ∈ seen

def BoundedRPublicHistory (budget : ℕ) (table : Memo (Sum ByteKey ByteKey) Digest) : Prop :=
  ∃ seen, seen.card ≤ budget ∧ RPublicHistory seen table

theorem r_public_history_empty : BoundedRPublicHistory 0 (fun _ => none) := by
  refine ⟨∅, by simp, ?_⟩
  intro key value stored
  cases stored

theorem r_public_history_mono (before after : ℕ)
    (table : Memo (Sum ByteKey ByteKey) Digest) (bound : before ≤ after)
    (history : BoundedRPublicHistory before table) : BoundedRPublicHistory after table := by
  obtain ⟨seen, size, cover⟩ := history
  exact ⟨seen, size.trans bound, cover⟩

theorem r_public_history_query (budget : ℕ) (table : Memo (Sum ByteKey ByteKey) Digest)
    (history : BoundedRPublicHistory budget table) (key : ByteKey)
    (out : Digest × Memo (Sum ByteKey ByteKey) Digest)
    (supported : out ∈ (memoQuery digestDraw table (.inl key)).support) :
    BoundedRPublicHistory (budget + 1) out.2 := by
  classical
  obtain ⟨seen, size, cover⟩ := history
  refine ⟨insert key seen, (Finset.card_insert_le _ _).trans (Nat.add_le_add_right size 1), ?_⟩
  intro other value stored
  rcases memoQuery_origin digestDraw table (.inl key) (.inl other) value
      out supported stored with prior | equal
  · exact Finset.mem_insert_of_mem (cover other value prior)
  · exact Finset.mem_insert.mpr (Or.inl (Sum.inl.inj equal))

theorem r_public_history_execution {R : Type*} {fuel : ℕ}
    (program : QueryProgram (Sum ByteKey ByteKey) Digest R fuel)
    (budget : ℕ) (calls : PublicBudget program budget)
    (seen : Finset ByteKey) (table : Memo (Sum ByteKey ByteKey) Digest)
    (history : RPublicHistory seen table) (out : R × Memo (Sum ByteKey ByteKey) Digest)
    (supported : out ∈ (evalProgram digestDraw program table).support) :
    ∃ after, after.card ≤ seen.card + budget ∧ RPublicHistory after out.2 := by
  classical
  have tracedSupport : out ∈ ((traceProgram digestDraw program table).map
      (fun traced => (traced.value, traced.cache))).support := by
    simpa only [traceProgram_erases] using supported
  rw [PMF.mem_support_map_iff] at tracedSupport
  obtain ⟨traced, tracedSupport, rfl⟩ := tracedSupport
  let added := (publicQueries traced.queries).toFinset
  have addedBound : added.card ≤ budget :=
    (List.toFinset_card_le _).trans
      (traceProgram_public_length digestDraw program budget calls table traced tracedSupport)
  refine ⟨seen ∪ added, (Finset.card_union_le _ _).trans (Nat.add_le_add_left addedBound _), ?_⟩
  intro key value stored
  rcases traceProgram_origin digestDraw program table traced tracedSupport
      (.inl key) value stored with prior | queried
  · exact Finset.mem_union_left _ (history key value prior)
  · apply Finset.mem_union_right
    apply List.mem_toFinset.mpr
    exact List.mem_filterMap.mpr ⟨.inl key, queried, rfl⟩

theorem r_public_history_search (budget : ℕ) (table : Memo (Sum ByteKey ByteKey) Digest)
    (history : BoundedRPublicHistory budget table) (random message seed root : ByteKey)
    (n : ℕ) (bound : 0 + n ≤ 2 ^ 32)
    (out : Option (ℕ × Randomizer × Digest) × Memo (Sum ByteKey ByteKey) Digest)
    (supported : out ∈ (privateRandomizerSearch table random message seed root n bound).support) :
    BoundedRPublicHistory (budget + n) out.2 := by
  obtain ⟨seen, size, cover⟩ := history
  rw [← privateRandomizerProgram_independent] at supported
  obtain ⟨after, afterSize, afterCover⟩ := r_public_history_execution
    (privateRandomizerProgram random message seed root n bound) n
    (privateRandomizerProgram_budget random message seed root n bound) seen table cover out supported
  exact ⟨after, afterSize.trans (Nat.add_le_add_right size n), afterCover⟩

theorem r_public_history_hmsg_card (seen : Finset ByteKey)
    (table : Memo (Sum ByteKey ByteKey) Digest) (history : RPublicHistory seen table)
    (seed root message : ByteKey) :
    (embeddedHistory table (Sum.inl ∘ hmsgRandomizerInput seed root message)).card ≤ seen.card := by
  classical
  let keys := embeddedHistory table (Sum.inl ∘ hmsgRandomizerInput seed root message)
  have inclusion : keys.image (hmsgRandomizerInput seed root message) ⊆ seen := by
    intro key member
    obtain ⟨randomizer, present, rfl⟩ := Finset.mem_image.mp member
    cases stored : table (.inl (hmsgRandomizerInput seed root message randomizer)) with
    | none => simp [keys, embeddedHistory, stored] at present
    | some value => exact history _ value stored
  calc
    keys.card = (keys.image (hmsgRandomizerInput seed root message)).card :=
      (Finset.card_image_of_injective keys (hmsg_randomizer_injective seed root message)).symm
    _ ≤ seen.card := Finset.card_le_card inclusion

theorem bounded_r_public_history_hmsg_card (budget : ℕ)
    (table : Memo (Sum ByteKey ByteKey) Digest) (history : BoundedRPublicHistory budget table)
    (seed root message : ByteKey) :
    (embeddedHistory table (Sum.inl ∘ hmsgRandomizerInput seed root message)).card ≤ budget := by
  obtain ⟨seen, size, cover⟩ := history
  exact (r_public_history_hmsg_card seen table cover seed root message).trans size

end
end C10Probability

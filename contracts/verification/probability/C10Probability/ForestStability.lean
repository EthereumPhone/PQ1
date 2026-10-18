import C10Probability.RootStability
import C10Probability.ForestHonest

/-! The actual forest public key at a fixed hypertree coordinate is independent
of the accepted digest's selected leaves and the signing shuffle. Every root
and both final lookups are derived from the executed signing program. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem recorded_forest_slot_roots_eq (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (firstDigest secondDigest : Digest)
    (first second : ForestState) (i : Fin 12)
    (one : RecordedForestSlot encode table seed ht firstDigest first i)
    (two : RecordedForestSlot encode table seed ht secondDigest second i) :
    (first.roots[i.val]?).getD 0 = (second.roots[i.val]?).getD 0 := by
  obtain ⟨a, ha, _, _, ar⟩ := one
  obtain ⟨b, hb, _, _, br⟩ := two
  simp only [ar, br, Option.getD_some]
  exact replay_forest_one_roots_eq encode table seed ht i.val
    (forestIndex firstDigest i.val) (forestIndex secondDigest i.val) a b ha hb
    (forest_index_bound firstDigest i.val) (forest_index_bound secondDigest i.val)

theorem replay_forest_ordered_compression_roots_eq (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (ht : ℕ)
    (firstDigest secondDigest : Digest) (firstOrder secondOrder : ForestOrder)
    (first second : ForestState)
    (one : replayProgram table (forestOrderedProgram encode seed ht firstDigest firstOrder) = some first)
    (two : replayProgram table (forestOrderedProgram encode seed ht secondDigest secondOrder) = some second)
    (last : Randomizer) : first.roots.set 12 last = second.roots.set 12 last := by
  obtain ⟨firstShape, firstSlots⟩ := replay_forest_ordered_records encode table seed ht firstDigest firstOrder first one
  obtain ⟨secondShape, secondSlots⟩ := replay_forest_ordered_records encode table seed ht secondDigest secondOrder second two
  rw [← forest_roots_complete first.roots last firstShape.2.2.1,
    ← forest_roots_complete second.roots last secondShape.2.2.1]
  congr 1
  apply List.map_congr_left
  intro i _
  exact recorded_forest_slot_roots_eq encode table seed ht firstDigest secondDigest
    first second i (firstSlots i) (secondSlots i)

theorem replay_forest_finish_lookup_witness (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (state : ForestState) (out : ForestOutput)
    (recorded : replayProgram table (forestFinishProgram encode seed ht state) = some out) :
    ∃ last leaf reply,
      replayProgram table (forsRootProgram encode seed ht 12) = some last ∧
      table (encode (.inl (forsLeafInput seed ht 12 0 last))) = some leaf ∧
      table (encode (.inl (forsPkInput seed ht (state.roots.set 12 (randomizerOfDigest leaf))))) = some reply ∧
      out.pk = randomizerOfDigest reply := by
  rw [forestFinishProgram] at recorded
  obtain ⟨last, root, finish⟩ := replay_program_bind_witness table _ _ _ recorded
  cases leaf : table (encode (.inl (forsLeafInput seed ht 12 0 last))) with
  | none => simp only [forestLastProgram, replayProgram, leaf, Option.bind_none] at finish; cases finish
  | some leafReply =>
    simp only [forestLastProgram, replayProgram, leaf, Option.bind_some] at finish
    cases compression : table (encode (.inl
        (forsPkInput seed ht (state.roots.set 12 (randomizerOfDigest leafReply))))) with
    | none => simp only [compression, Option.bind_none] at finish; cases finish
    | some reply =>
      simp only [compression, Option.bind_some, Option.some.injEq] at finish
      subst out
      exact ⟨last, leafReply, reply, root, leaf, compression, rfl⟩

theorem replay_forest_finish_pk_eq (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (first second : ForestState) (a b : ForestOutput)
    (roots : ∀ last, first.roots.set 12 last = second.roots.set 12 last)
    (one : replayProgram table (forestFinishProgram encode seed ht first) = some a)
    (two : replayProgram table (forestFinishProgram encode seed ht second) = some b) :
    a.pk = b.pk := by
  obtain ⟨last, leaf, reply, root, lookup, compression, value⟩ :=
    replay_forest_finish_lookup_witness encode table seed ht first a one
  obtain ⟨last', leaf', reply', root', lookup', compression', value'⟩ :=
    replay_forest_finish_lookup_witness encode table seed ht second b two
  have lastEq := replay_program_unique _ table last last' root root'
  subst last'
  have leafEq := Option.some.inj (lookup.symm.trans lookup')
  subst leaf'
  rw [roots] at compression
  have replyEq := Option.some.inj (compression.symm.trans compression')
  exact value.trans ((congrArg randomizerOfDigest replyEq).trans value'.symm)

theorem replay_forest_sign_pk_eq (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (firstDigest secondDigest : Digest)
    (firstShuffle secondShuffle : ByteKey) (first second : ForestOutput)
    (one : replayProgram table (forestSignProgram encode seed ht firstDigest firstShuffle) = some first)
    (two : replayProgram table (forestSignProgram encode seed ht secondDigest secondShuffle) = some second) :
    first.pk = second.pk := by
  rw [forestSignProgram] at one two
  obtain ⟨firstOrder, _, rest⟩ := replay_program_bind_witness table _ _ _ one
  obtain ⟨firstState, firstOrdered, firstFinish⟩ := replay_program_bind_witness table _ _ _ rest
  obtain ⟨secondOrder, _, rest⟩ := replay_program_bind_witness table _ _ _ two
  obtain ⟨secondState, secondOrdered, secondFinish⟩ := replay_program_bind_witness table _ _ _ rest
  exact replay_forest_finish_pk_eq encode table seed ht firstState secondState first second
    (replay_forest_ordered_compression_roots_eq encode table seed ht firstDigest secondDigest
      firstOrder secondOrder firstState secondState firstOrdered secondOrdered)
    firstFinish secondFinish

end
end C10Probability

import C10Probability.ForestRecoveryRecord
import C10Probability.TreeRootCertificate

/-! Actual shuffled forest signing supplies every ordinary tree certificate,
the special thirteenth root, and both final hash lookups. Returned arrays and
the compressed public key are linked to the same executed program. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem recorded_forest_slot_certificate (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (state : ForestState) (i : Fin 12)
    (recorded : RecordedForestSlot encode table seed ht digest state i) :
    ForsTreeCertificate encode table seed ht i.val ((state.roots[i.val]?).getD 0) := by
  obtain ⟨out, one, _, _, root⟩ := recorded
  have built := (replay_forest_one_builder encode table seed ht i.val
    (forestIndex digest i.val) out one (forest_index_bound digest i.val)).2
  simpa only [root, Option.getD_some] using
    replay_fors_tree_certificate encode table seed ht i.val
      (forestIndex digest i.val) (out.root, out.auth) built

structure ForestSigningRecord where
  order : ForestOrder
  state : ForestState
  last : Randomizer
  lastDigest : Digest
  pkDigest : Digest

structure ForestSigningRecordValid (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (shuffle : ByteKey)
    (out : ForestOutput) (record : ForestSigningRecord) : Prop where
  order : replayProgram table (forestShuffleProgram (fun key => encode (.inl key)) shuffle) =
    some record.order
  ordered : replayProgram table (forestOrderedProgram encode seed ht digest record.order) =
    some record.state
  shape : ForestShape record.state
  slots : ∀ i, RecordedForestSlot encode table seed ht digest record.state i
  certificates : ∀ i : Fin 12,
    ForsTreeCertificate encode table seed ht i.val ((record.state.roots[i.val]?).getD 0)
  lastRoot : replayProgram table (forsRootProgram encode seed ht 12) = some record.last
  lastCertificate : ForsTreeCertificate encode table seed ht 12 record.last
  lastLeaf : table (encode (.inl (forsLeafInput seed ht 12 0 record.last))) = some record.lastDigest
  compression : table (encode (.inl (forsPkInput seed ht
    (record.state.roots.set 12 (randomizerOfDigest record.lastDigest))))) = some record.pkDigest
  secrets : out.secrets = record.state.secrets.set 12 record.last
  auths : out.auths = record.state.auths
  publicKey : out.pk = randomizerOfDigest record.pkDigest

theorem replay_forest_sign_record (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (shuffle : ByteKey) (out : ForestOutput)
    (recorded : replayProgram table (forestSignProgram encode seed ht digest shuffle) = some out) :
    ∃ record, ForestSigningRecordValid encode table seed ht digest shuffle out record := by
  rw [forestSignProgram] at recorded
  obtain ⟨order, orderedShuffle, rest⟩ := replay_program_bind_witness table _ _ _ recorded
  obtain ⟨state, ordered, finish⟩ := replay_program_bind_witness table _ _ _ rest
  obtain ⟨shape, slots⟩ := replay_forest_ordered_records encode table seed ht digest order state ordered
  rw [forestFinishProgram] at finish
  obtain ⟨last, root, finish⟩ := replay_program_bind_witness table _ _ _ finish
  cases leaf : table (encode (.inl (forsLeafInput seed ht 12 0 last))) with
  | none => simp only [forestLastProgram, replayProgram, leaf, Option.bind_none] at finish; cases finish
  | some lastDigest =>
    simp only [forestLastProgram, replayProgram, leaf, Option.bind_some] at finish
    cases compression : table (encode (.inl
        (forsPkInput seed ht (state.roots.set 12 (randomizerOfDigest lastDigest))))) with
    | none => simp only [compression, Option.bind_none] at finish; cases finish
    | some pkDigest =>
      simp only [compression, Option.bind_some, Option.some.injEq] at finish
      subst out
      refine ⟨⟨order, state, last, lastDigest, pkDigest⟩,
        orderedShuffle, ordered, shape, slots, ?_, root,
        replay_fors_root_certificate encode table seed ht 12 last root,
        leaf, compression, rfl, rfl, rfl⟩
      exact fun i => recorded_forest_slot_certificate encode table seed ht digest state i (slots i)

end
end C10Probability

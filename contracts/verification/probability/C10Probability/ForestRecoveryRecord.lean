import C10Probability.ForestHonest
import Mathlib.Data.List.Forall2

/-! The actual verifier supplies the ordered twelve recovered roots, the
separate hash of its thirteenth transmitted value, and the final compression
lookup. Defaults for missing secrets and authentication arrays are preserved. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem replay_forest_recovery_records (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (secrets : List Randomizer)
    (auths : List (List Randomizer)) (indices : List (Fin 12))
    (initial result : List Randomizer)
    (recorded : replayProgram table
      (forestRecoveryProgram encode seed ht digest secrets auths indices initial) = some result) :
    ∃ values, result = initial ++ values ∧
      List.Forall₂ (fun i root => replayProgram table (forsRecoverProgram encode seed ht i.val
        (forestIndex digest i.val) ((secrets[i.val]?).getD 0)
        ((auths[i.val]?).getD [])) = some root) indices values := by
  induction indices generalizing initial result with
  | nil =>
    have equal : initial = result := Option.some.inj recorded
    exact ⟨[], by simpa only [List.append_nil] using equal.symm, .nil⟩
  | cons i rest ih =>
    rw [forestRecoveryProgram, stateFoldProgram, replay_program_cast] at recorded
    obtain ⟨middle, head, tail⟩ := replay_program_bind_witness table _ _ _ recorded
    rw [forestRecoveryStep] at head
    obtain ⟨root, recovered, written⟩ := replay_program_map_witness table _ _ _ head
    subst middle
    obtain ⟨values, equal, records⟩ := ih (initial ++ [root]) result tail
    exact ⟨root :: values, by simpa only [List.append_assoc, List.singleton_append] using equal,
      .cons recovered records⟩

theorem replay_forest_recovery_positions (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (secrets : List Randomizer)
    (auths : List (List Randomizer)) (roots : List Randomizer)
    (recorded : replayProgram table (forestRecoveryProgram encode seed ht digest secrets auths
      forestTreeIndices []) = some roots) :
    roots.length = 12 ∧ ∀ i : Fin 12, replayProgram table
      (forsRecoverProgram encode seed ht i.val (forestIndex digest i.val)
        ((secrets[i.val]?).getD 0) ((auths[i.val]?).getD [])) = some ((roots[i.val]?).getD 0) := by
  obtain ⟨values, equal, records⟩ := replay_forest_recovery_records encode table seed ht
    digest secrets auths forestTreeIndices [] roots recorded
  simp only [List.nil_append] at equal
  subst roots
  have length : values.length = 12 := by
    simpa only [forest_tree_indices_length] using records.length_eq.symm
  refine ⟨length, ?_⟩
  intro i
  have position := records.get (by simpa only [forest_tree_indices_length] using i.isLt)
    (by simpa only [length] using i.isLt)
  simpa only [List.get_eq_getElem, forestTreeIndices, List.getElem_ofFn, id_eq,
    List.getElem?_eq_getElem (by omega : i.val < values.length), Option.getD_some] using position

structure ForestRecoveryRecord where
  roots : List Randomizer
  lastDigest : Digest
  pkDigest : Digest

structure ForestRecoveryRecordValid (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (secrets : List Randomizer)
    (auths : List (List Randomizer)) (pk : Randomizer) (record : ForestRecoveryRecord) : Prop where
  replay : replayProgram table (forestRecoveryProgram encode seed ht digest secrets auths
    forestTreeIndices []) = some record.roots
  length : record.roots.length = 12
  positions : ∀ i : Fin 12, replayProgram table (forsRecoverProgram encode seed ht i.val
    (forestIndex digest i.val) ((secrets[i.val]?).getD 0) ((auths[i.val]?).getD [])) =
      some ((record.roots[i.val]?).getD 0)
  last : table (encode (forsLeafInput seed ht 12 0 ((secrets[12]?).getD 0))) = some record.lastDigest
  compression : table (encode (forsPkInput seed ht
    (record.roots ++ [randomizerOfDigest record.lastDigest]))) = some record.pkDigest
  publicKey : randomizerOfDigest record.pkDigest = pk

theorem replay_forest_recover_record (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (secrets : List Randomizer)
    (auths : List (List Randomizer)) (pk : Randomizer)
    (recorded : replayProgram table (forestRecoverProgram encode seed ht digest secrets auths) = some pk) :
    ∃ record, ForestRecoveryRecordValid encode table seed ht digest secrets auths pk record := by
  rw [forestRecoverProgram] at recorded
  obtain ⟨roots, loop, finish⟩ := replay_program_bind_witness table _ _ _ recorded
  rw [replay_program_cast] at loop
  obtain ⟨length, positions⟩ := replay_forest_recovery_positions encode table seed ht digest secrets auths roots loop
  cases last : table (encode (forsLeafInput seed ht 12 0 ((secrets[12]?).getD 0))) with
  | none => simp only [replayProgram, last, Option.bind_none] at finish; cases finish
  | some lastDigest =>
    simp only [replayProgram, last, Option.bind_some] at finish
    cases compression : table (encode (forsPkInput seed ht (roots ++ [randomizerOfDigest lastDigest]))) with
    | none => simp only [compression, Option.bind_none] at finish; cases finish
    | some pkDigest =>
      simp only [compression, Option.bind_some, Option.some.injEq] at finish
      exact ⟨⟨roots, lastDigest, pkDigest⟩, loop, length, positions, last, compression, finish⟩

end
end C10Probability

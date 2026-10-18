import C10Probability.ForestAccess
import C10Probability.ProgramReplayWitness
import C10Probability.ReturnedForsSigning

/-! Actual per-tree signing/recovery records survive shuffled positional
writes. Every ordinary forest position is derived from the computed order;
the invariant does not assume that the returned arrays already agree. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem replay_forest_one_recorded (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree target : ℕ) (out : ForestTreeResult)
    (recorded : replayProgram table (forestOneProgram encode seed ht tree target) = some out) :
    replayProgram table (forsSignProgram encode seed ht tree target) = some (out.secret, out.auth) ∧
      replayProgram table (forsRecoverProgram (fun key => encode (.inl key))
        seed ht tree target out.secret out.auth) = some out.root := by
  rw [forestOneProgram] at recorded
  obtain ⟨sig, signed, rest⟩ := replay_program_bind_witness table _ _ _ recorded
  obtain ⟨root, recovered, equal⟩ := replay_program_map_witness table _ _ _ rest
  subst out
  exact ⟨signed, recovered⟩

theorem replay_forest_one_builder (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree target : ℕ) (out : ForestTreeResult)
    (recorded : replayProgram table (forestOneProgram encode seed ht tree target) = some out)
    (bound : target < 2048) :
    out.auth.length = 11 ∧
      replayProgram table (forsTreeProgram encode seed ht tree target) = some (out.root, out.auth) := by
  obtain ⟨signed, recovered⟩ := replay_forest_one_recorded encode table seed ht tree target out recorded
  obtain ⟨length, root, built, correct⟩ := replay_fors_sign_returned_recovery encode table
    seed ht tree target (out.secret, out.auth) signed bound
  have equal := replay_program_unique _ table out.root root recovered correct
  exact ⟨length, by simpa only [equal] using built⟩

def RecordedForestSlot (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (state : ForestState) (i : Fin 12) : Prop :=
  ∃ out : ForestTreeResult,
    replayProgram table (forestOneProgram encode seed ht i.val (forestIndex digest i.val)) = some out ∧
    state.secrets[i.val]? = some out.secret ∧ state.auths[i.val]? = some out.auth ∧
    state.roots[i.val]? = some out.root

theorem forest_recorded_write (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (state : ForestState) (i : Fin 12)
    (out : ForestTreeResult) (shape : ForestShape state)
    (recorded : replayProgram table (forestOneProgram encode seed ht i.val (forestIndex digest i.val)) = some out) :
    RecordedForestSlot encode table seed ht digest (forestWrite state i.val out) i ∧
      (∀ j, RecordedForestSlot encode table seed ht digest state j →
        RecordedForestSlot encode table seed ht digest (forestWrite state i.val out) j) := by
  obtain ⟨secretBound, authBound, rootBound⟩ := forest_write_indices state i shape
  have here : RecordedForestSlot encode table seed ht digest (forestWrite state i.val out) i :=
    ⟨out, recorded, List.getElem?_set_self secretBound,
      List.getElem?_set_self authBound, List.getElem?_set_self rootBound⟩
  refine ⟨here, ?_⟩
  intro j old
  by_cases equal : i.val = j.val
  · have same : i = j := Fin.ext equal
    subst j
    exact here
  · obtain ⟨prior, replay, secret, auth, root⟩ := old
    refine ⟨prior, replay, ?_, ?_, ?_⟩
    · simpa only [forestWrite, List.getElem?_set_ne equal] using secret
    · simpa only [forestWrite, List.getElem?_set_ne equal] using auth
    · simpa only [forestWrite, List.getElem?_set_ne equal] using root

theorem replay_forest_fill_records (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (order : List (Fin 12))
    (initial result : ForestState) (shape : ForestShape initial)
    (recorded : replayProgram table (forestFillProgram encode seed ht digest order initial) = some result) :
    ForestShape result ∧
      ∀ i, i ∈ order ∨ RecordedForestSlot encode table seed ht digest initial i →
        RecordedForestSlot encode table seed ht digest result i := by
  induction order generalizing initial result with
  | nil =>
    have equal : initial = result := Option.some.inj recorded
    subst result
    exact ⟨shape, fun _ h => h.resolve_left (by simp)⟩
  | cons i rest ih =>
    rw [forestFillProgram, stateFoldProgram, replay_program_cast] at recorded
    obtain ⟨middle, head, tail⟩ := replay_program_bind_witness table _ _ _ recorded
    rw [forestFillStep] at head
    obtain ⟨out, one, written⟩ := replay_program_map_witness table _ _ _ head
    subst middle
    have length := (replay_forest_one_builder encode table seed ht i.val
      (forestIndex digest i.val) out one (forest_index_bound digest i.val)).1
    have newShape := forest_write_shape initial i.val out shape length
    obtain ⟨finalShape, finalSlots⟩ := ih (forestWrite initial i.val out) result newShape tail
    obtain ⟨here, preserve⟩ := forest_recorded_write encode table seed ht digest initial i out shape one
    refine ⟨finalShape, ?_⟩
    intro j eligible
    apply finalSlots j
    rcases eligible with member | old
    · rcases List.mem_cons.mp member with same | later
      · exact Or.inr (same ▸ here)
      · exact Or.inl later
    · exact Or.inr (preserve j old)

theorem replay_forest_ordered_records (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (order : ForestOrder) (state : ForestState)
    (recorded : replayProgram table (forestOrderedProgram encode seed ht digest order) = some state) :
    ForestShape state ∧ ∀ i, RecordedForestSlot encode table seed ht digest state i := by
  rw [forestOrderedProgram, replay_program_cast] at recorded
  obtain ⟨shape, positions⟩ := replay_forest_fill_records encode table seed ht digest
    order.val emptyForestState state empty_forest_shape recorded
  exact ⟨shape, fun i => positions i (Or.inl (forest_order_mem order i))⟩

theorem recorded_forest_slot_recovery (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (state : ForestState) (i : Fin 12)
    (recorded : RecordedForestSlot encode table seed ht digest state i) :
    replayProgram table (forsRecoverProgram (fun key => encode (.inl key)) seed ht i.val
      (forestIndex digest i.val) ((state.secrets[i.val]?).getD 0)
      ((state.auths[i.val]?).getD [])) = some ((state.roots[i.val]?).getD 0) := by
  obtain ⟨out, one, secret, auth, root⟩ := recorded
  simpa only [secret, auth, root, Option.getD_some] using
    (replay_forest_one_recorded encode table seed ht i.val (forestIndex digest i.val) out one).2

end
end C10Probability

import C10Probability.RContext
import C10Probability.QueryReplay

/-! Previously successful contexts replay the actual search and its complete
result. The witness is derived from execution support and survives all later
memo extensions; cached success is never counted as a fresh random trial. -/
namespace C10Probability
noncomputable section

abbrev RSearchResult := ℕ × Randomizer × Digest

def AcceptedRContexts (contexts : Finset RContext)
    (table : Memo (Sum ByteKey ByteKey) Digest) (seed root : ByteKey)
    (n : ℕ) (bound : 0 + n ≤ 2 ^ 32) : Prop :=
  ∀ context ∈ contexts, ∃ result : RSearchResult,
    replayProgram table (privateRandomizerProgram context.1 context.2 seed root n bound) =
      some (some result)

theorem accepted_r_contexts_empty (table : Memo (Sum ByteKey ByteKey) Digest)
    (seed root : ByteKey) (n : ℕ) (bound : 0 + n ≤ 2 ^ 32) :
    AcceptedRContexts ∅ table seed root n bound := by
  intro context member
  cases member

theorem accepted_r_contexts_extend (contexts : Finset RContext)
    (before after : Memo (Sum ByteKey ByteKey) Digest) (seed root : ByteKey)
    (n : ℕ) (bound : 0 + n ≤ 2 ^ 32)
    (accepted : AcceptedRContexts contexts before seed root n bound)
    (extension : MemoExtends before after) :
    AcceptedRContexts contexts after seed root n bound := by
  intro context member
  obtain ⟨result, recorded⟩ := accepted context member
  exact ⟨result, replay_program_extends _ before after _ extension recorded⟩

theorem r_context_replay_exact (table : Memo (Sum ByteKey ByteKey) Digest)
    (context : RContext) (seed root : ByteKey) (n : ℕ) (bound : 0 + n ≤ 2 ^ 32)
    (result : RSearchResult)
    (recorded : replayProgram table
      (privateRandomizerProgram context.1 context.2 seed root n bound) = some (some result)) :
    privateRandomizerSearch table context.1 context.2 seed root n bound =
      PMF.pure (some result, table) := by
  rw [← privateRandomizerProgram_independent]
  exact replay_program_eval digestDraw _ table _ recorded

theorem r_context_replay_from_support (before after : Memo (Sum ByteKey ByteKey) Digest)
    (context : RContext) (seed root : ByteKey) (n : ℕ) (bound : 0 + n ≤ 2 ^ 32)
    (result : RSearchResult)
    (supported : (some result, after) ∈
      (privateRandomizerSearch before context.1 context.2 seed root n bound).support) :
    replayProgram after (privateRandomizerProgram context.1 context.2 seed root n bound) =
      some (some result) := by
  rw [← privateRandomizerProgram_independent] at supported
  exact eval_program_replay digestDraw _ before (some result, after) supported

theorem r_context_replay_later (before after later : Memo (Sum ByteKey ByteKey) Digest)
    (context : RContext) (seed root : ByteKey) (n : ℕ) (bound : 0 + n ≤ 2 ^ 32)
    (result : RSearchResult)
    (supported : (some result, after) ∈
      (privateRandomizerSearch before context.1 context.2 seed root n bound).support)
    (extension : MemoExtends after later) :
    privateRandomizerSearch later context.1 context.2 seed root n bound =
      PMF.pure (some result, later) := by
  apply r_context_replay_exact
  exact replay_program_extends _ after later _ extension
    (r_context_replay_from_support before after context seed root n bound result supported)

theorem accepted_r_contexts_insert_success (contexts : Finset RContext)
    (before after : Memo (Sum ByteKey ByteKey) Digest)
    (context : RContext) (seed root : ByteKey) (n : ℕ) (bound : 0 + n ≤ 2 ^ 32)
    (result : RSearchResult)
    (accepted : AcceptedRContexts contexts before seed root n bound)
    (supported : (some result, after) ∈
      (privateRandomizerSearch before context.1 context.2 seed root n bound).support) :
    AcceptedRContexts (insert context contexts) after seed root n bound := by
  classical
  have execution : (some result, after) ∈ (evalProgram digestDraw
      (privateRandomizerProgram context.1 context.2 seed root n bound) before).support := by
    simpa only [privateRandomizerProgram_independent] using supported
  have extension := eval_program_extends digestDraw _ before (some result, after) execution
  intro requested member
  rcases Finset.mem_insert.mp member with same | old
  · subst requested
    exact ⟨result, eval_program_replay digestDraw _ before (some result, after) execution⟩
  · exact accepted_r_contexts_extend contexts before after seed root n bound
      accepted extension requested old

theorem accepted_r_context_has_no_exhaustion (contexts : Finset RContext)
    (table : Memo (Sum ByteKey ByteKey) Digest) (seed root : ByteKey)
    (n : ℕ) (bound : 0 + n ≤ 2 ^ 32)
    (accepted : AcceptedRContexts contexts table seed root n bound)
    (context : RContext) (member : context ∈ contexts) :
    ((privateRandomizerSearch table context.1 context.2 seed root n bound).map Prod.fst) none = 0 := by
  obtain ⟨result, recorded⟩ := accepted context member
  rw [r_context_replay_exact table context seed root n bound result recorded, PMF.pure_map]
  simp

end
end C10Probability

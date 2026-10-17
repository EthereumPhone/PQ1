import C10Probability.QueryReplay

/-! Lookup-only splitting and reverse binding for the actual chain program.
Every step uses one fixed cache; these facts make no fresh-sampling claim. -/
namespace C10Probability
noncomputable section

variable {K α N : Type*}

theorem replay_chain_split (table : Memo K α) (input : ℕ → N → K)
    (project : α → N) (start first later : ℕ) (current : N) :
    replayProgram table (chainProgram input project start (first + later) current) =
      (replayProgram table (chainProgram input project start first current)).bind
        (fun middle => replayProgram table
          (chainProgram input project (start + first) later middle)) := by
  induction first generalizing start current with
  | zero =>
    rw [Nat.zero_add]
    simp only [Nat.add_zero, chainProgram, replayProgram, Option.bind_some]
  | succ first ih =>
    rw [show first + 1 + later = (first + later) + 1 by omega]
    simp only [chainProgram, replayProgram, ih, Option.bind_assoc,
      show start + 1 + first = start + (first + 1) by omega]

theorem replay_chain_prefix (table : Memo K α) (input : ℕ → N → K)
    (project : α → N) (start steps cut : ℕ) (current endpoint : N)
    (bound : cut ≤ steps)
    (recorded : replayProgram table
      (chainProgram input project start steps current) = some endpoint) :
    ∃ middle, replayProgram table (chainProgram input project start cut current) = some middle ∧
      replayProgram table (chainProgram input project (start + cut) (steps - cut) middle) =
        some endpoint := by
  rw [show steps = cut + (steps - cut) by omega, replay_chain_split] at recorded
  cases h : replayProgram table (chainProgram input project start cut current) with
  | none => simp only [h, Option.bind_none] at recorded; cases recorded
  | some middle =>
    simp only [h, Option.bind_some] at recorded
    exact ⟨middle, rfl, recorded⟩

theorem replay_chain_start_eq (table : Memo K α) (input : ℕ → N → K)
    (project : α → N)
    (binding : ∀ position first second firstReply secondReply,
      table (input position first) = some firstReply →
      table (input position second) = some secondReply →
      project firstReply = project secondReply → first = second)
    (start steps : ℕ) (first second endpoint : N)
    (recorded : replayProgram table (chainProgram input project start steps first) = some endpoint)
    (recorded' : replayProgram table (chainProgram input project start steps second) = some endpoint) :
    first = second := by
  induction steps generalizing start first second with
  | zero =>
    exact (Option.some.inj recorded).trans (Option.some.inj recorded').symm
  | succ steps ih =>
    cases hf : table (input start first) with
    | none => simp only [chainProgram, replayProgram, hf, Option.bind_none] at recorded; cases recorded
    | some firstReply =>
      simp only [chainProgram, replayProgram, hf, Option.bind_some] at recorded
      cases hs : table (input start second) with
      | none => simp only [chainProgram, replayProgram, hs, Option.bind_none] at recorded'; cases recorded'
      | some secondReply =>
        simp only [chainProgram, replayProgram, hs, Option.bind_some] at recorded'
        exact binding start first second firstReply secondReply hf hs
          (ih (start + 1) (project firstReply) (project secondReply) recorded recorded')

end
end C10Probability

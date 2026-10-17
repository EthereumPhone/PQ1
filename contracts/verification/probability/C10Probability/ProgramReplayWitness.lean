import C10Probability.QueryReplay

/-! Completed composed programs retain their intermediate lookup witnesses
in the same cache. No new execution or sampling is introduced. -/
namespace C10Probability
noncomputable section

variable {K α R T : Type*}

theorem replay_program_bind_witness (table : Memo K α) {n m : ℕ}
    (program : QueryProgram K α R n) (after : R → QueryProgram K α T m) (result : T)
    (recorded : replayProgram table (bindProgram program after) = some result) :
    ∃ middle, replayProgram table program = some middle ∧
      replayProgram table (after middle) = some result := by
  rw [replay_program_bind] at recorded
  cases h : replayProgram table program with
  | none => simp only [h, Option.bind_none] at recorded; cases recorded
  | some middle =>
    simp only [h, Option.bind_some] at recorded
    exact ⟨middle, rfl, recorded⟩

theorem replay_program_map_witness (table : Memo K α) {n : ℕ}
    (program : QueryProgram K α R n) (f : R → T) (result : T)
    (recorded : replayProgram table (mapReturnProgram f program) = some result) :
    ∃ original, replayProgram table program = some original ∧ f original = result := by
  rw [replay_program_map_return] at recorded
  cases h : replayProgram table program with
  | none => simp only [h, Option.map_none] at recorded; cases recorded
  | some original =>
    simp only [h, Option.map_some, Option.some.injEq] at recorded
    exact ⟨original, rfl, recorded⟩

end
end C10Probability

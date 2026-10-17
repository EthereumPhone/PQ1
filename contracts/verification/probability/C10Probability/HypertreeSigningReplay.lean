import C10Probability.LayerSigningReplay
import C10Probability.HypertreeSign

/-! Successful hypertree signing retains the actual ordered layer calls and
their intermediate reconstructed nodes, without a correctness premise. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem replay_hypertree_sign_step (encode : WotsQuery → K) (table : Memo K Digest)
    (seed shuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32) (steps layer index : ℕ)
    (current top : Randomizer) (initial signatures : List LayerSignature)
    (recorded : replayProgram table (hypertreeSignProgram encode seed shuffle n bound
      (steps + 1) layer index current initial) = some (some (signatures, top))) :
    ∃ sig middle,
      replayProgram table (layerSignProgram encode seed layer (hypertreeParent index)
        (hypertreeLeaf index) current shuffle n bound) = some (some (sig, middle)) ∧
      replayProgram table (hypertreeSignProgram encode seed shuffle n bound steps
        (layer + 1) (hypertreeParent index) middle (initial ++ [sig])) = some (some (signatures, top)) := by
  rw [hypertreeSignProgram, replay_program_cast] at recorded
  obtain ⟨signed, hs, rest⟩ := replay_program_bind_witness table _ _ _ recorded
  cases signed with
  | none => cases rest
  | some signed => exact ⟨signed.1, signed.2, hs, rest⟩

theorem replay_hypertree_sign_two (encode : WotsQuery → K) (table : Memo K Digest)
    (seed shuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32) (index : ℕ)
    (current top : Randomizer) (signatures : List LayerSignature)
    (recorded : replayProgram table (hypertreeSignProgram encode seed shuffle n bound
      2 0 index current []) = some (some (signatures, top))) :
    ∃ lower upper middle, signatures = [lower, upper] ∧
      replayProgram table (layerSignProgram encode seed 0 (hypertreeParent index)
        (hypertreeLeaf index) current shuffle n bound) = some (some (lower, middle)) ∧
      replayProgram table (layerSignProgram encode seed 1 (hypertreeParent (hypertreeParent index))
        (hypertreeLeaf (hypertreeParent index)) middle shuffle n bound) = some (some (upper, top)) := by
  obtain ⟨lower, middle, hl, rest⟩ := replay_hypertree_sign_step encode table seed shuffle n bound
    1 0 index current top [] signatures recorded
  obtain ⟨upper, last, hu, done⟩ := replay_hypertree_sign_step encode table seed shuffle n bound
    0 1 (hypertreeParent index) middle top [lower] signatures rest
  simp only [hypertreeSignProgram, replayProgram, Option.some.injEq, Prod.mk.injEq,
    List.cons_append, List.nil_append] at done
  exact ⟨lower, upper, middle, done.1.symm, hl, done.2 ▸ hu⟩

end
end C10Probability

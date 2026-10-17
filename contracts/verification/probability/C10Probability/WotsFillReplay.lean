import C10Probability.QueryReplay
import C10Probability.WotsLeaf

/-! Positional chain witnesses come from the actual private-seeded fill.
Repeated indices are permitted: replay uses one fixed cache and a repeated
write has the same chain result. Untouched positions retain their old value. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem replay_wots_fill_positions (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (steps : Fin 43 → ℕ)
    (order : List (Fin 43)) (initial result : WotsSigma)
    (recorded : replayProgram table
      (wotsFillProgram encode seed layer tree kp steps order initial) = some result) :
    (∀ i ∈ order, replayProgram table
      (wotsSeedChainProgram encode seed layer tree kp i.val (steps i)) = some (result i)) ∧
      (∀ i, i ∉ order → result i = initial i) := by
  induction order generalizing initial result with
  | nil =>
    have equal : initial = result := Option.some.inj recorded
    subst result
    exact ⟨by simp, by simp⟩
  | cons index rest ih =>
    simp only [wotsFillProgram, stateFoldProgram, replay_program_cast, replay_program_bind,
      wotsFillStep, replay_program_map_return] at recorded
    cases head : replayProgram table
      (wotsSeedChainProgram encode seed layer tree kp index.val (steps index)) with
    | none => simp only [head, Option.map_none, Option.bind_none] at recorded; cases recorded
    | some value =>
      simp only [head, Option.map_some, Option.bind_some] at recorded
      obtain ⟨visited, unchanged⟩ := ih (Function.update initial index value) result recorded
      constructor
      · intro i member
        by_cases later : i ∈ rest
        · exact visited i later
        · have equal : i = index := (List.mem_cons.mp member).resolve_right later
          subst i
          have stored := unchanged index later
          simp only [Function.update_self] at stored
          exact stored.symm ▸ head
      · intro i absent
        have different : i ≠ index := by
          intro equal
          exact absent (List.mem_cons.mpr (Or.inl equal))
        have later : i ∉ rest := fun member => absent (List.mem_cons.mpr (Or.inr member))
        have stored := unchanged i later
        simpa only [Function.update_of_ne different] using stored

theorem replay_wots_leaf_fill_positions (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (result : WotsSigma)
    (recorded : replayProgram table (wotsLeafFillProgram encode seed layer tree kp) = some result) :
    ∀ i, replayProgram table (wotsSeedChainProgram encode seed layer tree kp i.val 7) =
      some (result i) := by
  rw [wotsLeafFillProgram, replay_program_cast] at recorded
  have positions := (replay_wots_fill_positions encode table seed layer tree kp
    (fun _ => 7) wotsIndices wotsZeroSigma result recorded).1
  intro i
  exact positions i (by simp only [wotsIndices, List.mem_ofFn]; exact ⟨i, rfl⟩)

theorem replay_wots_leaf_witness (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (leaf : Randomizer)
    (recorded : replayProgram table (wotsLeafProgram encode seed layer tree kp) = some leaf) :
    ∃ (endpoints : WotsSigma) (digest : Digest),
      (∀ i, replayProgram table (wotsSeedChainProgram encode seed layer tree kp i.val 7) =
        some (endpoints i)) ∧
      table (encode (.inl (wotsPkInput seed layer tree kp (List.ofFn endpoints)))) = some digest ∧
      randomizerOfDigest digest = leaf := by
  rw [wotsLeafProgram, replay_program_bind] at recorded
  cases filled : replayProgram table (wotsLeafFillProgram encode seed layer tree kp) with
  | none => simp only [filled, Option.bind_none] at recorded; cases recorded
  | some endpoints =>
    simp only [filled, Option.bind_some] at recorded
    cases compressed : table (encode (.inl (wotsPkInput seed layer tree kp (List.ofFn endpoints)))) with
    | none => simp only [replayProgram, compressed, Option.bind_none] at recorded; cases recorded
    | some digest =>
      simp only [replayProgram, compressed, Option.bind_some, Option.some.injEq] at recorded
      exact ⟨endpoints, digest,
        replay_wots_leaf_fill_positions encode table seed layer tree kp endpoints filled,
        compressed, recorded⟩

end
end C10Probability

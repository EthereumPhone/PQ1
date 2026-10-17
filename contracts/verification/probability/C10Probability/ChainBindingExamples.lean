import C10Probability.WotsChainBinding
import C10Probability.WotsFillReplay

/-! Finite lookup executions exercise reverse-chain premises. They do not
assert a success probability for an initially empty random-oracle cache. -/
namespace C10Probability
noncomputable section

def bindingChainTable (key : ℕ × ℕ) : Option ℕ :=
  if key = (0, 1) then some 3 else if key = (1, 3) then some 5
  else if key = (2, 5) then some 7 else none

theorem binding_chain_table_collision_free : CollisionFree id bindingChainTable := by
  intro key other first second hf hs same
  simp only [bindingChainTable] at hf hs
  split_ifs at hf hs <;> simp_all <;> omega

theorem binding_chain_full_replay :
    replayProgram bindingChainTable (chainProgram Prod.mk id 0 3 1) = some 7 := by
  rfl

theorem binding_chain_prefix_suffix :
    replayProgram bindingChainTable (chainProgram Prod.mk id 0 1 1) = some 3 ∧
      replayProgram bindingChainTable (chainProgram Prod.mk id 1 2 3) = some 7 := by
  exact ⟨rfl, rfl⟩

theorem binding_chain_same_coordinate (first second : ℕ)
    (hf : replayProgram bindingChainTable (chainProgram Prod.mk id 0 3 first) = some 7)
    (hs : replayProgram bindingChainTable (chainProgram Prod.mk id 0 3 second) = some 7) :
    first = second := by
  apply replay_chain_start_eq bindingChainTable Prod.mk id _ 0 3 first second 7 hf hs
  intro position left right firstReply secondReply hl hr equal
  exact congrArg Prod.snd (binding_chain_table_collision_free (position, left) (position, right)
    firstReply secondReply hl hr equal)

theorem binding_chain_coordinate_is_necessary :
    replayProgram bindingChainTable (chainProgram (fun position value => (0, position + value))
      id 0 1 1) = some 3 ∧
      replayProgram bindingChainTable (chainProgram (fun position value => (0, position + value))
        id 1 1 0) = some 3 ∧ (1 : ℕ) ≠ 0 := by
  exact ⟨rfl, rfl, by decide⟩

theorem binding_chain_length_is_necessary :
    replayProgram bindingChainTable (chainProgram Prod.mk id 0 0 7) = some 7 ∧
      replayProgram bindingChainTable (chainProgram Prod.mk id 0 3 1) = some 7 ∧ (7 : ℕ) ≠ 1 := by
  exact ⟨rfl, rfl, by decide⟩

theorem binding_chain_missing_cache_rejected :
    replayProgram (fun _ : ℕ × ℕ => (none : Option ℕ)) (chainProgram Prod.mk id 0 3 1) = none := by
  rfl

theorem binding_chain_collision_allows_distinct_starts :
    replayProgram (fun _ : ℕ × ℕ => some (7 : ℕ)) (chainProgram Prod.mk id 0 1 1) = some 7 ∧
      replayProgram (fun _ : ℕ × ℕ => some (7 : ℕ)) (chainProgram Prod.mk id 0 1 2) = some 7 ∧
      ¬ CollisionFree id (fun _ : ℕ × ℕ => some (7 : ℕ)) := by
  refine ⟨rfl, rfl, ?_⟩
  intro free
  have equal := congrArg Prod.snd (free (0, 1) (0, 2) 7 7 rfl rfl rfl)
  omega

theorem binding_wots_chain_node_changes_input :
    wotsChainInput (List.replicate 32 0) 1 0 2 3 4 1 ≠
      wotsChainInput (List.replicate 32 0) 1 0 2 3 4 2 := by
  intro equal
  have same := wots_chain_input_injective _ _ _ _ _ _ equal
  exact (by decide : (1 : Randomizer) ≠ 2) same

theorem binding_compression_order_matters :
    wotsPkInput (List.replicate 32 0) 1 0 2 [1, 2] ≠
      wotsPkInput (List.replicate 32 0) 1 0 2 [2, 1] := by
  intro equal
  exact (by decide : ([1, 2] : List Randomizer) ≠ [2, 1])
    (wots_pk_input_injective _ _ _ _ equal)

theorem binding_compression_length_matters :
    wotsPkInput (List.replicate 32 0) 1 0 2 [1] ≠
      wotsPkInput (List.replicate 32 0) 1 0 2 [1, 0] := by
  intro equal
  exact (by decide : ([1] : List Randomizer) ≠ [1, 0])
    (wots_pk_input_injective _ _ _ _ equal)

theorem binding_wots_address_truncation :
    wotsChainInput (List.replicate 32 0) 1 0 2 0 4 1 =
      wotsChainInput (List.replicate 32 0) 1 0 2 (2 ^ 32) 4 1 := by
  set_option maxRecDepth 4096 in decide +kernel

end
end C10Probability

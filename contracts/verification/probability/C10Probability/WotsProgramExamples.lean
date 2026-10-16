import C10Probability.WotsProgram
import C10Probability.WotsChain

/-! Small independent executions and kernel-evaluated byte boundaries. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem count_empty_retains (table : Memo Bool Bool) :
    evalProgram fairReply (countProgram id 9 ([] : List Bool)) table =
      PMF.pure (none, table) := by rfl

theorem count_early_cache :
    evalProgram (PMF.pure true) (countProgram id 3 [false, true]) (fun _ => none) =
      PMF.pure (some (3, true), Function.update (fun _ => none) false (some true)) := by
  simp [countProgram, evalProgram, memoQuery, PMF.pure_map, PMF.pure_bind]

theorem count_cached_advances :
    evalProgram fairReply (countProgram id 7 [false, true]) (fun key => some key) =
      PMF.pure (some (8, true), fun key => some key) := by
  simp [countProgram, evalProgram, memoQuery, PMF.pure_bind]

theorem count_cached_exhausts :
    evalProgram fairReply (countProgram id 7 [false, true]) (fun _ => some false) =
      PMF.pure (none, fun _ => some false) := by
  simp [countProgram, evalProgram, memoQuery, PMF.pure_bind]

theorem count_repeat_failure :
    ((evalProgram fairReply (countProgram id 0 [false, false])
      (fun _ => none)).map Prod.fst) none = (2 : ℝ≥0∞)⁻¹ := by
  rw [evalProgram_count, memo_repeat_two_failure]

theorem count_two_fresh_failure :
    ((evalProgram fairReply (countProgram id 0 [false, true])
      (fun _ => none)).map Prod.fst) none = (4 : ℝ≥0∞)⁻¹ := by
  have distribution :
      (evalProgram fairReply (countProgram id 0 [false, true]) (fun _ => none)).map Prod.fst =
        fairReply.bind (fun first => if first then PMF.pure (some (0, true)) else
          fairReply.map (fun second => if second then some (1, true) else none)) := by
    simp only [countProgram, evalProgram, memoQuery, PMF.map_bind, PMF.bind_map,
      Function.comp_def]
    congr 1
    funext first
    cases first <;> simp [evalProgram, memoQuery, PMF.map_bind, PMF.bind_map,
      PMF.pure_map, Function.comp_def]
    conv_rhs => rw [PMF.map]
    congr 1
    funext second
    cases second <;> simp [evalProgram, PMF.pure_map]
  rw [distribution]
  simp [PMF.bind_apply, fairReply, tsum_fintype]
  apply (ENNReal.toReal_eq_toReal_iff' (by finiteness) (by finiteness)).mp
  norm_num [ENNReal.toReal_mul]


theorem count_selected_early_allowance :
    SelectedBudget id (countProgram id 0 [false, true]) 1 := by
  simp [countProgram, SelectedBudget]

theorem count_selected_zero_rejected :
    ¬ SelectedBudget id (countProgram id 0 [true, false]) 0 := by
  simp [countProgram, SelectedBudget]

theorem count_excluded_zero_allowance :
    SelectedBudget id (countProgram id 0 [false, false]) 0 := by
  simp [countProgram, SelectedBudget]

theorem chain_zero_preserves (table : Memo Bool Bool) :
    evalProgram fairReply (chainProgram (fun _ (value : Bool) => value) not 5 0 true) table =
      PMF.pure (true, table) := by rfl

theorem chain_projection_used :
    evalProgram (PMF.pure true)
      (chainProgram (fun _ (value : Bool) => value) not 5 1 true) (fun _ => none) =
      PMF.pure (false, Function.update (fun _ => none) true (some true)) := by
  simp [chainProgram, evalProgram, memoQuery, PMF.pure_map, PMF.pure_bind]

theorem chain_cached_replies :
    evalProgram fairReply (chainProgram (fun _ (value : Bool) => value) id 0 2 false)
      (fun _ => some true) = PMF.pure (true, fun _ => some true) := by
  simp [chainProgram, evalProgram, memoQuery, PMF.pure_bind]

theorem chain_positions_advance :
    evalProgram (PMF.pure true)
      (chainProgram (fun pos (_ : Bool) => decide (pos = 5)) id 5 2 false) (fun _ => none) =
      PMF.pure (true, Function.update (Function.update (fun _ => none) true (some true))
        false (some true)) := by
  simp [chainProgram, evalProgram, memoQuery, PMF.pure_map, PMF.pure_bind]

theorem chain_adaptive_mass :
    ((evalProgram fairReply (chainProgram (fun _ (value : Bool) => value) id 0 2 false)
      (fun _ => none)).map Prod.fst) true = (4 : ℝ≥0∞)⁻¹ := by
  simp only [chainProgram, evalProgram, memoQuery, PMF.map_bind, PMF.bind_map,
    PMF.pure_map, Function.comp_def]
  rw [PMF.bind_apply, tsum_fintype, Fintype.sum_bool]
  simp [PMF.bind_map, Function.comp_def, fairReply]
  apply (ENNReal.toReal_eq_toReal_iff' (by finiteness) (by finiteness)).mp
  norm_num [ENNReal.toReal_mul]

theorem chain_selected_both_branches :
    SelectedBudget (fun _ : Bool => true)
      (chainProgram (fun _ (value : Bool) => value) id 0 2 false) 2 := by
  simp [chainProgram, SelectedBudget]

theorem chain_selected_missing_call :
    ¬ SelectedBudget (fun _ : Bool => true)
      (chainProgram (fun _ (value : Bool) => value) id 0 2 false) 1 := by
  simp [chainProgram, SelectedBudget]

theorem address_field_endianness :
    c10Address 0x01020304 0x1112131415161718 0x21222324 0x31323334
      0x41424344 0x51525354 0x61626364 =
      [1,2,3,4,17,18,19,20,21,22,23,24,33,34,35,36,49,50,51,52,
       65,66,67,68,81,82,83,84,97,98,99,100] := by decide +kernel

theorem address_zero_width : beBytes 0 1000 = [] := by decide +kernel

theorem address_word_wrap : beBytes 4 (2 ^ 32 + 1) = [0,0,0,1] := by decide +kernel

theorem address_tree_high_byte :
    ((c10Address 0 (2 ^ 56) 0 0 0 0 0).drop 4).take 8 = [1,0,0,0,0,0,0,0] := by
  decide +kernel

theorem address_position_field :
    ((c10Address 0 0 0 0 0 7 0).drop 24).take 4 = [0,0,0,7] := by decide +kernel

theorem wots_count_message_padding :
    ((counterKey (wotsCountStem (List.replicate 32 0) 0 0 0
      (List.replicate 16 1)) 0).drop 64).take 32 =
      List.replicate 16 1 ++ List.replicate 16 0 := by
  set_option maxRecDepth 4096 in
    decide +kernel

theorem wots_count_nonce_tail :
    (counterKey (wotsCountStem (List.replicate 32 0) 0 0 0
      (List.replicate 16 0)) 257).drop 124 = [0,0,1,1] := by
  set_option maxRecDepth 4096 in
    decide +kernel

theorem wots_chain_node_and_padding :
    (wotsChainInput (List.replicate 32 0) 0 0 0 0 0 1).drop 64 =
      List.replicate 15 0 ++ [1] ++ List.replicate 16 0 := by
  set_option maxRecDepth 4096 in
    decide +kernel

theorem wots_chain_address_offsets :
    ((wotsChainInput (List.replicate 32 0) 0 0 0 3 6 0).drop 52).take 12 =
      [0,0,0,3,0,0,0,6,0,0,0,0] := by
  set_option maxRecDepth 4096 in
    decide +kernel

theorem wots_count_valid_excluded :
    nodeQuery (counterKey (wotsCountStem (List.replicate 32 0) 1 2 3
      (List.replicate 16 0)) 17) = false := by
  set_option maxRecDepth 4096 in
    decide +kernel

theorem wots_chain_valid_selected :
    nodeQuery (wotsChainInput (List.replicate 32 0) 1 2 3 4 5 0) = true := by
  set_option maxRecDepth 4096 in
    decide +kernel

end
end C10Probability

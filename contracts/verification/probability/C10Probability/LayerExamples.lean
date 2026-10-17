import C10Probability.LayerCharges
import C10Probability.MerkleExamples

/-! Independent byte/coordinate witnesses and cached rejection/reconstruction
executions. These examples do not assert fresh sampling from a populated table. -/
namespace C10Probability
noncomputable section
set_option maxRecDepth 4096

theorem layer_zero_label_vector :
    layerShuffleLabel 0 = [119,111,116,115,45,48,0] := by decide +kernel

theorem layer_one_label_vector :
    layerShuffleLabel 1 = [119,111,116,115,45,49,0] := by decide +kernel

theorem layer_other_label_vector :
    layerShuffleLabel 2 = [119,111,116,115,45,49,0] := by decide +kernel

theorem layer_subseed_full_input :
    shuffleDeriveInput (List.replicate 32 9) (layerShuffleLabel 0) =
      [115,112,104,105,110,99,115,45,99,49,48,45,115,104,117,102,102,108,101,45,118,49] ++
        List.replicate 32 9 ++ [119,111,116,115,45,48,0] := by decide +kernel

theorem hypertree_low_bit_boundary : hypertreeIndex (2 ^ 142) = 0 := by decide +kernel

theorem hypertree_first_bit : hypertreeIndex (2 ^ 143) = 1 := by decide +kernel

theorem hypertree_last_bit : hypertreeIndex (2 ^ 160) = 131072 := by decide +kernel

theorem hypertree_high_bit_boundary : hypertreeIndex (2 ^ 161) = 0 := by decide +kernel

theorem hypertree_two_coordinates_vector :
    let ht := hypertreeIndex (513 * 2 ^ 143)
    (hypertreeLeaf ht, hypertreeParent ht,
      hypertreeLeaf (hypertreeParent ht), hypertreeParent (hypertreeParent ht)) = (1,1,1,0) := by
  decide +kernel

theorem hypertree_last_coordinate_vector :
    let ht := hypertreeIndex (262143 * 2 ^ 143)
    (hypertreeLeaf ht, hypertreeParent ht,
      hypertreeLeaf (hypertreeParent ht), hypertreeParent (hypertreeParent ht)) = (511,511,511,0) := by
  decide +kernel

theorem layer_count_full_block_vector :
    wotsRecoverCountInput [] 0 0 0 [] 16909060 = List.replicate 76 0 ++ [1,2,3,4] := by
  decide +kernel

theorem layer_count_last_u32_vector :
    (wotsRecoverCountInput [] 0 0 0 [] 4294967295).drop 76 = [255,255,255,255] := by
  decide +kernel

theorem layer_natural_count_not_u32_wrapped :
    (wotsRecoverCountInput [] 0 0 0 [] 4294967297).drop 75 = [1,0,0,0,1] := by
  decide +kernel

theorem layer_message_byte_vector :
    nodeValueBytes (2 ^ 120 + 2) = [1] ++ List.replicate 14 0 ++ [2] := by decide +kernel

theorem layer_recovery_reject_then_path {K : Type*} [DecidableEq K]
    (encode : ByteKey → K) (seed : ByteKey) (layer tree leaf : ℕ)
    (message : Randomizer) (sig : LayerSignature) :
    layerRecover encode (fun _ => some (2 ^ 128)) seed layer tree leaf message sig =
      PMF.pure (1, fun _ => some (2 ^ 128)) := by
  rw [layerRecover, wots_recovery_under_rejected_cached encode _ seed layer tree leaf
    (nodeValueBytes message) sig.sigma sig.count (2 ^ 128) (by rfl) (by decide +kernel),
    PMF.pure_bind, merkle_recover_cached]
  rfl

theorem layer_after_returned_reconstruction :
    layerSignAfter id (fun _ => some (2 ^ 128)) [] 1 2 3 4 [5,6]
      (some (fun _ => 7, 8)) =
      PMF.pure (some (⟨fun _ => 7, 8, [5,6]⟩, 1), fun _ => some (2 ^ 128)) := by
  rw [layerSignAfter, layer_recovery_reject_then_path, PMF.pure_map]

theorem layer_recovery_rejected_query_order :
    (traceProgram digestDraw
      (layerRecoverProgram id [] 1 2 0 17 ⟨fun _ => 42, 7, [2,3,4,5,6,7,8,9,10]⟩)
      (fun _ => some (2 ^ 128))).map (fun out => out.queries) =
      PMF.pure [wotsRecoverCountInput [] 1 2 0 (nodeValueBytes 17) 7,
        merklePairInput [] 1 2 0 0 0 2,
        merklePairInput [] 1 2 1 0 1 3,
        merklePairInput [] 1 2 2 0 1 4,
        merklePairInput [] 1 2 3 0 1 5,
        merklePairInput [] 1 2 4 0 1 6,
        merklePairInput [] 1 2 5 0 1 7,
        merklePairInput [] 1 2 6 0 1 8,
        merklePairInput [] 1 2 7 0 1 9,
        merklePairInput [] 1 2 8 0 1 10] := by
  have reject : wotsAccept (wotsOfDigest (2 ^ 128)) = false := by decide +kernel
  have project : randomizerOfDigest (2 ^ 128) = 1 := by decide +kernel
  simp [layerRecoverProgram, wotsRecoveryUnderProgram, wotsRecoveryAfter, reject,
    bindProgram, mapProgram, castProgram, reserveProgram, merkleRecoverProgram,
    recoveryProgram, recoveryInput, traceProgram, memoQuery, PMF.pure_bind,
    PMF.pure_map, project]

end
end C10Probability

import C10Probability.WotsRecovery

/-! Finite shared-cache executions and independent byte/arithmetic witnesses.
The cached complete recovery example does not assume fresh oracle draws. -/
namespace C10Probability
noncomputable section

theorem collection_step_sum :
    collectionSteps (fun i : Bool => if i then 3 else 2) [false, true, false] = 7 := by rfl

theorem collection_zero_order :
    chainCollectionLoop fairReply (fun i _ (_ : Bool) => i) id (fun _ => 0)
      (fun _ => 0) id [true, false, false] (fun _ => none) =
      PMF.pure ([true, false, false], fun _ => none) := by
  simp [chainCollectionLoop, chainLoop, PMF.pure_bind, PMF.pure_map]

theorem collection_cached_order :
    chainCollectionLoop fairReply (fun i _ (_ : Bool) => i) id (fun _ => 2)
      (fun _ => 1) (fun _ => false) [false, true] (fun key => some key) =
      PMF.pure ([false, true], fun key => some key) := by
  simp [chainCollectionLoop, chainLoop, memoQuery, PMF.pure_bind, PMF.pure_map]

theorem collection_accumulates_cache :
    chainCollectionLoop (PMF.pure true) (fun i _ (_ : Bool) => i) not (fun _ => 0)
      (fun _ => 1) (fun _ => true) [false, true] (fun _ => none) =
      PMF.pure ([false, false], Function.update
        (Function.update (fun _ => none) false (some true)) true (some true)) := by
  simp [chainCollectionLoop, chainLoop, memoQuery, PMF.pure_bind, PMF.pure_map]

theorem collection_program_zero_order :
    evalProgram fairReply
      (chainCollectionProgram (fun i _ (_ : Bool) => i) id (fun _ => 0)
        (fun _ => 0) id [true, false, false]) (fun _ => none) =
      PMF.pure ([true, false, false], fun _ => none) := by
  simp [chainCollectionProgram, evalProgram_cast, evalProgram_bind, evalProgram_chain,
    evalProgram_mapReturn, chainLoop, evalProgram, PMF.pure_bind, PMF.pure_map]

theorem wots_index_order :
    wotsIndices.map Fin.val = List.range 43 := by decide +kernel

theorem wots_remaining_max_word : wotsRemaining (fun _ => 7) = 0 := by decide +kernel

theorem wots_remaining_zero_word : wotsRemaining (fun _ => 0) = 301 := by decide +kernel

theorem wots_remaining_accepted_word : wotsRemaining acceptedWotsWitness = 96 := by
  decide +kernel

theorem compression_node_bytes : nodeBlock 257 =
    List.replicate 14 0 ++ [1,1] ++ List.replicate 16 0 := by
  set_option maxRecDepth 4096 in
    decide +kernel

theorem compression_kind_bytes :
    ((wotsPkInput (List.replicate 32 0) 2 3 4 [1, 2]).drop 44).take 20 =
      [0,0,0,1,0,0,0,4,0,0,0,0,0,0,0,0,0,0,0,0] := by
  set_option maxRecDepth 4096 in
    decide +kernel

theorem compression_element_order :
    (wotsPkInput (List.replicate 32 0) 2 3 4 [1, 2]).drop 64 =
      (List.replicate 15 0 ++ [1] ++ List.replicate 16 0) ++
      (List.replicate 15 0 ++ [2] ++ List.replicate 16 0) := by
  set_option maxRecDepth 4096 in
    decide +kernel

theorem compression_result_cache :
    wotsCompress (fun _ => some (2 ^ 128)) [] 1 2 3 [4] =
      PMF.pure (1, fun _ => some (2 ^ 128)) := by
  set_option maxRecDepth 4096 in
    simp only [wotsCompress, memoQuery, PMF.pure_map]
    have projected : randomizerOfDigest (2 ^ 128 : Digest) = 1 := by decide +kernel
    rw [projected]

def recoveryAcceptedDigest : Digest := 2 ^ 200 + 3 * 8 ^ 29 - 1

theorem recovery_digest_accepted :
    wotsAccept (wotsOfDigest recoveryAcceptedDigest) = true := by decide +kernel

theorem recovery_digest_node : randomizerOfDigest recoveryAcceptedDigest = 2 ^ 72 := by
  decide +kernel

theorem recovery_digest_rejected : wotsAccept (wotsOfDigest (2 ^ 128)) = false := by
  decide +kernel

theorem recovery_invalid_retains_cache :
    wotsRecovery (fun _ => some (2 ^ 128)) (List.replicate 32 0) 1 2 3
      (List.replicate 16 0) (fun _ => 5) 17 = PMF.pure (0, fun _ => some (2 ^ 128)) := by
  set_option maxRecDepth 4096 in
    simp only [wotsRecovery, memoQuery, PMF.pure_bind]
    have rejected : wotsAccept (wotsOfDigest (2 ^ 128)) = false := by decide +kernel
    simp only [rejected, Bool.false_eq_true, ↓reduceIte]

theorem recovery_after_rejected (seed : ByteKey) (layer tree kp : ℕ)
    (sigma : Fin 43 → Randomizer) :
    wotsRecoveryAfter seed layer tree kp sigma (2 ^ 128) = .done 0 := by
  rw [wotsRecoveryAfter]
  have rejected : wotsAccept (wotsOfDigest (2 ^ 128)) = false := by decide +kernel
  simp only [rejected, Bool.false_eq_true, ↓reduceDIte]

theorem recovery_complete_cached (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (nonce : Counter) :
    wotsRecovery (fun _ => some recoveryAcceptedDigest) seed layer tree kp message
      (fun _ => randomizerOfDigest recoveryAcceptedDigest) nonce =
      PMF.pure (randomizerOfDigest recoveryAcceptedDigest, fun _ => some recoveryAcceptedDigest) := by
  set_option maxRecDepth 4096 in
    rw [wots_recovery_accepted_cached _ _ _ _ _ _ _ _ recoveryAcceptedDigest rfl
      recovery_digest_accepted]
    rw [wotsRecoverChains, chainCollectionLoop_constant_cached, PMF.pure_bind]
    exact wots_compress_cached _ _ _ _ _ _ recoveryAcceptedDigest rfl

theorem recovery_charge_arithmetic : Nat.choose 97 2 + 98 = 4754 := by decide +kernel

end
end C10Probability

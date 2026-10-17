import C10Probability.C10Cached
import C10Probability.C10Flow
import C10Probability.C10Charges
import C10Probability.LayerExamples

/-! Independent whole-client field, root-padding, rejection and query-order
witnesses. Constant populated tables deliberately permit inconsistent nodes;
their successful executions are not a probability or correctness claim. -/
namespace C10Probability
noncomputable section
set_option maxRecDepth 4096

theorem c10_finish_output_fields :
    (c10FinishOutput 7 ⟨[2,3], [[4,5]], 9⟩
      (some ([⟨fun _ => 11, 12, [13]⟩, ⟨fun _ => 21, 22, [23]⟩], 99))).map
        (fun sig => (sig.randomizer, sig.secrets, sig.auths,
          sig.layers.map (fun layer => (layer.sigma 0, layer.count, layer.auth)))) =
        some (7, [2,3], [[4,5]], [(11,12,[13]), (21,22,[23])]) := by rfl

theorem c10_keygen_seed_high_half :
    nodeBlock (randomizerOfDigest (2 ^ 248 + 7)) = [1] ++ List.replicate 31 0 := by
  decide +kernel

theorem c10_keygen_cached_vector :
    c10Keygen id (fun _ => some (2 ^ 128 + 123)) (2 ^ 248 + 7) =
      PMF.pure (([1] ++ List.replicate 31 0,
        List.replicate 15 0 ++ [1] ++ List.replicate 16 0), fun _ => some (2 ^ 128 + 123)) := by
  rw [c10_keygen_full_cache, c10_keygen_seed_high_half]
  have hr : nodeBlock (randomizerOfDigest (2 ^ 128 + 123)) =
      List.replicate 15 0 ++ [1] ++ List.replicate 16 0 := by decide +kernel
  rw [hr]

theorem c10_verify_cached_success (seed message : ByteKey) (sig : C10Signature) :
    c10Verify id (fun _ => some (2 ^ 128)) seed
      (List.replicate 15 0 ++ [1] ++ List.replicate 16 0) message sig =
        PMF.pure (true, fun _ => some (2 ^ 128)) := by
  rw [c10_verify_full_cache]
  have hb : (forsAccept (forsOfDigest (2 ^ 128)) &&
      decide (nodeBlock (randomizerOfDigest (2 ^ 128)) =
        List.replicate 15 0 ++ [1] ++ List.replicate 16 0)) = true := by decide +kernel
  rw [hb]

theorem c10_verify_padding_mismatch (seed message : ByteKey) (sig : C10Signature) :
    c10Verify id (fun _ => some (2 ^ 128)) seed
      (List.replicate 15 0 ++ [1] ++ List.replicate 15 0 ++ [1]) message sig =
        PMF.pure (false, fun _ => some (2 ^ 128)) := by
  rw [c10_verify_full_cache]
  have hb : (forsAccept (forsOfDigest (2 ^ 128)) &&
      decide (nodeBlock (randomizerOfDigest (2 ^ 128)) =
        List.replicate 15 0 ++ [1] ++ List.replicate 15 0 ++ [1])) = false := by decide +kernel
  rw [hb]

theorem c10_verify_forced_zero_reject (seed root message : ByteKey) (sig : C10Signature) :
    c10Verify id (fun _ => some (2 ^ 132)) seed root message sig =
      PMF.pure (false, fun _ => some (2 ^ 132)) := by
  rw [c10_verify_full_cache]
  have hb : forsAccept (forsOfDigest (2 ^ 132)) = false := by decide +kernel
  rw [hb, Bool.false_and]

theorem c10_verify_reject_only_hmsg (seed root message : ByteKey) (sig : C10Signature) :
    (traceProgram digestDraw (c10VerifyProgram id seed root message sig)
      (fun _ => some (2 ^ 132))).map (fun out => out.queries) =
        PMF.pure [hmsgRandomizerInput seed root message sig.randomizer] := by
  have hb : forsAccept (forsOfDigest (2 ^ 132)) = false := by decide +kernel
  simp only [c10VerifyProgram, traceProgram, memoQuery, PMF.pure_bind,
    c10VerifyAfterProgram, hb, Bool.false_eq_true, ↓reduceIte, PMF.pure_map, id_eq]

theorem c10_verify_missing_layer_defaults :
    c10Verify id (fun _ => some (2 ^ 128)) [] (nodeBlock 1) [] ⟨9,[],[],[]⟩ =
      PMF.pure (true, fun _ => some (2 ^ 128)) := by
  exact c10_verify_cached_success [] [] _

theorem c10_sign_r_cached_reject (random message seed root shuffle : ByteKey)
    (n : ℕ) (hn : n ≤ 2 ^ 32) :
    c10Sign id (fun _ => some (2 ^ 132)) random message seed root shuffle
      1 n (by decide) hn = PMF.pure (none, fun _ => some (2 ^ 132)) := by
  have hb : forsAccept (forsOfDigest (2 ^ 132)) = false := by decide +kernel
  simp [c10Sign, randomizerUnder, counterSchedule, derivedMemoGrind, memoQuery,
    PMF.pure_bind, hb, c10SignAfter]

theorem c10_sign_layer_cached_reject (random message seed root shuffle : ByteKey)
    (n : ℕ) (hn : n ≤ 2 ^ 32) :
    c10Sign id (fun _ => some 0) random message seed root shuffle
      1 n (by decide) hn = PMF.pure (none, fun _ => some 0) := by
  have hr : forsAccept (forsOfDigest 0) = true := by decide +kernel
  have hw : wotsAccept (wotsOfDigest 0) = false := by decide +kernel
  have grind : randomizerUnder id (fun _ => some 0) random message seed root 1 (by decide) =
      PMF.pure (some (0,0,0), fun _ => some 0) := by
    simp [randomizerUnder, counterSchedule, derivedMemoGrind, memoQuery, PMF.pure_bind, hr]
    rfl
  rw [c10Sign, grind, PMF.pure_bind, c10SignAfter]
  exact c10_finish_full_cache_reject _ _ _ _ _ _ _ _ hw

theorem randomizer_under_two_query_order :
    (traceProgram digestDraw (randomizerUnderProgram id [1] [2] [3] [4] 1 (by decide))
      (fun _ => some 5444517870735015415413993718908291383296)).map (fun out => out.queries) =
        PMF.pure [.inr ([82,95,103,114,105,110,100] ++
          [1,2] ++ List.replicate 32 0), .inl (hmsgRandomizerInput [3] [4] [2] 16)] := by
  have reject : forsAccept (forsOfDigest 5444517870735015415413993718908291383296) = false := by decide +kernel
  have project : randomizerOfDigest 5444517870735015415413993718908291383296 = 16 := by decide +kernel
  rw [randomizerUnderProgram, mapProgram_id]
  change (traceProgram digestDraw
    (derivedProgram Sum.inr randomizerOfDigest (Sum.inl ∘ hmsgRandomizerInput [3] [4] [2])
      (forsAccept ∘ forsOfDigest) 0 [counterKey (rTailStem [1] [2]) ⟨0, by decide⟩])
    (fun _ => some 5444517870735015415413993718908291383296)).map (fun out => out.queries) = _
  simp only [derivedProgram, castProgram, traceProgram, memoQuery, PMF.pure_bind,
    Function.comp_apply]
  rw [reject, project]
  simp only [Bool.false_eq_true, ↓reduceIte, traceProgram, PMF.pure_map]
  rfl

theorem hypertree_two_layer_query_order :
    (traceProgram digestDraw (hypertreeRecoverProgram id []
      [⟨fun _ => 42, 7, [2,3,4,5,6,7,8,9,10]⟩,
       ⟨fun _ => 52, 9, [12,13,14,15,16,17,18,19,20]⟩] 2 0 513 17)
      (fun _ => some (2 ^ 128))).map (fun out => out.queries) = PMF.pure
      [wotsRecoverCountInput [] 0 1 1 (nodeValueBytes 17) 7,
       merklePairInput [] 0 1 0 0 2 0,
       merklePairInput [] 0 1 1 0 1 3,
       merklePairInput [] 0 1 2 0 1 4,
       merklePairInput [] 0 1 3 0 1 5,
       merklePairInput [] 0 1 4 0 1 6,
       merklePairInput [] 0 1 5 0 1 7,
       merklePairInput [] 0 1 6 0 1 8,
       merklePairInput [] 0 1 7 0 1 9,
       merklePairInput [] 0 1 8 0 1 10,
       wotsRecoverCountInput [] 1 0 1 (nodeValueBytes 1) 9,
       merklePairInput [] 1 0 0 0 12 0,
       merklePairInput [] 1 0 1 0 1 13,
       merklePairInput [] 1 0 2 0 1 14,
       merklePairInput [] 1 0 3 0 1 15,
       merklePairInput [] 1 0 4 0 1 16,
       merklePairInput [] 1 0 5 0 1 17,
       merklePairInput [] 1 0 6 0 1 18,
       merklePairInput [] 1 0 7 0 1 19,
       merklePairInput [] 1 0 8 0 1 20] := by
  have reject : wotsAccept (wotsOfDigest (2 ^ 128)) = false := by decide +kernel
  have project : randomizerOfDigest (2 ^ 128) = 1 := by decide +kernel
  simp [hypertreeRecoverProgram, hypertreeParent, hypertreeLeaf,
    layerRecoverProgram, wotsRecoveryUnderProgram, wotsRecoveryAfter, reject,
    bindProgram, mapProgram, castProgram, reserveProgram, merkleRecoverProgram,
    recoveryProgram, recoveryInput, traceProgram, memoQuery, PMF.pure_bind,
    PMF.pure_map, project]

theorem c10_deployed_cost_arithmetic :
    10000000 ≤ 2 ^ 32 ∧
    2 * 10000000 + 2 * 10000000 + 435044 = 40435044 ∧
    10000000 + 2 * 10000000 + 364290 = 30364290 ∧
    10000000 + 435042 = 10435042 ∧
    Nat.choose 358 2 + 361 = 64264 := by decide +kernel

end
end C10Probability

import C10Probability.HonestProbability
import C10Probability.C10Cached
import C10Probability.GrindClientExamples

/-! Asymmetric finite replay vectors plus actual populated-cache whole-signer
witnesses. The latter establish satisfiability, not a lower bound on success
from an empty cache. Wrong supplied roots and overwritten replies expose the
necessary premises of the universal honest-correctness result. -/
namespace C10Probability
noncomputable section
set_option maxRecDepth 4096

def honestChainTable : Memo (ℕ × ℕ × ℕ) ℕ :=
  fun key => some (100 * key.1 + 10 * key.2.1 + key.2.2 + 1)

theorem honest_asymmetric_chain_collection :
    replayProgram honestChainTable (chainCollectionProgram
      (fun i step value => (i, step, value)) id (fun _ => 2) (fun _ => 2)
      (fun i => i + 3) [1, 0, 1, 0]) = some [256, 55, 256, 55] := by decide +kernel

theorem honest_asymmetric_chain_order_matters :
    replayProgram honestChainTable (chainCollectionProgram
      (fun i step value => (i, step, value)) id (fun _ => 2) (fun _ => 2)
      (fun i => i + 3) [0, 1, 1, 0]) ≠ some [256, 55, 256, 55] := by decide +kernel

theorem honest_derived_retry_replay :
    replayProgram (fun key : ℕ => some (decide (key = 0 ∨ key = 3)))
      (derivedProgram id id (fun value => if value then (2 : ℕ) else 3) id 6 [0, 1, 4]) =
      some (some (7, false, true)) := by decide +kernel

theorem honest_derived_retry_keeps_accepted_query :
    ∃ (i : Fin ([0, 1, 4] : List ℕ).length) (first : Bool), 7 = 6 + i.val ∧
      (fun key : ℕ => some (decide (key = 0 ∨ key = 3))) ([0, 1, 4][i.val]) = some first ∧
      false = id first ∧
      (fun key : ℕ => some (decide (key = 0 ∨ key = 3)))
        (if false then (2 : ℕ) else 3) = some true ∧ id true = true := by
  exact replay_derived_success id _ id id (fun value => if value then (2 : ℕ) else 3)
    id 6 [0, 1, 4] 7 false true (by
      simpa only [mapProgram_id] using honest_derived_retry_replay)

def honestForestState : ForestState :=
  ⟨[21,22,23,24,25,26,27,28,29,30,31,32,33], List.replicate 12 (List.replicate 11 4),
    [1,2,3,4,5,6,7,8,9,10,11,12,13]⟩

def honestLastTable : Memo WotsQuery Digest := fun key =>
  if key = .inl (forsLeafInput [] 513 12 0 41) then some (7 * 2 ^ 128)
  else if key = .inl (forsPkInput [] 513 [1,2,3,4,5,6,7,8,9,10,11,12,7]) then some (99 * 2 ^ 128)
  else none

theorem honest_last_slot_replay :
    replayProgram honestLastTable (forestLastProgram id [] 513 honestForestState 41) =
      some ⟨[21,22,23,24,25,26,27,28,29,30,31,32,41], honestForestState.auths, 99⟩ := by
  decide +kernel

theorem honest_last_slot_unhashed_root_absent :
    honestLastTable (.inl (forsPkInput [] 513 [1,2,3,4,5,6,7,8,9,10,11,12,41])) = none := by
  decide +kernel

theorem honest_last_slot_reordered_roots_absent :
    honestLastTable (.inl (forsPkInput [] 513 [2,1,3,4,5,6,7,8,9,10,11,12,7])) = none := by
  decide +kernel

theorem honest_forest_positional_writes :
    forestWrite (forestWrite ⟨[1,2,3], [[4],[5],[6]], [7,8,9]⟩ 2 ⟨31,[61],91⟩)
      0 ⟨11,[41],71⟩ = ⟨[11,2,31], [[41],[5],[61]], [71,8,91]⟩ := by
  decide +kernel

theorem honest_generated_key_success_inhabited :
    ∃ sig, c10Sign id (fun _ => some recoveryAcceptedDigest) [] []
        (nodeBlock 0) (nodeBlock (2 ^ 72)) [] 1 1 (by decide) (by decide) =
          PMF.pure (some sig, fun _ => some recoveryAcceptedDigest) ∧
      c10Verify (Sum.inl : ByteKey → WotsQuery) (fun _ => some recoveryAcceptedDigest)
        (nodeBlock 0) (nodeBlock (2 ^ 72)) [] sig =
          PMF.pure (true, fun _ => some recoveryAcceptedDigest) := by
  obtain ⟨sig, signed⟩ := c10_sign_full_cache_accept id [] [] (nodeBlock 0) (nodeBlock (2 ^ 72)) []
  refine ⟨sig, signed, ?_⟩
  apply c10_honest_verification_support id (fun _ => some recoveryAcceptedDigest) 0
    ((nodeBlock 0, nodeBlock (2 ^ 72)), fun _ => some recoveryAcceptedDigest)
    [] [] [] 1 1 (by decide) (by decide) sig _
  · rw [c10_keygen_full_cache, recovery_digest_node]
    have zero : randomizerOfDigest 0 = 0 := by decide +kernel
    rw [zero]
    simp only [PMF.mem_support_pure_iff]
  · rw [signed]
    simp only [PMF.mem_support_pure_iff]

theorem honest_wrong_supplied_root_can_reject :
    ∃ sig, c10Sign id (fun _ => some recoveryAcceptedDigest) [] []
        (nodeBlock 0) (nodeBlock 0) [] 1 1 (by decide) (by decide) =
          PMF.pure (some sig, fun _ => some recoveryAcceptedDigest) ∧
      c10Verify (Sum.inl : ByteKey → WotsQuery) (fun _ => some recoveryAcceptedDigest)
        (nodeBlock 0) (nodeBlock 0) [] sig =
          PMF.pure (false, fun _ => some recoveryAcceptedDigest) := by
  obtain ⟨sig, signed⟩ := c10_sign_full_cache_accept id [] [] (nodeBlock 0) (nodeBlock 0) []
  refine ⟨sig, signed, ?_⟩
  rw [c10_verify_full_cache]
  have rejected : (forsAccept (forsOfDigest recoveryAcceptedDigest) &&
      decide (nodeBlock (randomizerOfDigest recoveryAcceptedDigest) = nodeBlock 0)) = false := by
    decide +kernel
  rw [rejected]

theorem honest_overwritten_cache_can_reject :
    ∃ sig, c10Sign id (fun _ => some recoveryAcceptedDigest) [] []
        (nodeBlock 0) (nodeBlock (2 ^ 72)) [] 1 1 (by decide) (by decide) =
          PMF.pure (some sig, fun _ => some recoveryAcceptedDigest) ∧
      c10Verify (Sum.inl : ByteKey → WotsQuery) (fun _ => some (2 ^ 132))
        (nodeBlock 0) (nodeBlock (2 ^ 72)) [] sig =
          PMF.pure (false, fun _ => some (2 ^ 132)) ∧
      ¬ MemoExtends (fun _ : WotsQuery => some recoveryAcceptedDigest)
        (fun _ => some (2 ^ 132)) := by
  obtain ⟨sig, signed, _⟩ := honest_generated_key_success_inhabited
  refine ⟨sig, signed, ?_, ?_⟩
  · rw [c10_verify_full_cache]
    have rejected : forsAccept (forsOfDigest (2 ^ 132)) = false := by decide +kernel
    rw [rejected, Bool.false_and]
  · intro extension
    have same := extension (.inl []) recoveryAcceptedDigest rfl
    have different : (2 ^ 132 : Digest) ≠ recoveryAcceptedDigest := by decide +kernel
    exact different (Option.some.inj same)

end
end C10Probability

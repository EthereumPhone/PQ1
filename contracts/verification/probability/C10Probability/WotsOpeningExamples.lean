import C10Probability.ObservedChains
import C10Probability.LayerPrefixComparison
import C10Probability.ObservedExamples

/-! Accepted-word and actual signing witnesses. Populated-cache executions
show satisfiable interfaces, not empty-cache probabilities or secrecy. -/
namespace C10Probability
noncomputable section

set_option maxRecDepth 4096

def swappedAcceptedWord : WotsWord := fun i =>
  if i.val = 28 then 2 else if i.val = 29 then 7 else acceptedWotsWitness i

theorem opening_swapped_word_accepted : wotsAccept swappedAcceptedWord = true := by
  decide +kernel

theorem opening_distinct_words_have_two_cuts :
    acceptedWotsWitness ≠ swappedAcceptedWord ∧
      (acceptedWotsWitness 29).val < (swappedAcceptedWord 29).val ∧
      (swappedAcceptedWord 28).val < (acceptedWotsWitness 28).val := by
  refine ⟨?_, by decide +kernel, by decide +kernel⟩
  intro equal
  have same := congrFun equal 28
  contradiction

theorem opening_max_word_rejected :
    wotsAccept (fun _ => 7) = false ∧ ¬ ∃ _i : Fin 43, (7 : Fin 8).val < 7 := by
  decide +kernel

theorem opening_equal_words_different_digests :
    wotsOfDigest recoveryAcceptedDigest = wotsOfDigest (recoveryAcceptedDigest + 2 ^ 129) ∧
      recoveryAcceptedDigest ≠ recoveryAcceptedDigest + 2 ^ 129 := by
  decide +kernel

theorem opening_equal_words_different_messages :
    (List.replicate 15 0 ++ [1] : ByteKey) ≠ List.replicate 15 0 ++ [2] ∧
      replayProgram (fun _ : ByteKey => some recoveryAcceptedDigest)
        (wotsCountProgram (List.replicate 32 0) 1 0 0 (List.replicate 15 0 ++ [1]) 0 1 (by decide)) =
        some (some (0, recoveryAcceptedDigest)) ∧
      replayProgram (fun _ : ByteKey => some recoveryAcceptedDigest)
        (wotsCountProgram (List.replicate 32 0) 1 0 0 (List.replicate 15 0 ++ [2]) 0 1 (by decide)) =
        some (some (0, recoveryAcceptedDigest)) := by
  decide +kernel

theorem opening_zero_cut_uses_private_reply :
    replayProgram (fun key : WotsQuery => some (match key with
      | .inl _ => (2 ^ 129 : Digest) | .inr _ => 2 ^ 128))
      (wotsSeedChainProgram id (List.replicate 32 0) 1 0 0 0 0) = some 1 ∧
      replayProgram (fun key : WotsQuery => some (match key with
        | .inl _ => (2 ^ 129 : Digest) | .inr _ => 2 ^ 128))
        (wotsSeedChainProgram id (List.replicate 32 0) 1 0 0 0 1) = some 2 := by
  decide +kernel

theorem opening_actual_cached_signing :
    replayProgram (fun _ : WotsQuery => some recoveryAcceptedDigest)
      (wotsSignProgram id (List.replicate 32 0) 1 0 0 (List.replicate 16 0)
        (List.replicate 32 0) 1 (by decide)) = some (some ((fun _ => 2 ^ 72), 0)) := by
  apply eval_program_replay digestDraw _ (fun _ => some recoveryAcceptedDigest)
    (some ((fun _ => 2 ^ 72), 0), fun _ => some recoveryAcceptedDigest)
  rw [wots_sign_eval, wots_sign_one_accepted_cached]
  simp only [PMF.mem_support_pure_iff]
  rfl

theorem opening_actual_cached_signing_prefixes :
    ∃ digest, wotsAccept (wotsOfDigest digest) = true ∧
      ∀ i, replayProgram (fun _ : WotsQuery => some recoveryAcceptedDigest)
        (wotsSeedChainProgram id (List.replicate 32 0) 1 0 0 i.val
          (wotsOfDigest digest i).val) = some (2 ^ 72) := by
  obtain ⟨digest, _, accepted, positions⟩ := replay_wots_sign_witness id
    (fun _ : WotsQuery => some recoveryAcceptedDigest) (List.replicate 32 0) 1 0 0
    (List.replicate 16 0) (List.replicate 32 0) 1 (by decide) (fun _ => 2 ^ 72) 0
    opening_actual_cached_signing
  exact ⟨digest, accepted, positions⟩

theorem opening_actual_c10_signing_witness :
    ∃ sig, C10ChainWitness id (fun _ : WotsQuery => some recoveryAcceptedDigest)
      [] (List.replicate 32 0) (List.replicate 32 0) (List.replicate 32 0)
      (List.replicate 32 0) 1 1 (by decide) (by decide) sig := by
  obtain ⟨sig, execution⟩ := c10_sign_full_cache_accept id [] (List.replicate 32 0)
    (List.replicate 32 0) (List.replicate 32 0) (List.replicate 32 0)
  refine ⟨sig, replay_c10_chain_witness id (fun _ => some recoveryAcceptedDigest)
    [] (List.replicate 32 0) (List.replicate 32 0) (List.replicate 32 0)
    (List.replicate 32 0) 1 1 (by decide) (by decide) sig ?_⟩
  apply eval_program_replay digestDraw _ (fun _ => some recoveryAcceptedDigest)
    (some sig, fun _ => some recoveryAcceptedDigest)
  rw [c10_sign_eval, execution]
  simp only [PMF.mem_support_pure_iff]

end
end C10Probability

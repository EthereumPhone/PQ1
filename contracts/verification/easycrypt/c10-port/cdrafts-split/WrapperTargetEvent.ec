(* An unreturned ordinary FORS coordinate in the original wrapper is an
   unopened target in the release-aware equivalent execution. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion.
require import RawKeygen ForsPrivateLeaves WrapperSession WrapperByteSession ExposureLog ClientQueryLog ReturnedPrivateInputs.
require import TargetOracleSplit TargetByteView TargetTableProjection TargetTableGames OriginalTargetEvent.
require import WrapperTargetContext WrapperCandidateProjection WrapperSelectedTargetBound.

lemma wrapper_selected_candidates_unopened
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-OriginalTargetState,-TargetConfig}) target_ht target_tree target_index :
  hoare [ObservedWrapperCandidates(A).run : target=fors_private_key target_ht target_tree target_index ==>
    0<size res => !returned_private_input Independent.rawhistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries (fors_private_key target_ht target_tree target_index) => !OriginalTargetState.revealed].
proof.
  proc; call (wrapper_observed_candidates_unopened A target_ht target_tree target_index);
    inline Independent.init; auto; smt().
qed.

module SelectedWrapperUnreturnedCandidate (A : WrapperByteClient) = {
  proc run(target : raw_input) : bool = {
    var outputs; outputs <@ ObservedWrapperCandidates(A).run(target);
    return unreturned_candidate_guess Independent.rawhistory Independent.secrethistory
      WrapperSession.seed WrapperSession.root ExposureLog.entries outputs target;
  }
}.
lemma wrapper_selected_unreturned_implies_unopened
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-OriginalTargetState,-TargetConfig}) target_ht target_tree target_index :
  equiv [SelectedWrapperUnreturnedCandidate(A).run ~ SelectedWrapperTargetGuess(A).run :
    ={arg,glob A,glob WrapperLimits,glob KeygenInputs,glob WrapperSession,glob ExposureLog,glob ClientQueryLog} /\
    target{1}=fors_private_key target_ht target_tree target_index ==> res{1} => res{2}].
proof.
  proc; inline OriginalObservedPrivateGuess(TargetWrapperByteCandidates(A)).run
    ObservedCandidates(TargetWrapperByteCandidates(A),Independent).run.
  outline{2} [1-4] by { outputs <@ ObservedWrapperCandidates(A).run(target); }.
  wp;
  call (_ : ={arg,glob A,glob WrapperLimits,glob KeygenInputs,glob WrapperSession,glob ExposureLog,glob ClientQueryLog} /\
    target{1}=fors_private_key target_ht target_tree target_index ==>
    ={res,glob Independent,glob WrapperSession,glob ExposureLog,glob OriginalTargetState} /\
    TargetConfig.input{2}=fors_private_key target_ht target_tree target_index /\
    (0<size res{1} => !returned_private_input Independent.rawhistory{1} WrapperSession.seed{1} WrapperSession.root{1}
      ExposureLog.entries{1} (fors_private_key target_ht target_tree target_index) => !OriginalTargetState.revealed{1})).
  + conseq (_ : ={arg,glob A,glob WrapperLimits,glob KeygenInputs,glob WrapperSession,glob ExposureLog,glob ClientQueryLog} /\ target{1}=fors_private_key target_ht target_tree target_index ==>
      ={res,glob Independent,glob WrapperSession,glob ExposureLog,glob OriginalTargetState} /\ TargetConfig.input{2}=fors_private_key target_ht target_tree target_index)
      (wrapper_selected_candidates_unopened A target_ht target_tree target_index); 1,2:smt().
    proc; call (_ : ={glob A,glob WrapperLimits,glob KeygenInputs,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,glob Independent,glob OriginalTargetState,glob TargetConfig}); first by sim.
    inline Independent.init; auto; smt().
  auto=> />; rewrite /unreturned_candidate_guess /observed_private_guess;
    smt(size_eq0 size_ge0).
qed.

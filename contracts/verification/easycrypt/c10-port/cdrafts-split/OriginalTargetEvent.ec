(* Fixed-coordinate event on the unchanged, initialized byte candidate game. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion.
require import RawKeygen ForsPrivateLeaves FullSession ByteSession ExposureLog ClientQueryLog ReturnedPrivateInputs.
require import TargetOracleSplit TargetByteView TargetTableProjection TargetTableGames TargetContextOpenings.
require import OriginalByteTargetBound.

module ByteCandidateGame (A : ByteClient) = {
  proc run() : raw_input list = {
    var outputs; Independent.init();
    outputs <@ OriginalByteCandidates(A,Independent).run(); return outputs;
  }
}.
module ObservedSelectedCandidates (A : ByteClient) = {
  proc run(target : raw_input) : raw_input list = {
    var outputs; TargetConfig.input <- target;
    Independent.init(); OriginalTargetState.revealed <- false;
    outputs <@ TargetByteCandidates(A,ObservedTarget(Independent)).run(); return outputs;
  }
}.

lemma target_passive_context_projection
  (A <: TargetContext {-OriginalTargetState,-TargetConfig})
  (O <: PrefixOracle {-A,-OriginalTargetState,-TargetConfig}) :
  equiv [A(ConcreteTarget(O)).run ~ A(ObservedTarget(O)).run :
    ={glob A,glob O} ==> ={res,glob A,glob O}].
proof.
  proc (={glob O}) => //.
  + by sim.
  + proc*; inline ObservedTarget(O).derive; wp; call (_ : true); auto.
  + by sim.
  proc; inline ObservedTarget(O).derive PreparationView(O).fors.
  wp; call (_ : true); auto; rewrite /fors_private_key.
qed.
lemma observed_byte_candidates_projection
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-OriginalTargetState,-TargetConfig}) :
  equiv [OriginalByteCandidates(A,Independent).run ~ TargetByteCandidates(A,ObservedTarget(Independent)).run :
    ={glob A,glob Independent,glob FullLimits,glob KeygenInputs,glob FullSession,glob ExposureLog,glob ClientQueryLog} ==>
    ={res,glob A,glob Independent,glob FullSession,glob ExposureLog,glob ClientQueryLog}].
proof.
  transitivity TargetByteCandidates(A,ConcreteTarget(Independent)).run
    (={glob A,glob Independent,glob FullLimits,glob KeygenInputs,glob FullSession,glob ExposureLog,glob ClientQueryLog} ==>
      ={res,glob A,glob Independent,glob FullSession,glob ExposureLog,glob ClientQueryLog})
    (={glob A,glob Independent,glob FullLimits,glob KeygenInputs,glob FullSession,glob ExposureLog,glob ClientQueryLog} ==>
      ={res,glob A,glob Independent,glob FullSession,glob ExposureLog,glob ClientQueryLog}) => //.
  + smt().
  + conseq (target_byte_candidates_projection A Independent); smt().
  conseq (target_passive_context_projection (TargetByteCandidates(A)) Independent); smt().
qed.
lemma initialized_candidate_observer
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-OriginalTargetState,-TargetConfig}) :
  equiv [ByteCandidateGame(A).run ~ ObservedSelectedCandidates(A).run :
    ={glob A,glob FullLimits,glob KeygenInputs,glob FullSession,glob ExposureLog,glob ClientQueryLog} ==>
    ={res,glob A,glob Independent,glob FullSession,glob ExposureLog,glob ClientQueryLog}].
proof. proc; call (observed_byte_candidates_projection A); inline Independent.init; auto. qed.
lemma selected_candidates_unopened
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-OriginalTargetState,-TargetConfig}) target_ht target_tree target_index :
  hoare [ObservedSelectedCandidates(A).run : target=fors_private_key target_ht target_tree target_index ==>
    0<size res => !returned_private_input Independent.rawhistory FullSession.seed FullSession.root
      ExposureLog.entries (fors_private_key target_ht target_tree target_index) => !OriginalTargetState.revealed].
proof.
  proc; call (observed_byte_candidates_unopened A target_ht target_tree target_index);
    inline Independent.init; auto; smt().
qed.

op unreturned_candidate_guess h s seed root entries outputs input =
  !returned_private_input h seed root entries input /\ observed_private_guess s input outputs.
module SelectedUnreturnedCandidate (A : ByteClient) = {
  proc run(target : raw_input) : bool = {
    var outputs; outputs <@ ObservedSelectedCandidates(A).run(target);
    return unreturned_candidate_guess Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries outputs target;
  }
}.
lemma selected_unreturned_implies_unopened
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-OriginalTargetState,-TargetConfig}) target_ht target_tree target_index :
  equiv [SelectedUnreturnedCandidate(A).run ~ SelectedByteTargetGuess(A).run :
    ={arg,glob A,glob FullLimits,glob KeygenInputs,glob FullSession,glob ExposureLog,glob ClientQueryLog} /\
    target{1}=fors_private_key target_ht target_tree target_index ==> res{1} => res{2}].
proof.
  proc; inline OriginalObservedPrivateGuess(TargetByteCandidates(A)).run
    ObservedCandidates(TargetByteCandidates(A),Independent).run.
  outline{2} [1-4] by { outputs <@ ObservedSelectedCandidates(A).run(target); }.
  wp;
  call (_ : ={arg,glob A,glob FullLimits,glob KeygenInputs,glob FullSession,glob ExposureLog,glob ClientQueryLog} /\
    target{1}=fors_private_key target_ht target_tree target_index ==>
    ={res,glob Independent,glob FullSession,glob ExposureLog,glob OriginalTargetState} /\
    TargetConfig.input{2}=fors_private_key target_ht target_tree target_index /\
    (0<size res{1} => !returned_private_input Independent.rawhistory{1} FullSession.seed{1} FullSession.root{1}
      ExposureLog.entries{1} (fors_private_key target_ht target_tree target_index) => !OriginalTargetState.revealed{1})).
  + conseq (_ : ={arg,glob A,glob FullLimits,glob KeygenInputs,glob FullSession,glob ExposureLog,glob ClientQueryLog} /\ target{1}=fors_private_key target_ht target_tree target_index ==>
      ={res,glob Independent,glob FullSession,glob ExposureLog,glob OriginalTargetState} /\ TargetConfig.input{2}=fors_private_key target_ht target_tree target_index)
      (selected_candidates_unopened A target_ht target_tree target_index); 1,2:smt().
    proc; call (_ : ={glob A,glob FullLimits,glob KeygenInputs,glob FullSession,glob ExposureLog,glob ClientQueryLog,glob Independent,glob OriginalTargetState,glob TargetConfig}); first by sim.
    inline Independent.init; auto; smt().
  auto; rewrite /unreturned_candidate_guess /observed_private_guess; smt(size_eq0).
qed.

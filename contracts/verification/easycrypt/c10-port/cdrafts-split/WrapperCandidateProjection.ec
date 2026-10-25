(* The accepted ordinary-node candidates come from the original initialized
   byte wrapper. The release observer preserves both tables and all outputs,
   while cached internal-query logs may differ. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion.
require import WrapperSession WrapperByteSession ExposureLog ClientQueryLog ForsLeafView.
require import TargetOracleSplit TargetByteView TargetTableProjection OriginalTargetEvent.
require import WrapperQueryDriver WrapperReleaseSession WrapperReleaseContext WrapperTargetSession WrapperTargetContext.

module OriginalWrapperCandidates (A : WrapperByteClient) (O : PrefixOracle) = {
  proc run() : raw_input list = {
    var accepted, outputs;
    accepted <@ WrapperQueryContext(WrapperByteLift(A),O).run();
    outputs <- [];
    if (accepted) { outputs <- ordinary_output_candidates ClientQueryLog.output.`2; }
    return outputs;
  }
}.
module WrapperCandidateGame (A : WrapperByteClient) = {
  proc run() : raw_input list = {
    var outputs; Independent.init();
    outputs <@ OriginalWrapperCandidates(A,Independent).run(); return outputs;
  }
}.
module ObservedWrapperCandidates (A : WrapperByteClient) = {
  proc run(target : raw_input) : raw_input list = {
    var outputs; TargetConfig.input <- target;
    Independent.init(); OriginalTargetState.revealed <- false;
    outputs <@ TargetWrapperByteCandidates(A,ObservedTarget(Independent)).run(); return outputs;
  }
}.

lemma wrapper_concrete_candidates_projection
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) :
  equiv [OriginalWrapperCandidates(A,Independent).run ~ TargetWrapperByteCandidates(A,ConcreteTarget(Independent)).run :
    ={glob A,glob Independent,glob WrapperLimits,glob KeygenInputs} ==>
    ={res,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc; wp; call (_ : ={glob A,glob Independent,glob WrapperLimits,glob KeygenInputs} ==>
    ={res,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory}).
  + transitivity ConcreteWrapperReleaseContext(WrapperByteLift(A),Independent).run
      (={glob A,glob Independent,glob WrapperLimits,glob KeygenInputs} ==>
        ={res,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory})
      (={glob A,glob Independent,glob WrapperLimits,glob KeygenInputs} ==>
        ={res,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,glob Independent}) => //.
    - smt().
    - exact (wrapper_release_context_projection (WrapperByteLift(A))).
    by sim.
  auto; smt().
qed.

lemma wrapper_observed_candidates_projection
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-OriginalTargetState,-TargetConfig}) :
  equiv [OriginalWrapperCandidates(A,Independent).run ~ TargetWrapperByteCandidates(A,ObservedTarget(Independent)).run :
    ={glob A,glob Independent,glob WrapperLimits,glob KeygenInputs,glob WrapperSession,glob ExposureLog,glob ClientQueryLog} ==>
    ={res,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory}].
proof.
  transitivity TargetWrapperByteCandidates(A,ConcreteTarget(Independent)).run
    (={glob A,glob Independent,glob WrapperLimits,glob KeygenInputs,glob WrapperSession,glob ExposureLog,glob ClientQueryLog} ==>
      ={res,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory})
    (={glob A,glob Independent,glob WrapperLimits,glob KeygenInputs,glob WrapperSession,glob ExposureLog,glob ClientQueryLog} ==>
      ={res,glob A,glob Independent,glob WrapperSession,glob ExposureLog,glob ClientQueryLog}) => //.
  + smt().
  + conseq (wrapper_concrete_candidates_projection A); smt().
  conseq (target_passive_context_projection (TargetWrapperByteCandidates(A)) Independent); smt().
qed.

lemma wrapper_initialized_candidate_observer
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -Independent,-OriginalTargetState,-TargetConfig}) :
  equiv [WrapperCandidateGame(A).run ~ ObservedWrapperCandidates(A).run :
    ={glob A,glob WrapperLimits,glob KeygenInputs,glob WrapperSession,glob ExposureLog,glob ClientQueryLog} ==>
    ={res,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc; call (wrapper_observed_candidates_projection A); inline Independent.init; auto.
qed.

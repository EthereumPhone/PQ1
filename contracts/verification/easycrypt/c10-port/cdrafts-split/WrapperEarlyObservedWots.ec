(* Eager memo sampling can add the passive disclosure observer without changing the selected event. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen.
require import WrapperSession WrapperByteSession ExposureLog ClientQueryLog.
require import ChainStageSampling CachedChainOracle WrapperWotsChainContext ActualWotsCoordinate.
require import PublicTargetSampling PrivateValueSampling InitializedChainSampling WrapperSelectedChainSampling.
require import ChainStartSampling ChainSamplingOrder ChainReferenceSampling WrapperWotsCandidateEvidence.

module WrapperEarlyPlainWotsGame (A : WrapperByteClient) = {
  proc run() : bool = {
    var ignored; Independent.init(); CompleteChainCache.sample();
    ignored <@ WrapperLoggingWotsContext(A,Independent).run();
    return selected_wots_cut Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries WrapperWotsCandidatesLog.outputs
      (ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainCut.cut);
  }
}.
module WrapperEarlyObservedWotsGame (A : WrapperByteClient) = {
  proc run() : bool = {
    Independent.init(); CompleteChainCache.sample(); ChainRevelation.opened <- false;
    WrapperWotsCandidatesLog.outputs <@ WrapperChainWotsCandidates(A,ObservedChain(Independent)).run();
    return selected_wots_cut Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries WrapperWotsCandidatesLog.outputs
      (ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainCut.cut);
  }
}.
lemma wrapper_early_selected_plain
  (A <: WrapperByteClient {-Independent,-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WrapperWotsCandidatesLog,-ChainStage,-ChainCut,-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,
    -PublicMemoSample,-PublicTargetSample}) :
  equiv[WrapperEarlySelectedWotsGame(A).run ~ WrapperEarlyPlainWotsGame(A).run :
    ={glob A,glob WrapperSession,glob WrapperLimits,glob KeygenInputs,glob ExposureLog,glob ClientQueryLog,
      glob WrapperWotsCandidatesLog,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainCut.cut}
    ==> ={res}].
proof.
  proc; inline InitializedChainSampling(WrapperLoggingWotsContext(A)).early ChainSamplingOrder(WrapperLoggingWotsContext(A)).run7.
  outline{1} [2..9] by { CompleteChainCache.sample(); }.
  wp; call (_ : ={glob A,glob Independent,glob WrapperSession,glob WrapperLimits,glob KeygenInputs,glob ExposureLog,
    glob ClientQueryLog,glob WrapperWotsCandidatesLog} ==>
    ={glob A,glob Independent,glob WrapperSession,glob WrapperLimits,glob KeygenInputs,glob ExposureLog,
      glob ClientQueryLog,glob WrapperWotsCandidatesLog}).
  + symmetry; conseq (sampling_oracle_context_projection (WrapperLoggingWotsContext(A))); smt().
  call (_ : ={glob Independent,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} ==>
    ={glob Independent}); first by sim.
  inline Independent.init; auto.
qed.
lemma wrapper_early_plain_observed
  (A <: WrapperByteClient {-Independent,-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WrapperWotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-CachedChain,-ObservedChain,
    -SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample}) :
  equiv[WrapperEarlyPlainWotsGame(A).run ~ WrapperEarlyObservedWotsGame(A).run :
    ={glob A,glob WrapperSession,glob WrapperLimits,glob KeygenInputs,glob ExposureLog,glob ClientQueryLog,
      ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainCut.cut} ==> ={res}].
proof.
  proc; inline WrapperLoggingWotsContext(A,Independent).run.
  wp; call (wrapper_observed_wots_candidates_projection A).
  wp; call (_ : ={glob Independent,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} ==>
    ={glob Independent}); first by sim.
  inline Independent.init; auto.
qed.

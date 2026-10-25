(* Silent selected-chain sampling is moved across the unchanged adaptive byte context. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen.
require import WrapperSession WrapperByteSession ExposureLog ClientQueryLog.
require import ChainStageSampling CachedChainOracle WrapperWotsChainContext ActualWotsCoordinate.
require import PublicTargetSampling PrivateValueSampling InitializedChainSampling.

module WrapperWotsCandidatesLog = { var outputs : raw_input list }.
module WrapperLoggingWotsContext (A : WrapperByteClient) (O : PrefixOracle) = {
  proc run() : bool = {
    WrapperWotsCandidatesLog.outputs <@ WrapperOriginalWotsCandidates(A,O).run();
    return true;
  }
}.
module WrapperSelectedWotsGame (A : WrapperByteClient) = {
  proc run() : bool = {
    var ignored; Independent.init(); ignored <@ WrapperLoggingWotsContext(A,Independent).run();
    return selected_wots_cut Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries WrapperWotsCandidatesLog.outputs
      (ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainCut.cut);
  }
}.
module WrapperLateSelectedWotsGame (A : WrapperByteClient) = {
  proc run() : bool = {
    var ignored; ignored <@ InitializedChainSampling(WrapperLoggingWotsContext(A)).late();
    return selected_wots_cut Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries WrapperWotsCandidatesLog.outputs
      (ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainCut.cut);
  }
}.
module WrapperEarlySelectedWotsGame (A : WrapperByteClient) = {
  proc run() : bool = {
    var ignored; ignored <@ InitializedChainSampling(WrapperLoggingWotsContext(A)).early();
    return selected_wots_cut Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries WrapperWotsCandidatesLog.outputs
      (ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainCut.cut);
  }
}.
lemma wrapper_selected_chain_early_late
  (A <: WrapperByteClient {-Independent,-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WrapperWotsCandidatesLog,-ChainStage,-ChainCut,-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,
    -PublicMemoSample,-PublicTargetSample}) :
  equiv[WrapperEarlySelectedWotsGame(A).run ~ WrapperLateSelectedWotsGame(A).run :
    ={glob A,glob WrapperSession,glob WrapperLimits,glob KeygenInputs,glob ExposureLog,glob ClientQueryLog,
      glob WrapperWotsCandidatesLog,glob Independent,glob PrivateValueSample,glob PublicTargetSample,glob ChainStage,glob ChainCut}
    ==> ={res}].
proof.
  proc; call (initialized_chain_sampling_early_late (WrapperLoggingWotsContext(A))); auto.
qed.

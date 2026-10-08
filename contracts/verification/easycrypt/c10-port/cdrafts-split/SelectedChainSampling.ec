(* Silent selected-chain sampling is moved across the unchanged adaptive byte context. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen.
require import FullSession ByteSession ExposureLog ClientQueryLog.
require import ChainStageSampling CachedChainOracle ChainByteCandidates ActualWotsCoordinate.
require import PublicTargetSampling PrivateValueSampling InitializedChainSampling.

module WotsCandidatesLog = { var outputs : raw_input list }.
module LoggingWotsContext (A : ByteClient) (O : PrefixOracle) = {
  proc run() : bool = {
    WotsCandidatesLog.outputs <@ OriginalWotsCandidates(A,O).run();
    return true;
  }
}.
module SelectedWotsGame (A : ByteClient) = {
  proc run() : bool = {
    var ignored; Independent.init(); ignored <@ LoggingWotsContext(A,Independent).run();
    return selected_wots_cut Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries WotsCandidatesLog.outputs
      (ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainCut.cut);
  }
}.
module LateSelectedWotsGame (A : ByteClient) = {
  proc run() : bool = {
    var ignored; ignored <@ InitializedChainSampling(LoggingWotsContext(A)).late();
    return selected_wots_cut Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries WotsCandidatesLog.outputs
      (ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainCut.cut);
  }
}.
module EarlySelectedWotsGame (A : ByteClient) = {
  proc run() : bool = {
    var ignored; ignored <@ InitializedChainSampling(LoggingWotsContext(A)).early();
    return selected_wots_cut Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries WotsCandidatesLog.outputs
      (ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainCut.cut);
  }
}.
lemma selected_chain_early_late
  (A <: ByteClient {-Independent,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WotsCandidatesLog,-ChainStage,-ChainCut,-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,
    -PublicMemoSample,-PublicTargetSample}) :
  equiv[EarlySelectedWotsGame(A).run ~ LateSelectedWotsGame(A).run :
    ={glob A,glob FullSession,glob FullLimits,glob KeygenInputs,glob ExposureLog,glob ClientQueryLog,
      glob WotsCandidatesLog,glob Independent,glob PrivateValueSample,glob PublicTargetSample,glob ChainStage,glob ChainCut}
    ==> ={res}].
proof.
  proc; call (initialized_chain_sampling_early_late (LoggingWotsContext(A))); auto.
qed.

(* Eager memo sampling can add the passive disclosure observer without changing the selected event. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen.
require import FullSession ByteSession ExposureLog ClientQueryLog.
require import ChainStageSampling CachedChainOracle ChainByteCandidates ActualWotsCoordinate.
require import PublicTargetSampling PrivateValueSampling InitializedChainSampling SelectedChainSampling.
require import ChainStartSampling ChainSamplingOrder ChainReferenceSampling ObservedCandidateHistory.

module EarlyPlainWotsGame (A : ByteClient) = {
  proc run() : bool = {
    var ignored; Independent.init(); CompleteChainCache.sample();
    ignored <@ LoggingWotsContext(A,Independent).run();
    return selected_wots_cut Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries WotsCandidatesLog.outputs
      (ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainCut.cut);
  }
}.
module EarlyObservedWotsGame (A : ByteClient) = {
  proc run() : bool = {
    Independent.init(); CompleteChainCache.sample(); ChainRevelation.opened <- false;
    WotsCandidatesLog.outputs <@ ChainByteCandidates(A,ObservedChain(Independent)).run();
    return selected_wots_cut Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries WotsCandidatesLog.outputs
      (ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainCut.cut);
  }
}.
lemma early_selected_plain
  (A <: ByteClient {-Independent,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WotsCandidatesLog,-ChainStage,-ChainCut,-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,
    -PublicMemoSample,-PublicTargetSample}) :
  equiv[EarlySelectedWotsGame(A).run ~ EarlyPlainWotsGame(A).run :
    ={glob A,glob FullSession,glob FullLimits,glob KeygenInputs,glob ExposureLog,glob ClientQueryLog,
      glob WotsCandidatesLog,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainCut.cut}
    ==> ={res}].
proof.
  proc; inline InitializedChainSampling(LoggingWotsContext(A)).early ChainSamplingOrder(LoggingWotsContext(A)).run7.
  outline{1} [2..9] by { CompleteChainCache.sample(); }.
  wp; call (_ : ={glob A,glob Independent,glob FullSession,glob FullLimits,glob KeygenInputs,glob ExposureLog,
    glob ClientQueryLog,glob WotsCandidatesLog} ==>
    ={glob A,glob Independent,glob FullSession,glob FullLimits,glob KeygenInputs,glob ExposureLog,
      glob ClientQueryLog,glob WotsCandidatesLog}).
  + symmetry; conseq (sampling_oracle_context_projection (LoggingWotsContext(A))); smt().
  call (_ : ={glob Independent,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} ==>
    ={glob Independent}); first by sim.
  inline Independent.init; auto.
qed.
lemma early_plain_observed
  (A <: ByteClient {-Independent,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-CachedChain,-ObservedChain,
    -SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample}) :
  equiv[EarlyPlainWotsGame(A).run ~ EarlyObservedWotsGame(A).run :
    ={glob A,glob FullSession,glob FullLimits,glob KeygenInputs,glob ExposureLog,glob ClientQueryLog,
      ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainCut.cut} ==> ={res}].
proof.
  proc; inline LoggingWotsContext(A,Independent).run.
  wp; call (observed_wots_candidates_projection A).
  wp; call (_ : ={glob Independent,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} ==>
    ={glob Independent}); first by sim.
  inline Independent.init; auto.
qed.

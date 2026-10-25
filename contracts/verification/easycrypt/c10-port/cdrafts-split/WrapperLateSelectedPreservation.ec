(* Sampling a chain after the actual run preserves every already witnessed selected-cut event. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen.
require import WrapperSession WrapperByteSession ExposureLog ClientQueryLog.
require import ChainStageSampling CachedChainOracle WrapperWotsChainContext ActualWotsCoordinate.
require import PublicTargetSampling PrivateValueSampling InitializedChainSampling WrapperSelectedChainSampling.
require import WrapperWotsSeed ChainStartSampling ChainReferenceEntries ChainReferenceSampling ChainSamplingTotal.

lemma wrapper_logging_wots_seed
  (A <: WrapperByteClient {-Independent,-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-WrapperWotsCandidatesLog}) seed0 :
  hoare[WrapperLoggingWotsContext(A,Independent).run : pad(node KeygenInputs.public_seed)=seed0 ==> WrapperSession.seed=seed0].
proof. proc; call (wrapper_wots_original_candidates_seed A seed0); auto. qed.

lemma wrapper_selected_wots_late_preserved
  (A <: WrapperByteClient {-Independent,-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WrapperWotsCandidatesLog,-ChainStage,-ChainCut,-SamplingOracle,-PrivateMemoSample,-PrivateValueSample,
    -PublicMemoSample,-PublicTargetSample}) :
  equiv[WrapperSelectedWotsGame(A).run ~ WrapperLateSelectedWotsGame(A).run :
    ={glob A,glob WrapperSession,glob WrapperLimits,glob KeygenInputs,glob ExposureLog,glob ClientQueryLog,
      glob WrapperWotsCandidatesLog,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainCut.cut} /\
    ChainStage.seed{1}=pad(node KeygenInputs.public_seed{1}) /\ 0<=ChainStage.index{1}<43 ==>
    res{1} => res{2}].
proof.
  proc; inline InitializedChainSampling(WrapperLoggingWotsContext(A)).late.
  outline{2} [3..10] by { CompleteChainCache.sample(); }.
  seq 2 2 : (={glob A,glob Independent,glob WrapperSession,glob WrapperLimits,glob KeygenInputs,glob ExposureLog,
    glob ClientQueryLog,glob WrapperWotsCandidatesLog,ChainStage.seed,ChainStage.layer,ChainStage.tree,
    ChainStage.kp,ChainStage.index,ChainCut.cut} /\ WrapperSession.seed{1}=ChainStage.seed{1} /\ 0<=ChainStage.index{1}<43).
  + call (_ : ={glob A,glob Independent,glob WrapperSession,glob WrapperLimits,glob KeygenInputs,glob ExposureLog,
      glob ClientQueryLog,glob WrapperWotsCandidatesLog} /\
      ChainStage.seed{1}=pad(node KeygenInputs.public_seed{1}) ==>
      ={glob A,glob Independent,glob WrapperSession,glob WrapperLimits,glob KeygenInputs,glob ExposureLog,
        glob ClientQueryLog,glob WrapperWotsCandidatesLog} /\ WrapperSession.seed{1}=ChainStage.seed{1}).
    - exists* ChainStage.seed{1}; elim* => seed0.
      conseq (sampling_oracle_context_projection (WrapperLoggingWotsContext(A))) (wrapper_logging_wots_seed A seed0) _; smt().
    inline Independent.init; auto; smt().
  case (selected_wots_cut Independent.rawhistory{1} Independent.secrethistory{1}
    WrapperSession.seed{1} WrapperSession.root{1} ExposureLog.entries{1} WrapperWotsCandidatesLog.outputs{1}
    (ChainStage.layer{1},ChainStage.tree{1},ChainStage.kp{1},ChainStage.index{1},ChainCut.cut{1})).
  + exists* ChainStage.seed{2},ChainStage.layer{2},ChainStage.tree{2},ChainStage.kp{2},ChainStage.index{2},
      Independent.rawhistory{2},Independent.secrethistory{2}; elim* => seed0 layer0 tree0 kp0 i0 h0 s0.
    wp; call{2} (complete_chain_existing_sure seed0 layer0 tree0 kp0 i0 h0 s0).
    auto; rewrite /selected_wots_cut; smt(wots_chain_reference).
  wp; call{2} complete_chain_sample_lossless; auto.
qed.

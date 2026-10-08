(* The selected original event is bounded by the already charged fresh unopened cache game. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen.
require import FullSession ByteSession ExposureLog ClientQueryLog.
require import ChainStageSampling CachedChainOracle ChainByteCandidates ActualWotsCoordinate.
require import PublicTargetSampling PrivateValueSampling SelectedChainSampling EarlyObservedWots.
require import ChainReferenceSampling ChainCacheInvariant ChainUnopenedEvent FreshChainGuess.
require import ObservedValueOpening PreparedCutCoupling.

lemma early_observed_cache_charge
  (A <: ByteClient {-Independent,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-CachedChain,-ObservedChain,
    -SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample}) qs0 :
  0<=qs0 =>
  equiv[EarlyObservedWotsGame(A).run ~ FreshCachedChainGuess(ChainByteCandidates(A)).run :
    ={glob A,glob FullSession,glob FullLimits,glob KeygenInputs,glob ExposureLog,glob ClientQueryLog,
      ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainCut.cut} /\
    FullLimits.sign_cap{1}=qs0 /\ ChainStage.seed{1}=pad(node KeygenInputs.public_seed{1}) /\
    valid_chain_address ChainStage.layer{1} ChainStage.tree{1} ChainStage.kp{1} ChainStage.index{1} /\
    0<=ChainCut.cut{1}<7 ==> res{1} => res{2}].
proof.
  move=> hqs; proc; inline CachedUnopenedGuess(ChainByteCandidates(A)).run.
  seq 2 2 : (={glob A,glob Independent,glob FullSession,glob FullLimits,glob KeygenInputs,glob ExposureLog,glob ClientQueryLog,
      ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainStage.values,ChainCut.cut} /\
    FullLimits.sign_cap{1}=qs0 /\ ChainStage.seed{1}=pad(node KeygenInputs.public_seed{1}) /\
    valid_chain_address ChainStage.layer{1} ChainStage.tree{1} ChainStage.kp{1} ChainStage.index{1} /\
    0<=ChainCut.cut{1}<7 /\
    complete_chain_cache Independent.rawhistory{1} Independent.secrethistory{1}
      (ChainStage.seed{1},ChainStage.layer{1},ChainStage.tree{1},ChainStage.kp{1},ChainStage.index{1}) ChainStage.values{1}).
  + exists* ChainStage.seed{1},ChainStage.layer{1},ChainStage.tree{1},ChainStage.kp{1},ChainStage.index{1};
      elim* => seed0 layer0 tree0 kp0 i0.
    call (complete_chain_coupled_cache (seed0,layer0,tree0,kp0,i0)); inline Independent.init; auto; smt().
  exists* ChainStage.seed{1},ChainStage.layer{1},ChainStage.tree{1},ChainStage.kp{1},ChainStage.index{1},ChainStage.values{1};
    elim* => seed0 layer0 tree0 kp0 i0 values.
  wp; call (prepared_actual_cut_coupling A qs0 (seed0,layer0,tree0,kp0,i0) values hqs).
  auto; smt().
qed.

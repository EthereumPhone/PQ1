(* The adaptive trusted-chain context can use the cached oracle with exact outputs. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen.
require import ChainValueView ChainStageSampling ChainCacheInvariant CachedChainOracle.
require import CacheMemoCoupling CacheValueCoupling ChainObserverProjection.

lemma chain_context_observer_projection
  (A <: ChainContext {-Independent,-ChainStage,-ChainCut,-ChainRevelation,-CachedChain,-ObservedChain}) :
  equiv [A(ConcreteChain(Independent)).run ~ A(ObservedChain(Independent)).run :
    ={glob A,glob Independent} ==> ={res,glob A,glob Independent}].
proof.
  proc (={glob Independent}) => //.
  + by sim.
  + proc*; call observed_private_projection; auto.
  proc*; call observed_value_projection; auto.
qed.

lemma chain_context_cache_coupling
  (A <: ChainContext {-Independent,-ChainStage,-ChainCut,-ChainRevelation,-CachedChain,-ObservedChain}) c values :
  equiv [A(ObservedChain(Independent)).run ~ A(CachedChain).run :
    ={glob A,Independent.rawhistory,Independent.secrethistory,ChainRevelation.opened,ChainCut.cut,
      ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainStage.values} /\
    (ChainStage.seed{1},ChainStage.layer{1},ChainStage.tree{1},ChainStage.kp{1},ChainStage.index{1})=c /\
    ChainStage.values{1}=values /\
    complete_chain_cache Independent.rawhistory{1} Independent.secrethistory{1} c values ==>
    ={res,glob A,Independent.rawhistory,Independent.secrethistory,ChainRevelation.opened,ChainCut.cut,
      ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainStage.values} /\
    complete_chain_cache Independent.rawhistory{1} Independent.secrethistory{1} c values].
proof.
  proc (={Independent.rawhistory,Independent.secrethistory,ChainRevelation.opened,ChainCut.cut,
      ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainStage.values} /\
    (ChainStage.seed{1},ChainStage.layer{1},ChainStage.tree{1},ChainStage.kp{1},ChainStage.index{1})=c /\
    ChainStage.values{1}=values /\
    complete_chain_cache Independent.rawhistory{1} Independent.secrethistory{1} c values) => //.
  + proc*; call (cache_hash_coupling c values); auto.
  + proc*; call (cache_derive_coupling c values); auto.
  proc*; call (cache_value_coupling c values); auto.
qed.

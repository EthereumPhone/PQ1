(* Concrete fallback chains remain coupled across unequal passive hash logs. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import ChainValueView ChainStageSampling ChainCacheInvariant CachedChainOracle CacheMemoCoupling.

lemma cache_concrete_coupling c values :
  equiv [ConcreteChain(ChainObservedPrefix(Independent)).value ~ ConcreteChain(ChainObservedPrefix(Independent)).value :
    ={arg,Independent.rawhistory,Independent.secrethistory,ChainRevelation.opened,
      ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\
    complete_chain_cache Independent.rawhistory{1} Independent.secrethistory{1} c values ==>
    ={res,Independent.rawhistory,Independent.secrethistory,ChainRevelation.opened} /\
    complete_chain_cache Independent.rawhistory{1} Independent.secrethistory{1} c values].
proof.
  proc; inline RawWots(PreparationView(ChainObservedPrefix(Independent))).chain.
  wp; while (={seed0,layer0,tree0,kp0,index0,current0,j,stop0,
      Independent.rawhistory,Independent.secrethistory,ChainRevelation.opened} /\
    complete_chain_cache Independent.rawhistory{1} Independent.secrethistory{1} c values).
  + wp; call (cache_hash_coupling c values); auto.
  wp; inline PreparationView(ChainObservedPrefix(Independent)).wots.
  wp; call (cache_derive_coupling c values); auto.
qed.

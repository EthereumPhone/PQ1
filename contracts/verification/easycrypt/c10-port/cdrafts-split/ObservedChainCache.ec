(* Public and observed private accesses preserve every precomputed chain value. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen RawWots KeygenPrefixes.
require import ChainValueView ChainStageSampling ChainCacheInvariant CachedChainOracle.

lemma observed_derive_cache_preserved c values :
  hoare [ChainObservedPrefix(Independent).derive :
    complete_chain_cache Independent.rawhistory Independent.secrethistory c values ==>
    complete_chain_cache Independent.rawhistory Independent.secrethistory c values].
proof. proc; call (chain_cache_derive_preserved c values); auto. qed.

lemma concrete_observed_cache_preserved c values :
  hoare [ConcreteChain(ChainObservedPrefix(Independent)).value :
    complete_chain_cache Independent.rawhistory Independent.secrethistory c values ==>
    complete_chain_cache Independent.rawhistory Independent.secrethistory c values].
proof.
  proc; inline RawWots(PreparationView(ChainObservedPrefix(Independent))).chain.
  wp; while (complete_chain_cache Independent.rawhistory Independent.secrethistory c values).
  + wp; call (chain_cache_hash_preserved c values); auto.
  wp; inline PreparationView(ChainObservedPrefix(Independent)).wots.
  wp; call (observed_derive_cache_preserved c values); auto.
qed.

lemma cached_value_cache_preserved c values :
  hoare [CachedChain.value :
    complete_chain_cache Independent.rawhistory Independent.secrethistory c values ==>
    complete_chain_cache Independent.rawhistory Independent.secrethistory c values].
proof. proc; if; auto; call (concrete_observed_cache_preserved c values); auto. qed.

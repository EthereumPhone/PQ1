(* Replacing trusted selected-chain replay by its cache preserves outputs and both tables. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen WotsChainSplit ChainReferenceEntries.
require import ChainStageSampling ChainValueView ChainCacheInvariant CachedChainOracle.
require import CacheConcreteCoupling ChainReplayTotal.

lemma cache_value_coupling c values :
  equiv [ObservedChain(Independent).value ~ CachedChain.value :
    ={arg,Independent.rawhistory,Independent.secrethistory,ChainRevelation.opened,ChainCut.cut,
      ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainStage.values} /\
    (ChainStage.seed{1},ChainStage.layer{1},ChainStage.tree{1},ChainStage.kp{1},ChainStage.index{1})=c /\
    ChainStage.values{1}=values /\
    complete_chain_cache Independent.rawhistory{1} Independent.secrethistory{1} c values ==>
    ={res,Independent.rawhistory,Independent.secrethistory,ChainRevelation.opened} /\
    complete_chain_cache Independent.rawhistory{1} Independent.secrethistory{1} c values].
proof.
  proc; if; first auto.
  + sp 1 1; wp.
    exists* Independent.rawhistory{1},Independent.secrethistory{1},stop{1}; elim* => h0 s0 stop0 oldR oldL.
    call{1} (concrete_chain_replay_total c.`1 c.`2 c.`3 c.`4 c.`5 stop0 h0 s0).
    auto; rewrite /complete_chain_cache /stored_wots_values; smt().
  call (cache_concrete_coupling c values); auto.
qed.

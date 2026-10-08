(* Coupled memo accesses agree even when their passive raw query logs differ. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PersistentGrind AcceptedContexts RawKeygen.
require import ChainStageSampling ChainCacheInvariant CachedChainOracle.

lemma cache_public_fresh h s c values x d :
  x \notin h => complete_chain_cache h s c values => complete_chain_cache h.[x<-d] s c values.
proof.
  move=> hx hc; apply (complete_chain_cache_extends h h.[x<-d] s s c values) => //.
  rewrite /extends; smt(get_setE domE).
qed.
lemma cache_private_fresh h s c values x d :
  x \notin s => complete_chain_cache h s c values => complete_chain_cache h s.[x<-d] c values.
proof.
  move=> hx hc; apply (complete_chain_cache_extends h h s s.[x<-d] c values) => //.
  rewrite /extends; smt(get_setE domE).
qed.

lemma cache_hash_coupling c values :
  equiv [Independent.hash ~ Independent.hash :
    ={arg,Independent.rawhistory,Independent.secrethistory} /\
    complete_chain_cache Independent.rawhistory{1} Independent.secrethistory{1} c values ==>
    ={res,Independent.rawhistory,Independent.secrethistory} /\
    complete_chain_cache Independent.rawhistory{1} Independent.secrethistory{1} c values].
proof. proc; sp 1 1; if; auto; smt(cache_public_fresh). qed.

lemma cache_derive_coupling c values :
  equiv [ChainObservedPrefix(Independent).derive ~ ChainObservedPrefix(Independent).derive :
    ={arg,Independent.rawhistory,Independent.secrethistory,ChainRevelation.opened,
      ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\
    complete_chain_cache Independent.rawhistory{1} Independent.secrethistory{1} c values ==>
    ={res,Independent.rawhistory,Independent.secrethistory,ChainRevelation.opened} /\
    complete_chain_cache Independent.rawhistory{1} Independent.secrethistory{1} c values].
proof. proc; inline Independent.derive; sp; if; auto; smt(cache_private_fresh). qed.

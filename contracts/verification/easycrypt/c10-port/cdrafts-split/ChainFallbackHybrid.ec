(* Ordinary fallback chains remain coupled up to the first hidden-node query. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots WotsReference.
require import ChainValueView ChainStageSampling CachedChainOracle DualDigestSampling.
require import RedactedChainOracle ChainRedactionTables ChainPublicHybrid.

lemma chain_hybrid_hash_bad_sure :
  phoare [ChainHybridPrefix.hash : ChainGuess.bad ==> ChainGuess.bad] = 1%r.
proof. proc; call independent_hash_ll; auto; smt(). qed.

lemma raw_chain_hybrid_coupling :
  equiv [RawWots(PreparationView(RedactedChainPrefix)).chain ~ RawWots(PreparationView(ChainHybridPrefix)).chain :
    ={arg} /\ !ChainGuess.bad{2} /\
    chain_public_agree DualDigest.hidden{2} Independent.rawhistory{1} Independent.rawhistory{2} ==>
    !ChainGuess.bad{2} => ={res} /\
    chain_public_agree DualDigest.hidden{2} Independent.rawhistory{1} Independent.rawhistory{2}].
proof.
  proc; while (={seed,layer,tree,kp,index,j,stop} /\
    (!ChainGuess.bad{2} => ={current} /\
      chain_public_agree DualDigest.hidden{2} Independent.rawhistory{1} Independent.rawhistory{2})).
  + wp; case (ChainGuess.bad{2}).
    - call{1} independent_hash_ll; call{2} chain_hybrid_hash_bad_sure; auto; smt().
    call chain_public_query_redaction; auto; smt().
  auto; smt().
qed.

lemma concrete_chain_hybrid_coupling :
  equiv [ConcreteChain(RedactedChainPrefix).value ~ ConcreteChain(ChainHybridPrefix).value :
    ={arg,ChainRedaction.opened,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\
    !ChainGuess.bad{2} /\
    chain_public_agree DualDigest.hidden{2} Independent.rawhistory{1} Independent.rawhistory{2} /\
    chain_private_agree (wots_key ChainStage.layer{2} ChainStage.tree{2} ChainStage.kp{2} ChainStage.index{2})
      Independent.secrethistory{1} Independent.secrethistory{2} ==>
    !ChainGuess.bad{2} => ={res,ChainRedaction.opened} /\
    chain_public_agree DualDigest.hidden{2} Independent.rawhistory{1} Independent.rawhistory{2} /\
    chain_private_agree (wots_key ChainStage.layer{2} ChainStage.tree{2} ChainStage.kp{2} ChainStage.index{2})
      Independent.secrethistory{1} Independent.secrethistory{2}].
proof.
  proc; call raw_chain_hybrid_coupling.
  inline PreparationView(RedactedChainPrefix).wots PreparationView(ChainHybridPrefix).wots.
  wp; call chain_private_query_redaction; auto; smt().
qed.

lemma cached_chain_hybrid_coupling :
  equiv [RedactedCachedChain.value ~ HybridCachedChain.value :
    ={arg,ChainRedaction.opened,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\
    !ChainGuess.bad{2} /\
    chain_visible_agree ChainCut.cut{2} ChainStage.values{1} ChainStage.values{2} /\
    chain_public_agree DualDigest.hidden{2} Independent.rawhistory{1} Independent.rawhistory{2} /\
    chain_private_agree (wots_key ChainStage.layer{2} ChainStage.tree{2} ChainStage.kp{2} ChainStage.index{2})
      Independent.secrethistory{1} Independent.secrethistory{2} ==>
    !ChainGuess.bad{2} => ={res,ChainRedaction.opened} /\
    chain_public_agree DualDigest.hidden{2} Independent.rawhistory{1} Independent.rawhistory{2} /\
    chain_private_agree (wots_key ChainStage.layer{2} ChainStage.tree{2} ChainStage.kp{2} ChainStage.index{2})
      Independent.secrethistory{1} Independent.secrethistory{2}].
proof.
  proc; if; first auto.
  + if; auto; rewrite /chain_visible_agree; smt().
  call concrete_chain_hybrid_coupling; auto; smt().
qed.

(* The adaptive context sees the same chain interface until a hidden-node guess. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots WotsReference.
require import ChainValueView ChainStageSampling CachedChainOracle DualDigestSampling.
require import RedactedChainOracle ChainRedactionTables ChainPublicHybrid ChainFallbackHybrid.

lemma chain_hybrid_hash_bad :
  hoare [ChainHybridPrefix.hash : ChainGuess.bad ==> ChainGuess.bad].
proof. proc; call (_ : true); auto; smt(). qed.
lemma concrete_hybrid_bad :
  hoare [ConcreteChain(ChainHybridPrefix).value : ChainGuess.bad ==> ChainGuess.bad].
proof.
  proc; inline RawWots(PreparationView(ChainHybridPrefix)).chain.
  wp; while ChainGuess.bad.
  + wp; call chain_hybrid_hash_bad; auto.
  wp; inline PreparationView(ChainHybridPrefix).wots; wp.
  call (_ : true); auto.
qed.
lemma cached_hybrid_bad :
  hoare [HybridCachedChain.value : ChainGuess.bad ==> ChainGuess.bad].
proof. proc; if; first by if; auto. call concrete_hybrid_bad; auto. qed.
lemma cached_hybrid_bad_sure :
  phoare [HybridCachedChain.value : ChainGuess.bad ==> ChainGuess.bad] = 1%r.
proof. conseq chain_hybrid_value_lossless cached_hybrid_bad; smt(). qed.

lemma adaptive_chain_hybrid
  (A <: ChainContext {-Independent,-ChainStage,-ChainCut,-ChainRevelation,-ChainRedaction,
    -CachedChain,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) :
  (forall (O <: ChainOracle {-A}), islossless O.hash => islossless O.derive =>
    islossless O.value => islossless A(O).run) =>
  equiv [A(RedactedCachedChain).run ~ A(HybridCachedChain).run :
    ={glob A,ChainRedaction.opened,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\
    !ChainGuess.bad{2} /\
    chain_visible_agree ChainCut.cut{2} ChainStage.values{1} ChainStage.values{2} /\
    chain_public_agree DualDigest.hidden{2} Independent.rawhistory{1} Independent.rawhistory{2} /\
    chain_private_agree (wots_key ChainStage.layer{2} ChainStage.tree{2} ChainStage.kp{2} ChainStage.index{2})
      Independent.secrethistory{1} Independent.secrethistory{2} ==>
    !ChainGuess.bad{2} => ={res,glob A,ChainRedaction.opened,ChainCut.cut,ChainStage.seed,ChainStage.layer,
      ChainStage.tree,ChainStage.kp,ChainStage.index} /\
    chain_visible_agree ChainCut.cut{2} ChainStage.values{1} ChainStage.values{2} /\
    chain_public_agree DualDigest.hidden{2} Independent.rawhistory{1} Independent.rawhistory{2} /\
    chain_private_agree (wots_key ChainStage.layer{2} ChainStage.tree{2} ChainStage.kp{2} ChainStage.index{2})
      Independent.secrethistory{1} Independent.secrethistory{2}].
proof.
  move=> hll.
  proc (ChainGuess.bad)
    (={ChainRedaction.opened,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\
    chain_visible_agree ChainCut.cut{2} ChainStage.values{1} ChainStage.values{2} /\
    chain_public_agree DualDigest.hidden{2} Independent.rawhistory{1} Independent.rawhistory{2} /\
    chain_private_agree (wots_key ChainStage.layer{2} ChainStage.tree{2} ChainStage.kp{2} ChainStage.index{2})
      Independent.secrethistory{1} Independent.secrethistory{2}) true.
  + smt().
  + smt().
  + exact hll.
  + proc*; call chain_public_query_redaction; auto; smt().
  + move=> &2 _; exact independent_hash_ll.
  + move=> &1; exact chain_hybrid_hash_bad_sure.
  + proc*; call chain_private_query_redaction; auto; smt().
  + move=> &2 _; exact redacted_chain_derive_lossless.
  + move=> &1; proc*; call redacted_chain_derive_lossless; auto.
  + proc*; call cached_chain_hybrid_coupling; auto; smt().
  + move=> &2 _; exact redacted_chain_value_lossless.
  + move=> &1; exact cached_hybrid_bad_sure.
qed.

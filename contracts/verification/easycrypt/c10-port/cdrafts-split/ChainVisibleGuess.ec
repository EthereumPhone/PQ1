(* The monitored visible-suffix game is exactly an independent hidden-vector guess. *)
require import AllCore List Distr DList FMap.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen LeafCommitmentHybrid.
require import ChainValueView ChainStageSampling CachedChainOracle DualDigestSampling.
require import RedactedChainOracle ChainPublicHybrid ChainGuessInstrumentation ChainInstrumentationContext.
require import VisibleChainInstallation NodeVectorMass VectorGuessBound.

module VisibleChainCandidates (A : ChainContext) = {
  proc run() : raw_input list = {
    var outputs;
    Independent.init();
    DualDigest.visible <$ dlist full_digest 8;
    VisibleChainInstall.run();
    ChainRedaction.opened <- false;
    outputs <@ A(RedactedCachedChain).run();
    return map leaf_suffix_candidate Independent.queries ++ outputs;
  }
}.
module HybridChainVectorGuess (A : ChainContext) = {
  proc run() : bool = {
    var outputs;
    Independent.init();
    DualDigest.hidden <$ dlist full_digest 8;
    DualDigest.visible <$ dlist full_digest 8;
    VisibleChainInstall.run();
    ChainGuess.bad <- false; ChainRedaction.opened <- false;
    outputs <@ A(HybridCachedChain).run();
    return node_vector_hit DualDigest.hidden outputs;
  }
}.
lemma visible_chain_install_self :
  equiv [VisibleChainInstall.run ~ VisibleChainInstall.run :
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,
      ChainStage.kp,ChainStage.index,DualDigest.visible} ==>
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,
      ChainStage.kp,ChainStage.index,DualDigest.visible,ChainStage.values}].
proof. by sim. qed.

lemma visible_chain_vector_guess_projection
  (A <: ChainContext {-Independent,-ChainStage,-ChainCut,-ChainRedaction,-DualDigest,
    -RedactedCachedChain,-RedactedChainPrefix,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) :
  equiv [HybridChainVectorGuess(A).run ~ IndependentVectorGuess(VisibleChainCandidates(A)).run :
    ={glob A,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} ==>
    (res{1} \/ ChainGuess.bad{1})=res{2}].
proof.
  proc; inline VisibleChainCandidates(A).run; wp.
  swap{1} 1 1.
  seq 1 1 : (={glob A,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\
    DualDigest.hidden{1}=hidden{2}); first by auto.
  exists* DualDigest.hidden{1}; elim* => hidden0.
  call (chain_context_instrumentation A hidden0).
  wp; call visible_chain_install_self.
  rnd; inline Independent.init; auto=> />;
    smt(chain_query_hit_nil chain_query_vector_hit node_vector_hit_cat).
qed.

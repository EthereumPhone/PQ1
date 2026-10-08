(* Complete deterministic installation drops only hidden-prefix entries. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess RawKeygen RawChainTrace WotsReference.
require import ChainStageSampling CachedChainOracle DualDigestSampling ChainVectorInstall.
require import ChainRedactionTables ChainTableInstallation.

module IndexedChainInstall = {
  proc run() : unit = {
    Independent.secrethistory.[wots_key ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index] <-
      selected_digest ChainCut.cut DualDigest.hidden DualDigest.visible 0;
    FullChainStep.run(0);
    FullChainStep.run(1);
    FullChainStep.run(2);
    FullChainStep.run(3);
    FullChainStep.run(4);
    FullChainStep.run(5);
    FullChainStep.run(6);
    ChainVectorInstall.digests <- selected_vector ChainCut.cut DualDigest.hidden DualDigest.visible;
    ChainStage.current <- node (selected_digest ChainCut.cut DualDigest.hidden DualDigest.visible 7);
    ChainStage.step <- 7;
    ChainStage.values <- map node ChainVectorInstall.digests;
  }
}.
module VisibleChainInstall = {
  proc run() : unit = {
    VisibleChainStep.run(0);
    VisibleChainStep.run(1);
    VisibleChainStep.run(2);
    VisibleChainStep.run(3);
    VisibleChainStep.run(4);
    VisibleChainStep.run(5);
    VisibleChainStep.run(6);
    ChainStage.current <- node (nth (nseq 256 false) DualDigest.visible 7);
    ChainStage.step <- 7;
    ChainStage.values <- map node DualDigest.visible;
  }
}.
lemma indexed_chain_install_projection :
  equiv [ChainVectorInstall.run ~ IndexedChainInstall.run :
    ={glob Independent,glob DualDigest,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} ==>
    ={glob Independent,ChainVectorInstall.digests,ChainStage.current,ChainStage.step,ChainStage.values}].
proof.
  by proc; inline FullChainStep.run; auto=> /> &m; rewrite !selected_vector_literal /selected_digest /=.
qed.
lemma visible_chain_installation :
  equiv [IndexedChainInstall.run ~ VisibleChainInstall.run :
    ={glob DualDigest,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\
    size DualDigest.hidden{1}=8 /\ size DualDigest.visible{1}=8 /\
    Independent.rawhistory{1}=empty /\ Independent.rawhistory{2}=empty /\
    Independent.secrethistory{1}=empty /\ Independent.secrethistory{2}=empty ==>
    chain_public_agree DualDigest.hidden{2} Independent.rawhistory{1} Independent.rawhistory{2} /\
    chain_private_agree (wots_key ChainStage.layer{2} ChainStage.tree{2} ChainStage.kp{2} ChainStage.index{2})
      Independent.secrethistory{1} Independent.secrethistory{2} /\
    chain_visible_agree ChainCut.cut{2} ChainStage.values{1} ChainStage.values{2}].
proof.
  proc; wp.
  call chain_step_installation.
  call chain_step_installation.
  call chain_step_installation.
  call chain_step_installation.
  call chain_step_installation.
  call chain_step_installation.
  call chain_step_installation.
  auto=> />; smt(chain_public_empty chain_private_empty chain_private_hidden_update selected_vector_visible).
qed.

(* Installation is deterministic once independent hidden and visible vectors are fixed. *)
require import AllCore List FMap.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen RawChainTrace WotsReference.
require import ChainStageSampling CachedChainOracle DualDigestSampling SeparatedChainVector DigestVectorSampling.

module ChainVectorInstall = {
  var digests : digest list
  proc run() : unit = {
    var d0,d1,d2,d3,d4,d5,d6,d7;
    d0 <- if 0<=ChainCut.cut then nth (nseq 256 false) DualDigest.hidden 0
      else nth (nseq 256 false) DualDigest.visible 0;
    d1 <- if 1<=ChainCut.cut then nth (nseq 256 false) DualDigest.hidden 1
      else nth (nseq 256 false) DualDigest.visible 1;
    d2 <- if 2<=ChainCut.cut then nth (nseq 256 false) DualDigest.hidden 2
      else nth (nseq 256 false) DualDigest.visible 2;
    d3 <- if 3<=ChainCut.cut then nth (nseq 256 false) DualDigest.hidden 3
      else nth (nseq 256 false) DualDigest.visible 3;
    d4 <- if 4<=ChainCut.cut then nth (nseq 256 false) DualDigest.hidden 4
      else nth (nseq 256 false) DualDigest.visible 4;
    d5 <- if 5<=ChainCut.cut then nth (nseq 256 false) DualDigest.hidden 5
      else nth (nseq 256 false) DualDigest.visible 5;
    d6 <- if 6<=ChainCut.cut then nth (nseq 256 false) DualDigest.hidden 6
      else nth (nseq 256 false) DualDigest.visible 6;
    d7 <- if 7<=ChainCut.cut then nth (nseq 256 false) DualDigest.hidden 7
      else nth (nseq 256 false) DualDigest.visible 7;
    digests <- [d0;d1;d2;d3;d4;d5;d6;d7];
    Independent.secrethistory.[wots_key ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index] <- d0;
    Independent.rawhistory.[chain_input ChainStage.seed ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index 0 (node d0)] <- d1;
    Independent.rawhistory.[chain_input ChainStage.seed ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index 1 (node d1)] <- d2;
    Independent.rawhistory.[chain_input ChainStage.seed ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index 2 (node d2)] <- d3;
    Independent.rawhistory.[chain_input ChainStage.seed ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index 3 (node d3)] <- d4;
    Independent.rawhistory.[chain_input ChainStage.seed ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index 4 (node d4)] <- d5;
    Independent.rawhistory.[chain_input ChainStage.seed ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index 5 (node d5)] <- d6;
    Independent.rawhistory.[chain_input ChainStage.seed ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index 6 (node d6)] <- d7;
    ChainStage.current <- node d7; ChainStage.step <- 7;
    ChainStage.values <- map node digests;
  }
}.
module StreamChainVector = {
  proc run() : unit = {
    DualDigest.hidden <@ EightDigests.sample();
    DualDigest.visible <@ EightDigests.sample();
    ChainVectorInstall.run();
  }
}.
module ListChainVector = {
  proc run() : unit = {
    DualDigest.hidden <@ ListEightDigests.sample();
    DualDigest.visible <@ ListEightDigests.sample();
    ChainVectorInstall.run();
  }
}.
lemma stream_chain_vector_projection :
  equiv [SeparatedChainVector.run ~ StreamChainVector.run :
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} ==>
    ={glob Independent,ChainStage.current,ChainStage.step,ChainStage.values,glob DualDigest} /\
    SeparatedChainVector.digests{1}=ChainVectorInstall.digests{2}].
proof. proc; inline EightDigests.sample ChainVectorInstall.run; auto=> />. qed.
lemma list_chain_vector_projection :
  equiv [StreamChainVector.run ~ ListChainVector.run :
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} ==>
    ={glob Independent,ChainStage.current,ChainStage.step,ChainStage.values,glob DualDigest,ChainVectorInstall.digests}].
proof.
  proc; call (_ : ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,
    ChainStage.kp,ChainStage.index,glob DualDigest} ==>
    ={glob Independent,ChainStage.current,ChainStage.step,ChainStage.values,glob DualDigest,ChainVectorInstall.digests}); first by sim.
  call eight_digests_list; call eight_digests_list; auto.
qed.

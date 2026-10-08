(* All hidden draws can precede the independent visible stream before programming. *)
require import AllCore List FMap.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen RawChainTrace WotsReference.
require import ChainStageSampling CachedChainOracle DualDigestSampling DualChainVector.

module SeparatedChainVector = {
  var digests : digest list
  proc run() : unit = {
    var d0,d1,d2,d3,d4,d5,d6,d7;
    var h0,h1,h2,h3,h4,h5,h6,h7,v0,v1,v2,v3,v4,v5,v6,v7;
    h0 <$ full_digest;
    h1 <$ full_digest;
    h2 <$ full_digest;
    h3 <$ full_digest;
    h4 <$ full_digest;
    h5 <$ full_digest;
    h6 <$ full_digest;
    h7 <$ full_digest;
    v0 <$ full_digest;
    v1 <$ full_digest;
    v2 <$ full_digest;
    v3 <$ full_digest;
    v4 <$ full_digest;
    v5 <$ full_digest;
    v6 <$ full_digest;
    v7 <$ full_digest;
    DualDigest.hidden <- [h0;h1;h2;h3;h4;h5;h6;h7];
    DualDigest.visible <- [v0;v1;v2;v3;v4;v5;v6;v7];
    d0 <- if 0<=ChainCut.cut then h0 else v0;
    d1 <- if 1<=ChainCut.cut then h1 else v1;
    d2 <- if 2<=ChainCut.cut then h2 else v2;
    d3 <- if 3<=ChainCut.cut then h3 else v3;
    d4 <- if 4<=ChainCut.cut then h4 else v4;
    d5 <- if 5<=ChainCut.cut then h5 else v5;
    d6 <- if 6<=ChainCut.cut then h6 else v6;
    d7 <- if 7<=ChainCut.cut then h7 else v7;
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
lemma separated_chain_vector_projection :
  equiv [DualChainVectorProgram.run ~ SeparatedChainVector.run :
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} ==>
    ={glob Independent,ChainStage.current,ChainStage.step,ChainStage.values,glob DualDigest} /\
    DualChainVectorProgram.digests{1}=SeparatedChainVector.digests{2}].
proof.
  proc; inline DualDigest.draw.
  swap{2} 9 -7.
  swap{2} 10 -6.
  swap{2} 11 -5.
  swap{2} 12 -4.
  swap{2} 13 -3.
  swap{2} 14 -2.
  swap{2} 15 -1.
  auto=> />.
qed.

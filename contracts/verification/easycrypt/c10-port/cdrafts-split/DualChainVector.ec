(* Independent hidden and visible streams realize the same programmed chain. *)
require import AllCore List FMap.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen RawChainTrace WotsReference.
require import ChainStageSampling CachedChainOracle ChainVectorProgram DualDigestSampling.

module DualChainVectorProgram = {
  var digests : digest list
  proc run() : unit = {
    var d0,d1,d2,d3,d4,d5,d6,d7;
    DualDigest.hidden <- []; DualDigest.visible <- [];
    d0 <@ DualDigest.draw(0<=ChainCut.cut);
    d1 <@ DualDigest.draw(1<=ChainCut.cut);
    d2 <@ DualDigest.draw(2<=ChainCut.cut);
    d3 <@ DualDigest.draw(3<=ChainCut.cut);
    d4 <@ DualDigest.draw(4<=ChainCut.cut);
    d5 <@ DualDigest.draw(5<=ChainCut.cut);
    d6 <@ DualDigest.draw(6<=ChainCut.cut);
    d7 <@ DualDigest.draw(7<=ChainCut.cut);
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
module CalledChainVectorProgram = {
  var digests : digest list
  proc run() : unit = {
    var d0,d1,d2,d3,d4,d5,d6,d7;
    d0 <@ FullDigestDraw.sample();
    d1 <@ FullDigestDraw.sample();
    d2 <@ FullDigestDraw.sample();
    d3 <@ FullDigestDraw.sample();
    d4 <@ FullDigestDraw.sample();
    d5 <@ FullDigestDraw.sample();
    d6 <@ FullDigestDraw.sample();
    d7 <@ FullDigestDraw.sample();
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
lemma called_chain_vector_projection :
  equiv [ChainVectorProgram.run ~ CalledChainVectorProgram.run :
    ={glob Independent,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} ==>
    ={glob Independent,ChainStage.current,ChainStage.step,ChainStage.values} /\
    ChainVectorProgram.digests{1}=CalledChainVectorProgram.digests{2}].
proof. proc; inline FullDigestDraw.sample; auto=> />. qed.

lemma called_dual_chain_vector_projection :
  equiv [CalledChainVectorProgram.run ~ DualChainVectorProgram.run :
    ={glob Independent,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} ==>
    ={glob Independent,ChainStage.current,ChainStage.step,ChainStage.values} /\
    CalledChainVectorProgram.digests{1}=DualChainVectorProgram.digests{2}].
proof.
  proc; wp.
  call dual_digest_projection.
  call dual_digest_projection.
  call dual_digest_projection.
  call dual_digest_projection.
  call dual_digest_projection.
  call dual_digest_projection.
  call dual_digest_projection.
  call dual_digest_projection.
  auto=> />.
qed.

(* Eight independent full digests give an explicit, straight-line chain-table program. *)
require import AllCore List FMap.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen RawChainTrace WotsReference.
require import ChainStageSampling ProgrammedChain.

module ChainVectorProgram = {
  var digests : digest list
  proc run() : unit = {
    var d0,d1,d2,d3,d4,d5,d6,d7;
    d0 <$ full_digest;
    d1 <$ full_digest;
    d2 <$ full_digest;
    d3 <$ full_digest;
    d4 <$ full_digest;
    d5 <$ full_digest;
    d6 <$ full_digest;
    d7 <$ full_digest;
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
lemma programmed_chain_vector :
  equiv [ProgrammedChain.sample ~ ChainVectorProgram.run :
    ={glob Independent,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} ==>
    ={glob Independent,ChainStage.current,ChainStage.step,ChainStage.values} /\
    ProgrammedChain.digests{1}=ChainVectorProgram.digests{2}].
proof. proc; inline ProgrammedChain.start ProgrammedChain.advance; auto=> />. qed.

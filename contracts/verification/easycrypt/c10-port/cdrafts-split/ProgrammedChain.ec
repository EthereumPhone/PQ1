(* An explicit vector of independent full digests programs the selected chain. *)
require import AllCore List FMap.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen RawChainTrace WotsReference.
require import ChainStageSampling ChainStartSampling ChainReferenceSampling ChainInputSeparation.
require import PrivateValueSampling PublicTargetSampling.

module ProgrammedChain = {
  var digests : digest list
  proc start() : unit = {
    var d;
    d <$ full_digest;
    Independent.secrethistory.[wots_key ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index] <- d;
    ChainStage.current <- node d; ChainStage.step <- 0;
    ChainStage.values <- [ChainStage.current]; digests <- [d];
  }
  proc advance() : unit = {
    var d;
    d <$ full_digest;
    Independent.rawhistory.[chain_input ChainStage.seed ChainStage.layer ChainStage.tree ChainStage.kp
      ChainStage.index ChainStage.step ChainStage.current] <- d;
    ChainStage.current <- node d; ChainStage.step <- ChainStage.step+1;
    ChainStage.values <- rcons ChainStage.values ChainStage.current;
    digests <- rcons digests d;
  }
  proc sample() : unit = {
    start(); advance(); advance(); advance(); advance(); advance(); advance(); advance();
  }
}.

lemma programmed_chain_start :
  equiv [ChainStart.initialize ~ ProgrammedChain.start :
    ={glob Independent,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\
    Independent.secrethistory{1}=empty ==>
    ={glob Independent,ChainStage.current,ChainStage.step,ChainStage.values} /\ ChainStage.step{1}=0].
proof.
  proc; inline PrivateValueSample.sample PrivateMemoSample.get; sp.
  rcondt{1} 1; first auto; smt(mem_empty).
  auto; smt(get_set_sameE).
qed.

lemma programmed_chain_stage n :
  0<=n<7 =>
  equiv [ChainStage.advance ~ ProgrammedChain.advance :
    ={glob Independent,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,
      ChainStage.current,ChainStage.step,ChainStage.values} /\ ChainStage.step{1}=n /\
    chain_steps_before Independent.rawhistory{1} ChainStage.seed{1} ChainStage.layer{1}
      ChainStage.tree{1} ChainStage.kp{1} ChainStage.index{1} n ==>
    ={glob Independent,ChainStage.current,ChainStage.step,ChainStage.values} /\ ChainStage.step{1}=n+1 /\
    chain_steps_before Independent.rawhistory{1} ChainStage.seed{1} ChainStage.layer{1}
      ChainStage.tree{1} ChainStage.kp{1} ChainStage.index{1} (n+1)].
proof.
  move=> hn; proc; inline PublicTargetSample.sample PublicMemoSample.get; sp.
  rcondt{1} 1; first auto; smt(chain_next_fresh).
  auto; smt(get_set_sameE chain_steps_insert).
qed.

lemma programmed_chain_complete :
  equiv [CompleteChainCache.sample ~ ProgrammedChain.sample :
    ={glob Independent,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\
    Independent.rawhistory{1}=empty /\ Independent.secrethistory{1}=empty ==>
    ={glob Independent,ChainStage.current,ChainStage.step,ChainStage.values} /\ ChainStage.step{1}=7].
proof.
  have hn0 : 0<=0<7 by smt().
  have hn1 : 0<=1<7 by smt().
  have hn2 : 0<=2<7 by smt().
  have hn3 : 0<=3<7 by smt().
  have hn4 : 0<=4<7 by smt().
  have hn5 : 0<=5<7 by smt().
  have hn6 : 0<=6<7 by smt().
  proc.
  call (programmed_chain_stage 6 hn6).
  call (programmed_chain_stage 5 hn5).
  call (programmed_chain_stage 4 hn4).
  call (programmed_chain_stage 3 hn3).
  call (programmed_chain_stage 2 hn2).
  call (programmed_chain_stage 1 hn1).
  call (programmed_chain_stage 0 hn0).
  call programmed_chain_start; auto=> />; smt(chain_steps_empty).
qed.

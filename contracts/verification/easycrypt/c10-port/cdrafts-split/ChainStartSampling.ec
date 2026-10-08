(* Sample the selected private start before or after an adaptive computation. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen WotsReference.
require import PrivateValueSampling PrivateValueContext ChainStageSampling.
module ChainStart = {
  proc initialize() : unit = {
    PrivateValueSample.target <- wots_key ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index;
    PrivateValueSample.sample();
    ChainStage.current <- node PrivateValueSample.value;
    ChainStage.step <- 0;
    ChainStage.values <- [ChainStage.current];
  }
}.
lemma chain_start_sample_hash :
  eager [ChainStart.initialize();, SamplingOracle.hash ~ SamplingOracle.hash, ChainStart.initialize(); :
    ={arg,glob Independent,glob PrivateValueSample,glob ChainStage} ==>
    ={res,glob Independent,glob PrivateValueSample,glob ChainStage}].
proof.
  eager proc; inline ChainStart.initialize.
  swap{1} [3..5] 1.
  swap{2} 3 -2.
  swap{2} 3 4.
  wp.
  seq 1 1 : (={x,glob Independent,glob PrivateValueSample,glob ChainStage}); first auto.
  eager call private_value_sample_hash; auto.
qed.

lemma chain_start_sample_derive :
  eager [ChainStart.initialize();, SamplingOracle.derive ~ SamplingOracle.derive, ChainStart.initialize(); :
    ={arg,glob Independent,glob PrivateValueSample,glob ChainStage} ==>
    ={res,glob Independent,glob PrivateValueSample,glob ChainStage}].
proof.
  eager proc; inline ChainStart.initialize.
  swap{1} [3..5] 1.
  swap{2} 3 -2.
  swap{2} 3 4.
  wp.
  seq 1 1 : (={tail,glob Independent,glob PrivateValueSample,glob ChainStage}); first auto.
  eager call private_value_sample_derive; auto.
qed.

lemma chain_start_sample_context
  (A <: PrefixContext {-Independent,-PrivateMemoSample,-PrivateValueSample,-ChainStage,-SamplingOracle}) :
  eager [ChainStart.initialize();, A(SamplingOracle).run ~ A(SamplingOracle).run, ChainStart.initialize(); :
    ={glob A,glob Independent,glob PrivateValueSample,glob ChainStage} ==>
    ={res,glob A,glob Independent,glob PrivateValueSample,glob ChainStage}].
proof.
  eager proc (={glob Independent,glob PrivateValueSample,glob ChainStage}) => //; try by sim.
  + apply chain_start_sample_hash.
  apply chain_start_sample_derive.
qed.


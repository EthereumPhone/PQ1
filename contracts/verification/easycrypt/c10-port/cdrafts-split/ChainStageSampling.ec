(* Silent precomputation of one selected chain stage commutes with an adaptive context. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen RawChainTrace.
require import PublicTargetSampling PublicSamplingContext.

module SamplingOracle = {
  proc hash(x : raw_input) : digest = {
    var y; y <@ Independent.hash(x); return y;
  }
  proc derive(tail : raw_input) : digest = {
    var y; y <@ Independent.derive(tail); return y;
  }
}.
module ChainStage = {
  var seed : raw_input
  var layer, tree, kp, index, step : int
  var current : raw_input
  var values : raw_input list
  proc advance() : unit = {
    PublicTargetSample.target <- chain_input seed layer tree kp index step current;
    PublicTargetSample.sample();
    current <- node PublicTargetSample.value;
    step <- step+1;
    values <- rcons values current;
  }
}.

lemma chain_stage_sample_hash :
  eager [ChainStage.advance();, SamplingOracle.hash ~ SamplingOracle.hash, ChainStage.advance(); :
    ={arg,glob Independent,glob PublicTargetSample,glob ChainStage} ==>
    ={res,glob Independent,glob PublicTargetSample,glob ChainStage}].
proof.
  eager proc; inline ChainStage.advance.
  swap{1} [3..5] 1.
  swap{2} 3 -2.
  swap{2} 3 4.
  wp.
  seq 1 1 : (={x,glob Independent,glob PublicTargetSample,glob ChainStage}); first auto.
  eager call public_target_sample_hash; auto.
qed.

lemma chain_stage_sample_derive :
  eager [ChainStage.advance();, SamplingOracle.derive ~ SamplingOracle.derive, ChainStage.advance(); :
    ={arg,glob Independent,glob PublicTargetSample,glob ChainStage} ==>
    ={res,glob Independent,glob PublicTargetSample,glob ChainStage}].
proof.
  eager proc; inline ChainStage.advance.
  swap{1} [3..5] 1.
  swap{2} 3 -2.
  swap{2} 3 4.
  wp.
  seq 1 1 : (={tail,glob Independent,glob PublicTargetSample,glob ChainStage}); first auto.
  eager call public_target_sample_derive; auto.
qed.

lemma chain_stage_sample_context
  (A <: PrefixContext {-Independent,-PublicMemoSample,-PublicTargetSample,-ChainStage,-SamplingOracle}) :
  eager [ChainStage.advance();, A(SamplingOracle).run ~ A(SamplingOracle).run, ChainStage.advance(); :
    ={glob A,glob Independent,glob PublicTargetSample,glob ChainStage} ==>
    ={res,glob A,glob Independent,glob PublicTargetSample,glob ChainStage}].
proof.
  eager proc (={glob Independent,glob PublicTargetSample,glob ChainStage}) => //; try by sim.
  + apply chain_stage_sample_hash.
  apply chain_stage_sample_derive.
qed.

lemma sampling_oracle_context_projection
  (A <: PrefixContext {-Independent}) :
  equiv [A(Independent).run ~ A(SamplingOracle).run :
    ={glob A,glob Independent} ==> ={res,glob A,glob Independent}].
proof. proc (={glob Independent}) => //; proc; inline *; sp; if; auto; smt(). qed.

(* Seven selected chain stages may be computed before or after the same adaptive run. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PublicTargetSampling ChainStageSampling.

module ChainSamplingOrder (A : PrefixContext) = {
  proc run0() : bool = {
    var result;
    result <@ A(SamplingOracle).run();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    return result;
  }
  proc run1() : bool = {
    var result;
    ChainStage.advance();
    result <@ A(SamplingOracle).run();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    return result;
  }
  proc run2() : bool = {
    var result;
    ChainStage.advance();
    ChainStage.advance();
    result <@ A(SamplingOracle).run();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    return result;
  }
  proc run3() : bool = {
    var result;
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    result <@ A(SamplingOracle).run();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    return result;
  }
  proc run4() : bool = {
    var result;
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    result <@ A(SamplingOracle).run();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    return result;
  }
  proc run5() : bool = {
    var result;
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    result <@ A(SamplingOracle).run();
    ChainStage.advance();
    ChainStage.advance();
    return result;
  }
  proc run6() : bool = {
    var result;
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    result <@ A(SamplingOracle).run();
    ChainStage.advance();
    return result;
  }
  proc run7() : bool = {
    var result;
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    result <@ A(SamplingOracle).run();
    return result;
  }
}.

lemma chain_sampling_move_1
  (A <: PrefixContext {-Independent,-PublicMemoSample,-PublicTargetSample,-ChainStage,-SamplingOracle}) :
  equiv [ChainSamplingOrder(A).run1 ~ ChainSamplingOrder(A).run0 :
    ={glob A,glob Independent,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PublicTargetSample,glob ChainStage}].
proof.
  proc; wp.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  eager call (chain_stage_sample_context A); auto.
qed.

lemma chain_sampling_move_2
  (A <: PrefixContext {-Independent,-PublicMemoSample,-PublicTargetSample,-ChainStage,-SamplingOracle}) :
  equiv [ChainSamplingOrder(A).run2 ~ ChainSamplingOrder(A).run1 :
    ={glob A,glob Independent,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PublicTargetSample,glob ChainStage}].
proof.
  proc; wp.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  seq 1 1 : (={glob A,glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  eager call (chain_stage_sample_context A); auto.
qed.

lemma chain_sampling_move_3
  (A <: PrefixContext {-Independent,-PublicMemoSample,-PublicTargetSample,-ChainStage,-SamplingOracle}) :
  equiv [ChainSamplingOrder(A).run3 ~ ChainSamplingOrder(A).run2 :
    ={glob A,glob Independent,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PublicTargetSample,glob ChainStage}].
proof.
  proc; wp.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  seq 2 2 : (={glob A,glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  eager call (chain_stage_sample_context A); auto.
qed.

lemma chain_sampling_move_4
  (A <: PrefixContext {-Independent,-PublicMemoSample,-PublicTargetSample,-ChainStage,-SamplingOracle}) :
  equiv [ChainSamplingOrder(A).run4 ~ ChainSamplingOrder(A).run3 :
    ={glob A,glob Independent,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PublicTargetSample,glob ChainStage}].
proof.
  proc; wp.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  seq 3 3 : (={glob A,glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  eager call (chain_stage_sample_context A); auto.
qed.

lemma chain_sampling_move_5
  (A <: PrefixContext {-Independent,-PublicMemoSample,-PublicTargetSample,-ChainStage,-SamplingOracle}) :
  equiv [ChainSamplingOrder(A).run5 ~ ChainSamplingOrder(A).run4 :
    ={glob A,glob Independent,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PublicTargetSample,glob ChainStage}].
proof.
  proc; wp.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  seq 4 4 : (={glob A,glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  eager call (chain_stage_sample_context A); auto.
qed.

lemma chain_sampling_move_6
  (A <: PrefixContext {-Independent,-PublicMemoSample,-PublicTargetSample,-ChainStage,-SamplingOracle}) :
  equiv [ChainSamplingOrder(A).run6 ~ ChainSamplingOrder(A).run5 :
    ={glob A,glob Independent,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PublicTargetSample,glob ChainStage}].
proof.
  proc; wp.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  seq 5 5 : (={glob A,glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  eager call (chain_stage_sample_context A); auto.
qed.

lemma chain_sampling_move_7
  (A <: PrefixContext {-Independent,-PublicMemoSample,-PublicTargetSample,-ChainStage,-SamplingOracle}) :
  equiv [ChainSamplingOrder(A).run7 ~ ChainSamplingOrder(A).run6 :
    ={glob A,glob Independent,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PublicTargetSample,glob ChainStage}].
proof.
  proc; wp.
  seq 6 6 : (={glob A,glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  eager call (chain_stage_sample_context A); auto.
qed.

lemma chain_sampling_early_late
  (A <: PrefixContext {-Independent,-PublicMemoSample,-PublicTargetSample,-ChainStage,-SamplingOracle}) :
  equiv [ChainSamplingOrder(A).run7 ~ ChainSamplingOrder(A).run0 :
    ={glob A,glob Independent,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PublicTargetSample,glob ChainStage}].
proof.
  transitivity ChainSamplingOrder(A).run6
    (={glob A,glob Independent,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PublicTargetSample,glob ChainStage})
    (={glob A,glob Independent,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PublicTargetSample,glob ChainStage}) => //.
  + smt().
  + conseq (chain_sampling_move_7 A); smt().
  transitivity ChainSamplingOrder(A).run5
    (={glob A,glob Independent,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PublicTargetSample,glob ChainStage})
    (={glob A,glob Independent,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PublicTargetSample,glob ChainStage}) => //.
  + smt().
  + conseq (chain_sampling_move_6 A); smt().
  transitivity ChainSamplingOrder(A).run4
    (={glob A,glob Independent,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PublicTargetSample,glob ChainStage})
    (={glob A,glob Independent,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PublicTargetSample,glob ChainStage}) => //.
  + smt().
  + conseq (chain_sampling_move_5 A); smt().
  transitivity ChainSamplingOrder(A).run3
    (={glob A,glob Independent,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PublicTargetSample,glob ChainStage})
    (={glob A,glob Independent,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PublicTargetSample,glob ChainStage}) => //.
  + smt().
  + conseq (chain_sampling_move_4 A); smt().
  transitivity ChainSamplingOrder(A).run2
    (={glob A,glob Independent,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PublicTargetSample,glob ChainStage})
    (={glob A,glob Independent,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PublicTargetSample,glob ChainStage}) => //.
  + smt().
  + conseq (chain_sampling_move_3 A); smt().
  transitivity ChainSamplingOrder(A).run1
    (={glob A,glob Independent,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PublicTargetSample,glob ChainStage})
    (={glob A,glob Independent,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PublicTargetSample,glob ChainStage}) => //.
  + smt().
  + conseq (chain_sampling_move_2 A); smt().
  conseq (chain_sampling_move_1 A); smt().
qed.

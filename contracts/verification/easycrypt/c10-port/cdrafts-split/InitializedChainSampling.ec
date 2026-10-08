(* Initialization and all seven selected stages commute with the unchanged context. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid.
require import PublicTargetSampling PrivateValueSampling ChainStageSampling ChainStartSampling ChainSamplingOrder.
module InitializedChainSampling (A : PrefixContext) = {
  proc early() : bool = {
    var result; Independent.init(); ChainStart.initialize();
    result <@ ChainSamplingOrder(A).run7(); return result;
  }
  proc middle() : bool = {
    var result; Independent.init(); ChainStart.initialize();
    result <@ ChainSamplingOrder(A).run0(); return result;
  }
  proc late() : bool = {
    var result; Independent.init(); result <@ A(SamplingOracle).run(); ChainStart.initialize();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    ChainStage.advance();
    return result;
  }
}.
lemma chain_sampling_early_middle
  (A <: PrefixContext {-Independent,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,-ChainStage,-SamplingOracle}) :
  equiv [InitializedChainSampling(A).early ~ InitializedChainSampling(A).middle :
    ={glob A,glob Independent,glob PrivateValueSample,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PrivateValueSample,glob PublicTargetSample,glob ChainStage}].
proof.
  proc; call (chain_sampling_early_late A).
  call (_ : ={glob A,glob Independent,glob PrivateValueSample,glob PublicTargetSample,glob ChainStage}); first by sim.
  inline Independent.init; auto.
qed.
lemma chain_sampling_middle_late
  (A <: PrefixContext {-Independent,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,-ChainStage,-SamplingOracle}) :
  equiv [InitializedChainSampling(A).middle ~ InitializedChainSampling(A).late :
    ={glob A,glob Independent,glob PrivateValueSample,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PrivateValueSample,glob PublicTargetSample,glob ChainStage}].
proof.
  proc; inline ChainSamplingOrder(A).run0; wp.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  call (_ : ={glob Independent,glob PublicTargetSample,glob ChainStage}); first by sim.
  seq 1 1 : (={glob A,glob Independent,glob PrivateValueSample,glob PublicTargetSample,glob ChainStage}); first by inline Independent.init; auto.
  eager call (chain_start_sample_context A); auto.
qed.
lemma initialized_chain_sampling_early_late
  (A <: PrefixContext {-Independent,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,-ChainStage,-SamplingOracle}) :
  equiv [InitializedChainSampling(A).early ~ InitializedChainSampling(A).late :
    ={glob A,glob Independent,glob PrivateValueSample,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PrivateValueSample,glob PublicTargetSample,glob ChainStage}].
proof.
  transitivity InitializedChainSampling(A).middle
    (={glob A,glob Independent,glob PrivateValueSample,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PrivateValueSample,glob PublicTargetSample,glob ChainStage})
    (={glob A,glob Independent,glob PrivateValueSample,glob PublicTargetSample,glob ChainStage} ==> ={res,glob A,glob Independent,glob PrivateValueSample,glob PublicTargetSample,glob ChainStage}) => //.
  + smt().
  + conseq (chain_sampling_early_middle A); smt().
  conseq (chain_sampling_middle_late A); smt().
qed.

(* Early/late selected-entry sampling for a passively observed adaptive context. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen.
require import PrivateTargetSampling LeafCommitmentHybrid LeafCommitmentBound TargetOracleSplit TargetPrivateBound.
require import TargetTableProjection.

module ObservedCandidates (A : TargetContext) (O : PrefixOracle) = {
  proc run() : raw_input list = {
    var outputs; outputs <@ A(ObservedTarget(O)).run(); return outputs;
  }
}.
lemma private_target_sample_list_context
  (A <: LeafCommitmentContext {-Independent,-PrivateTargetSample}) :
  eager [PrivateTargetSample.sample();, A(Independent).run ~ A(Independent).run, PrivateTargetSample.sample(); :
    ={glob A,glob Independent,PrivateTargetSample.target} ==>
    ={res,glob A,glob Independent,PrivateTargetSample.target}].
proof.
  eager proc (={glob Independent,PrivateTargetSample.target}) => //; try by sim.
  + apply private_target_sample_hash.
  apply private_target_sample_derive.
qed.
module EarlyTargetCandidates (A : TargetContext) = {
  proc run() : raw_input list = {
    var outputs;
    Independent.init(); OriginalTargetState.revealed <- false;
    PrivateTargetSample.target <- TargetConfig.input;
    PrivateTargetSample.sample();
    outputs <@ ObservedCandidates(A,Independent).run(); return outputs;
  }
}.
module LateTargetCandidates (A : TargetContext) = {
  proc run() : raw_input list = {
    var outputs;
    Independent.init(); OriginalTargetState.revealed <- false;
    PrivateTargetSample.target <- TargetConfig.input;
    outputs <@ ObservedCandidates(A,Independent).run();
    PrivateTargetSample.sample(); return outputs;
  }
}.
lemma observed_target_sampling
  (A <: TargetContext {-Independent,-PrivateTargetSample,-OriginalTargetState,-TargetConfig}) :
  equiv [EarlyTargetCandidates(A).run ~ LateTargetCandidates(A).run :
    ={glob A,glob TargetConfig} ==>
    ={res,glob A,glob TargetConfig,glob Independent,glob OriginalTargetState}].
proof.
  proc; seq 3 3 : (={glob A,glob TargetConfig,glob Independent,glob OriginalTargetState,PrivateTargetSample.target});
    first by inline *; auto.
  eager call (private_target_sample_list_context (ObservedCandidates(A))); auto.
qed.

op observed_private_guess (private : (raw_input,digest) fmap) (target : raw_input) outputs =
  target \in private /\ mem outputs (node (oget private.[target])).
module EarlyObservedPrivateGuess (A : TargetContext) = {
  proc run() : bool = {
    var outputs; outputs <@ EarlyTargetCandidates(A).run();
    return !OriginalTargetState.revealed /\
      observed_private_guess Independent.secrethistory TargetConfig.input outputs;
  }
}.
module LateObservedPrivateGuess (A : TargetContext) = {
  proc run() : bool = {
    var outputs; outputs <@ LateTargetCandidates(A).run();
    return !OriginalTargetState.revealed /\
      observed_private_guess Independent.secrethistory TargetConfig.input outputs;
  }
}.
module OriginalObservedPrivateGuess (A : TargetContext) = {
  proc run() : bool = {
    var outputs;
    Independent.init(); OriginalTargetState.revealed <- false;
    outputs <@ ObservedCandidates(A,Independent).run();
    return !OriginalTargetState.revealed /\
      observed_private_guess Independent.secrethistory TargetConfig.input outputs;
  }
}.
lemma observed_private_guess_early_late
  (A <: TargetContext {-Independent,-PrivateTargetSample,-OriginalTargetState,-TargetConfig}) :
  equiv [EarlyObservedPrivateGuess(A).run ~ LateObservedPrivateGuess(A).run :
    ={glob A,glob TargetConfig} ==> ={res,glob A,glob TargetConfig}].
proof. proc; call (observed_target_sampling A); auto; smt(). qed.

lemma original_private_guess_late
  (A <: TargetContext {-Independent,-PrivateTargetSample,-OriginalTargetState,-TargetConfig}) :
  equiv [OriginalObservedPrivateGuess(A).run ~ LateObservedPrivateGuess(A).run :
    ={glob A,glob TargetConfig} ==> res{1} => res{2}].
proof.
  proc; inline LateTargetCandidates(A).run.
  seq 3 4 : (={glob A,glob TargetConfig,glob Independent,glob OriginalTargetState} /\
    outputs{1}=outputs0{2} /\
    PrivateTargetSample.target{2}=TargetConfig.input{2}).
  + call (_ : ={glob A,glob Independent,glob OriginalTargetState,glob TargetConfig}); first by sim.
    inline Independent.init; auto.
  inline PrivateTargetSample.sample Independent.derive.
  sp; if{2}; auto; rewrite /observed_private_guess; smt(full_digest_ll domE).
qed.

lemma early_private_guess_projection
  (A <: TargetContext {-Independent,-Shared,-OtherPrivate,-RealTargetPrivate,
    -RealTargetOracle,-OriginalTargetState,-TargetConfig,-PrivateTargetSample}) :
  equiv [EarlyObservedPrivateGuess(A).run ~ SelectivePrivateGuess(A).run :
    ={glob A,glob TargetConfig} ==> ={res,glob A,glob TargetConfig}].
proof.
  proc; inline EarlyTargetCandidates(A).run ObservedCandidates(A,Independent).run.
  wp; call (observed_target_context_projection A).
  inline Independent.init PrivateTargetSample.sample Independent.derive Shared.init.
  sp; if{1}; auto; rewrite /selected_table /observed_private_guess;
    smt(get_setE domE).
qed.

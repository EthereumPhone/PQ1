(* Sampling one private table entry before an adaptive context. Both oracle
   tables and the target are explicitly outside the context's global state. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid.

module PrivateTargetSample = {
  var target : raw_input
  proc sample() : unit = {
    var ignored;
    ignored <@ Independent.derive(target);
  }
}.
lemma private_target_sample_hash :
  eager [PrivateTargetSample.sample();, Independent.hash ~ Independent.hash, PrivateTargetSample.sample(); :
    ={arg,glob Independent,PrivateTargetSample.target} ==>
    ={res,glob Independent,PrivateTargetSample.target}].
proof.
  eager proc; inline *.
  swap{1} [1..3] 3.
  sim.
qed.
lemma private_target_sample_derive :
  eager [PrivateTargetSample.sample();, Independent.derive ~ Independent.derive, PrivateTargetSample.sample(); :
    ={arg,glob Independent,PrivateTargetSample.target} ==>
    ={res,glob Independent,PrivateTargetSample.target}].
proof.
  eager proc; inline *.
  case (tail{1}=PrivateTargetSample.target{1}).
  + sp 1 0; if{1}.
    - rcondt{2} 1; first by auto; smt().
      seq 2 2 : (={glob Independent,PrivateTargetSample.target,tail} /\ tail{1} \in Independent.secrethistory{1} /\ tail{1}=PrivateTargetSample.target{1}).
      * auto; smt(mem_set).
      rcondf{1} 2; first by auto; smt().
      rcondf{2} 3; first by auto; smt().
      auto; smt().
    rcondf{2} 1; first by auto; smt().
    rcondf{1} 2; first by auto; smt().
    rcondf{2} 3; first by auto; smt().
    auto; smt().
  case (PrivateTargetSample.target{1} \in Independent.secrethistory{1});
    case (tail{1} \in Independent.secrethistory{1}).
  + rcondf{1} 2; first by auto.
    rcondf{1} 3; first by auto.
    rcondf{2} 1; first by auto.
    rcondf{2} 3; first by auto.
    auto; smt().
  + rcondf{1} 2; first by auto.
    rcondt{1} 3; first by auto.
    rcondt{2} 1; first by auto.
    rcondf{2} 5; first by auto; smt(mem_set).
    auto; smt().
  + rcondt{1} 2; first by auto.
    rcondf{1} 5; first by auto; smt(mem_set).
    rcondf{2} 1; first by auto.
    rcondt{2} 3; first by auto.
    auto; smt(get_setE).
  rcondt{1} 2; first by auto.
  rcondt{1} 5; first by auto; smt(mem_set).
  rcondt{2} 1; first by auto.
  rcondt{2} 5; first by auto; smt(mem_set).
  sp 1 0; swap{1} 4 -2; swap{2} 5 -4.
  auto; smt(get_setE set_set_neqE).
qed.

lemma private_target_sample_context
  (A <: PrefixContext {-Independent,-PrivateTargetSample}) :
  eager [PrivateTargetSample.sample();, A(Independent).run ~ A(Independent).run, PrivateTargetSample.sample(); :
    ={glob A,glob Independent,PrivateTargetSample.target} ==>
    ={res,glob A,glob Independent,PrivateTargetSample.target}].
proof.
  eager proc (={glob Independent,PrivateTargetSample.target}) => //; try by sim.
  + apply private_target_sample_hash.
  apply private_target_sample_derive.
qed.
module EarlyPrivateTarget (A : PrefixContext) = {
  proc run() : bool = {
    var result;
    Independent.init(); PrivateTargetSample.sample();
    result <@ A(Independent).run(); return result;
  }
}.
module LatePrivateTarget (A : PrefixContext) = {
  proc run() : bool = {
    var result;
    Independent.init(); result <@ A(Independent).run();
    PrivateTargetSample.sample(); return result;
  }
}.
lemma initialized_private_target_sampling
  (A <: PrefixContext {-Independent,-PrivateTargetSample}) :
  equiv [EarlyPrivateTarget(A).run ~ LatePrivateTarget(A).run :
    ={glob A,PrivateTargetSample.target} ==>
    ={res,glob A,glob Independent,PrivateTargetSample.target}].
proof.
  proc; seq 1 1 : (={glob A,glob Independent,PrivateTargetSample.target}); first by inline *; auto.
  eager call (private_target_sample_context A); auto.
qed.

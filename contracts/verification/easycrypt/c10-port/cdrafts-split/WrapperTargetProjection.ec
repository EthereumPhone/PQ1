(* Passive target observation preserves the public-plan and release routines.
   The selected value itself remains private observer state. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawSigner.
require import ForsPrivateLeaves ForsLeafView TargetOracleSplit TargetByteView TargetTableProjection.
require import WrapperSigningPlan WrapperPlanSigner WrapperReleasedFors WrapperOpeningFrames.

module type WrapperTargetPlan (O : TargetOracle) = {
  proc sign(seed root random message shuffle : raw_input) : wrapper_signature_plan option
    {O.hash,O.derive,O.leaf,O.secret}
}.
module type WrapperTargetSigning (O : TargetOracle) = {
  proc sign(seed root random message shuffle_a shuffle_b : raw_input,
    ready final_guard : bool) : raw_signature option {O.hash,O.derive,O.leaf,O.secret}
}.
module TargetWrapperReleased (O : TargetOracle) = WrapperReleasedFors(TargetPrefix(O),TargetLeaf(O)).

lemma wrapper_observed_derive_projection :
  equiv [ConcreteTarget(Independent).derive ~ ObservedTarget(Independent).derive :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  proc*; inline ObservedTarget(Independent).derive; wp.
  call (_ : ={glob Independent}); first by sim.
  auto.
qed.

lemma wrapper_observed_secret_projection :
  equiv [ConcreteTarget(Independent).secret ~ ObservedTarget(Independent).secret :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  proc; inline ObservedTarget(Independent).derive PreparationView(Independent).fors.
  wp; call (_ : ={glob Independent}); first by sim.
  auto; rewrite /fors_private_key.
qed.

lemma wrapper_target_plan_projection
  (S <: WrapperTargetPlan {-Independent,-OriginalTargetState,-TargetConfig}) :
  equiv [S(ObservedTarget(Independent)).sign ~ S(ConcreteTarget(Independent)).sign :
    ={arg,glob S,glob Independent} ==> ={res,glob S,glob Independent}].
proof.
  symmetry; proc (={glob Independent}) => //.
  + by sim.
  + conseq wrapper_observed_derive_projection; smt().
  + by sim.
  conseq wrapper_observed_secret_projection; smt().
qed.

lemma wrapper_target_signing_projection
  (S <: WrapperTargetSigning {-Independent,-OriginalTargetState,-TargetConfig}) :
  equiv [S(ObservedTarget(Independent)).sign ~ S(ConcreteTarget(Independent)).sign :
    ={arg,glob S,glob Independent} ==> ={res,glob S,glob Independent}].
proof.
  symmetry; proc (={glob Independent}) => //.
  + by sim.
  + conseq wrapper_observed_derive_projection; smt().
  + by sim.
  conseq wrapper_observed_secret_projection; smt().
qed.

lemma wrapper_plan_original_projection seed0 root0 message0 :
  equiv [TargetWrapperPlan(ConcreteTarget(Independent)).sign ~ RawSigner(Independent).sign :
    seed{1}=seed0 /\ root{1}=root0 /\ message{1}=message0 /\
    ={arg,Independent.rawhistory,Independent.secrethistory} ==>
    ={Independent.rawhistory,Independent.secrethistory} /\
    wrapper_plan_supported Independent.rawhistory{1} Independent.secrethistory{1} seed0 root0 message0 res{2} res{1}].
proof.
  symmetry.
  transitivity WrapperPlanSigner(Independent,ConcreteForsLeaf(PreparationView(Independent))).sign
    (seed{1}=seed0 /\ root{1}=root0 /\ message{1}=message0 /\
      ={arg,Independent.rawhistory,Independent.secrethistory} ==>
      ={Independent.rawhistory,Independent.secrethistory} /\
      wrapper_plan_supported Independent.rawhistory{1} Independent.secrethistory{1} seed0 root0 message0 res{1} res{2})
    (={arg,glob Independent} ==> ={res,glob Independent}) => //.
  + smt().
  + exact (wrapper_plan_signer_projection seed0 root0 message0).
  by sim.
qed.

lemma wrapper_observed_plan_entry seed0 root0 message0 :
  hoare [TargetWrapperPlan(ObservedTarget(Independent)).sign :
    seed=seed0 /\ root=root0 /\ message=message0 ==>
    res<>None => wrapper_plan_entry Independent.rawhistory seed0 root0 message0 (oget res)].
proof.
  have hc : hoare [TargetWrapperPlan(ConcreteTarget(Independent)).sign :
    seed=seed0 /\ root=root0 /\ message=message0 ==>
    res<>None => wrapper_plan_entry Independent.rawhistory seed0 root0 message0 (oget res)].
  + have ht : hoare [RawSigner(Independent).sign : true ==> true] by trivial.
    conseq (wrapper_plan_original_projection seed0 root0 message0) ht;
      rewrite /wrapper_plan_supported; smt().
  conseq (wrapper_target_plan_projection TargetWrapperPlan) hc; smt().
qed.

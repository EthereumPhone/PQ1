(* Preserve the original signer result and complete memo tables under the observer. *)
require import AllCore List.
require import C10RawOracle PrefixGuess PrefixHybrid RawSigner RoleGrind.
require import KeygenPrefixes ForsPrivateLeaves ForsLeafView LeafSignerView TargetByteView TargetOracleSplit TargetTableProjection.

lemma observed_grind_projection :
  equiv [RoleGrind(TargetPrefix(ObservedTarget(Independent))).run ~ RoleGrind(Independent).run :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  proc; while (={i,result,random,message,seed,root,glob Independent}).
  + inline ObservedTarget(Independent).derive.
    wp; call (_ : ={glob Independent}); first by sim.
    wp; call (_ : ={glob Independent}); first by sim.
    auto.
  auto.
qed.
module type TargetFinisher (O : TargetOracle) = {
  proc finish(seed randomizer : raw_input, digest : digest, shuffle : raw_input) :
    raw_signature option {O.hash,O.derive,O.leaf,O.secret}
}.
module TargetSigning (O : TargetOracle) = LeafSigner(TargetPrefix(O),TargetLeaf(O)).
lemma target_finish_observer_projection
  (A <: TargetFinisher {-OriginalTargetState,-TargetConfig})
  (O <: PrefixOracle {-A,-OriginalTargetState,-TargetConfig}) :
  equiv [A(ConcreteTarget(O)).finish ~ A(ObservedTarget(O)).finish :
    ={arg,glob A,glob O} ==> ={res,glob A,glob O}].
proof.
  proc (={glob O}) => //.
  + by sim.
  + proc*; inline ObservedTarget(O).derive; wp; call (_ : true); auto.
  + by sim.
  proc; inline ObservedTarget(O).derive PreparationView(O).fors.
  wp; call (_ : true); auto; rewrite /fors_private_key.
qed.
lemma observed_finish_projection :
  equiv [TargetSigning(ObservedTarget(Independent)).finish ~ RawSigner(Independent).finish :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  transitivity TargetSigning(ConcreteTarget(Independent)).finish
    (={arg,glob Independent} ==> ={res,glob Independent})
    (={arg,glob Independent} ==> ={res,glob Independent}) => //.
  + smt().
  + symmetry; conseq (target_finish_observer_projection TargetSigning Independent); smt().
  transitivity LeafSigner(Independent,ConcreteForsLeaf(PreparationView(Independent))).finish
    (={arg,glob Independent} ==> ={res,glob Independent})
    (={arg,glob Independent} ==> ={res,glob Independent}) => //.
  + smt().
  + by sim.
  symmetry; conseq (leaf_signer_finish_projection Independent); smt().
qed.
lemma observed_signer_projection :
  equiv [TargetSigning(ObservedTarget(Independent)).sign ~ RawSigner(Independent).sign :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  proc; sp 0 0; seq 1 1 : (={seed,root,random,message,shuffle,accepted,glob Independent}).
  + call observed_grind_projection; auto.
  sp 1 1; if; auto; call observed_finish_projection; auto.
qed.

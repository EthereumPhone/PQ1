(* Total correctness of the actual keygen/sign/recover component, with bounded
   count failure represented explicitly and no nonzero-root assumption. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawKeygenCost RawWots.
require import WotsReference WotsReferenceRoot WotsLeafReference RawWotsReference WotsSignCorrect BuilderTotality.

module ActualWotsConstruction (O : PreparationOracle) = {
  proc run(seed : raw_input, layer tree kp : int, message shuffle : raw_input) :
      raw_input * (raw_input list * int) option * raw_input option = {
    var root, result;
    root <@ RawKeygen(O).leaf(seed,layer,tree,kp);
    result <@ RawWotsSignRecover(O).run(seed,layer,tree,kp,message,shuffle);
    return (root,result.`1,result.`2);
  }
}.

lemma actual_wots_correct seed0 layer0 tree0 kp0 message0 :
  hoare [ActualWotsConstruction(PreparationView(Independent)).run :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 ==>
    (res.`2=None => res.`3=None) /\ (res.`2<>None => res.`3=Some res.`1)].
proof.
  proc; seq 1 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root).
  + call (raw_leaf_recorded seed0 layer0 tree0 kp0); auto; rewrite /wots_root; smt().
  exists* root; elim* => root0.
  call (wots_sign_recover_correct seed0 layer0 tree0 kp0 message0 root0); auto; smt().
qed.

lemma wots_sign_recover_lossless :
  islossless RawWotsSignRecover(PreparationView(Independent)).run.
proof.
  proc; seq 1 : true 1%r 1%r 0%r 0%r => //.
  + call (raw_sign_lossless (PreparationView(Independent)) independent_hash_ll preparation_wots_ll); auto.
  sp 1; if; auto; wp.
  call (raw_recover_lossless (PreparationView(Independent)) independent_hash_ll); auto.
qed.

lemma actual_wots_lossless : islossless ActualWotsConstruction(PreparationView(Independent)).run.
proof.
  proc; call wots_sign_recover_lossless.
  call (leaf_lossless (PreparationView(Independent)) independent_hash_ll preparation_wots_ll); auto.
qed.

lemma total_actual_wots_correct seed0 layer0 tree0 kp0 message0 :
  phoare [ActualWotsConstruction(PreparationView(Independent)).run :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 ==>
    (res.`2=None => res.`3=None) /\ (res.`2<>None => res.`3=Some res.`1)] = 1%r.
proof. conseq actual_wots_lossless (actual_wots_correct seed0 layer0 tree0 kp0 message0); smt(). qed.

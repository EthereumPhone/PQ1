(* Accepted actual WOTS signing/recovery agrees with the actual keygen leaf. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawKeygenCost.
require import WotsReferenceRoot WotsSignWitness WotsOpeningRecovery RawWotsReference.
require import WotsReference WotsLeafReference PersistentGrind BuilderTotality.

module RawWotsSignRecover (O : PreparationOracle) = {
  proc run(seed : raw_input, layer tree kp : int, message shuffle : raw_input) :
      (raw_input list * int) option * raw_input option = {
    var signature, recovered, value;
    signature <@ RawWots(O).sign(seed,layer,tree,kp,message,shuffle);
    recovered <- None;
    if (signature <> None) {
      value <@ RawWots(O).recover(seed,layer,tree,kp,message,(oget signature).`1,(oget signature).`2);
      recovered <- Some value;
    }
    return (signature,recovered);
  }
}.

lemma wots_sign_recover_correct seed0 layer0 tree0 kp0 message0 root0 :
  hoare [RawWotsSignRecover(PreparationView(Independent)).run :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0 ==>
    (res.`1=None => res.`2=None) /\ (res.`1<>None => res.`2=Some root0)].
proof.
  proc; seq 1 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    (signature<>None => exists h s,
      wots_opening h s seed0 layer0 tree0 kp0 message0 root0 (oget signature) /\
      extends s Independent.secrethistory /\ extends h Independent.rawhistory)).
  + call (raw_wots_sign_witness seed0 layer0 tree0 kp0 message0 root0); auto.
  sp 1; if; last by auto.
  conseq (_ : exists h s, seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    signature<>None /\ wots_opening h s seed0 layer0 tree0 kp0 message0 root0 (oget signature) /\
    extends s Independent.secrethistory /\ extends h Independent.rawhistory ==> _); first smt().
  elim* => h s.
  exists* signature; elim* => signature0.
  wp; call (raw_wots_recovers_opening seed0 layer0 tree0 kp0 message0 (oget signature0) root0 h s).
  auto; smt().
qed.

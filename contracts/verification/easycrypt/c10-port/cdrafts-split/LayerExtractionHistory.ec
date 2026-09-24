(* Intermediate recovery traces and retained paths survive the full layer call. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawMerkle.
require import WotsReferenceRoot RawRecoveryTrace WotsRecoveryHistory RawWotsExtraction LayerPath.

lemma wots_recovers_layer_trace seed0 layer0 tree0 kp0 message0 sigma0 count0 leaf0 auth0 root0 :
  hoare [RawWots(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\ sigma=sigma0 /\ count=count0 /\
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 leaf0 /\
    layer_path Independent.rawhistory seed0 layer0 tree0 kp0 leaf0 auth0 root0 ==>
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 leaf0 /\
    layer_path Independent.rawhistory seed0 layer0 tree0 kp0 leaf0 auth0 root0 /\
    wots_recovery_trace Independent.rawhistory seed0 layer0 tree0 kp0 message0 sigma0 count0 res].
proof.
  conseq (raw_wots_recovers_trace_and_root seed0 layer0 tree0 kp0 message0 sigma0 count0 leaf0)
    (recovery_keeps_layer_path RawWots seed0 layer0 tree0 kp0 leaf0 auth0 root0); smt().
qed.

lemma merkle_keeps_root_and_trace seed0 layer0 tree0 kp0 message0 sigma0 count0 result0 leaf0 :
  hoare [RawMerkle(PreparationView(Independent)).recover :
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 leaf0 /\
    wots_recovery_trace Independent.rawhistory seed0 layer0 tree0 kp0 message0 sigma0 count0 result0 ==>
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 leaf0 /\
    wots_recovery_trace Independent.rawhistory seed0 layer0 tree0 kp0 message0 sigma0 count0 result0].
proof.
  conseq (merkle_keeps_recovery_trace RawMerkle seed0 layer0 tree0 kp0 message0 sigma0 count0 result0)
    (merkle_keeps_wots_root RawMerkle seed0 layer0 tree0 kp0 leaf0); smt().
qed.

(* An actual matching recovery exposes the retained key's reference chain nodes. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawSignature.
require import WotsReferenceRoot RawRecoveryTrace WotsRecoveryHistory VerifierWotsOpening.
require import MemoNodeCollision PublicNodeZero.

lemma raw_wots_recovers_trace_and_root seed0 layer0 tree0 kp0 message0 sigma0 count0 root0 :
  hoare [RawWots(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\ sigma=sigma0 /\ count=count0 /\
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0 ==>
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0 /\
    wots_recovery_trace Independent.rawhistory seed0 layer0 tree0 kp0 message0 sigma0 count0 res].
proof.
  conseq (raw_recovery_recorded seed0 layer0 tree0 kp0 message0 sigma0 count0)
    (wots_recovery_keeps_root RawWots seed0 layer0 tree0 kp0 root0); smt().
qed.

lemma raw_wots_extracts_opening seed0 layer0 tree0 kp0 message0 sigma0 count0 root0 :
  hoare [RawWots(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\ sigma=sigma0 /\ count=count0 /\
    rows_width 43 sigma0 /\ 0<=count0<4294967296 /\
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0 ==>
    res=root0 => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      wots_verifier_opening Independent.rawhistory Independent.secrethistory
        seed0 layer0 tree0 kp0 message0 root0 (sigma0,count0)].
proof.
  conseq (raw_wots_recovers_trace_and_root seed0 layer0 tree0 kp0 message0 sigma0 count0 root0);
    smt(recovery_trace_opens_reference).
qed.

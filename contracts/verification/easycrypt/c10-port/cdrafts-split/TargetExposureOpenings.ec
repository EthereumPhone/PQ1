(* Persistent exposure accounting for the private-opening observer. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid ForsPrivateLeaves RawSigner FullSession.
require import PersistentGrind AcceptedContexts MonotoneHistory ForestReferenceHistory.
require import ExposureLog ExposureCoverage ReturnedPrivateInputs ClientQueryLog.
require import TargetOracleSplit TargetByteView TargetTableProjection TargetSignerOpenings.
require import TargetSessionOpenings TargetReturnedOpenings.

op opening_accounted (revealed failed : bool) h seed root entries input =
  revealed => failed \/ returned_private_input h seed root entries input.

lemma observed_session_opening_safe flag failed0 target_ht target_tree target_index seed0 root0 message0 :
  hoare [TargetSession(ObservedTarget(Independent)).sign :
    OriginalTargetState.revealed=flag /\ FullSession.failed=failed0 /\
    TargetConfig.input=fors_private_key target_ht target_tree target_index /\
    FullSession.seed=seed0 /\ FullSession.root=root0 /\ message=message0 ==>
    (failed0 => FullSession.failed) /\
    (OriginalTargetState.revealed => flag \/ FullSession.failed \/
      (res<>None /\ signature_opens_input Independent.rawhistory seed0 root0 message0 (oget res)
        (fors_private_key target_ht target_tree target_index)))].
proof.
  conseq (observed_session_failure_monotone failed0)
    (observed_session_opening flag target_ht target_tree target_index seed0 root0 message0); smt().
qed.

lemma observed_exposure_opening target_ht target_tree target_index seed0 root0 :
  hoare [TargetExposureSession(ObservedTarget(Independent)).sign :
    TargetConfig.input=fors_private_key target_ht target_tree target_index /\
    FullSession.seed=seed0 /\ FullSession.root=root0 /\
    opening_accounted OriginalTargetState.revealed FullSession.failed Independent.rawhistory
      seed0 root0 ExposureLog.entries (fors_private_key target_ht target_tree target_index) ==>
    opening_accounted OriginalTargetState.revealed FullSession.failed Independent.rawhistory
      seed0 root0 ExposureLog.entries (fors_private_key target_ht target_tree target_index)].
proof.
  proc; exists* OriginalTargetState.revealed, FullSession.failed,
    Independent.secrethistory, Independent.rawhistory, message;
    elim* => flag failed0 s0 h0 message0.
  wp; call (_ : OriginalTargetState.revealed=flag /\ FullSession.failed=failed0 /\
    TargetConfig.input=fors_private_key target_ht target_tree target_index /\
    FullSession.seed=seed0 /\ FullSession.root=root0 /\ message=message0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    (failed0 => FullSession.failed) /\
    (OriginalTargetState.revealed => flag \/ FullSession.failed \/
      (res<>None /\ signature_opens_input Independent.rawhistory seed0 root0 message0 (oget res)
        (fors_private_key target_ht target_tree target_index)))).
  + conseq (observed_session_histories s0 h0)
      (observed_session_opening_safe flag failed0 target_ht target_tree target_index seed0 root0 message0); smt().
  auto; rewrite /opening_accounted;
    smt(extends_refl returned_input_extends signature_opening_returned returned_input_rcons).
qed.

lemma observed_exposure_hash_projection :
  equiv [TargetExposureSession(ObservedTarget(Independent)).hash ~ FullSession(Independent).hash :
    ={arg,glob Independent,glob FullSession} ==> ={res,glob Independent,glob FullSession}].
proof. proc; inline FullSession(TargetPrefix(ObservedTarget(Independent))).hash; if{1}; sim. qed.

lemma observed_exposure_hash_histories s0 h0 :
  hoare [TargetExposureSession(ObservedTarget(Independent)).hash :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof. conseq observed_exposure_hash_projection (full_hash_histories s0 h0); smt(). qed.

lemma observed_exposure_hash target_ht target_tree target_index seed0 root0 :
  hoare [TargetExposureSession(ObservedTarget(Independent)).hash :
    opening_accounted OriginalTargetState.revealed FullSession.failed Independent.rawhistory
      seed0 root0 ExposureLog.entries (fors_private_key target_ht target_tree target_index) ==>
    opening_accounted OriginalTargetState.revealed FullSession.failed Independent.rawhistory
      seed0 root0 ExposureLog.entries (fors_private_key target_ht target_tree target_index)].
proof.
  exists* Independent.secrethistory, Independent.rawhistory; elim* => s0 h0.
  conseq (observed_exposure_hash_histories s0 h0);
    rewrite /opening_accounted; smt(extends_refl returned_input_extends).
qed.

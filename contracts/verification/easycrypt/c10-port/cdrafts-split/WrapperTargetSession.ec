(* Release-aware target accounting over the wrapper's retrying session. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawSigner WrapperSession.
require import PersistentGrind AcceptedContexts MonotoneHistory ForestReferenceHistory.
require import ForsPrivateLeaves ForsLeafView ExposureLog ReturnedPrivateInputs ClientQueryLog.
require import TargetOracleSplit TargetByteView TargetTableProjection TargetSignerOpenings TargetReturnedOpenings.
require import WrapperForestRelease WrapperReleasedFors WrapperReleaseSession WrapperTargetProjection WrapperReleaseOpenings.

module TargetWrapperSession (O : TargetOracle) = WrapperReleaseSession(TargetPrefix(O),TargetLeaf(O)).
module TargetWrapperExposure (O : TargetOracle) = WrapperReleaseExposure(TargetPrefix(O),TargetLeaf(O)).
module TargetWrapperDriver (A : WrapperClient) (O : TargetOracle) = WrapperReleaseDriver(A,TargetPrefix(O),TargetLeaf(O)).
module TargetWrapperContext (A : WrapperClient) (O : TargetOracle) = WrapperReleaseContext(A,TargetPrefix(O),TargetLeaf(O)).

op wrapper_opening_accounted revealed h seed root entries input =
  revealed => returned_private_input h seed root entries input.

lemma wrapper_release_values_histories s0 h0 :
  hoare [WrapperForestRelease(TargetLeaf(ObservedTarget(Independent))).values :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc; while (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory).
  + wp; inline ObservedTarget(Independent).secret ObservedTarget(Independent).derive.
    wp; call (independent_derive_extends s0 h0); auto.
  auto.
qed.

lemma wrapper_observed_release_histories s0 h0 :
  hoare [TargetWrapperReleased(ObservedTarget(Independent)).sign :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc; sp 1; if; last auto.
  seq 1 : (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory).
  + call (wrapper_observed_plan_histories s0 h0); auto.
  if; last auto.
  seq 1 : (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory).
  + call (wrapper_observed_plan_histories s0 h0); auto.
  if; last auto.
  if; last auto.
  wp; call (wrapper_release_values_histories s0 h0); auto.
qed.

lemma wrapper_target_session_histories s0 h0 :
  hoare [TargetWrapperSession(ObservedTarget(Independent)).sign :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc; sp 1; if; last auto.
  wp; call (wrapper_observed_release_histories s0 h0); auto.
qed.

lemma wrapper_target_session_opening flag target_ht target_tree target_index seed0 root0 message0 :
  hoare [TargetWrapperSession(ObservedTarget(Independent)).sign :
    OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index /\
    WrapperSession.seed=seed0 /\ WrapperSession.root=root0 /\ message=message0 ==>
    OriginalTargetState.revealed => flag \/
      (res<>None /\ signature_opens_input Independent.rawhistory seed0 root0 message0 (oget res)
        (fors_private_key target_ht target_tree target_index))].
proof.
  proc; sp 1; if; last auto.
  wp; call (wrapper_released_opening flag target_ht target_tree target_index seed0 root0 message0); auto.
qed.

lemma wrapper_target_exposure_opening target_ht target_tree target_index seed0 root0 :
  hoare [TargetWrapperExposure(ObservedTarget(Independent)).sign :
    TargetConfig.input=fors_private_key target_ht target_tree target_index /\
    WrapperSession.seed=seed0 /\ WrapperSession.root=root0 /\
    wrapper_opening_accounted OriginalTargetState.revealed Independent.rawhistory
      seed0 root0 ExposureLog.entries (fors_private_key target_ht target_tree target_index) ==>
    wrapper_opening_accounted OriginalTargetState.revealed Independent.rawhistory
      seed0 root0 ExposureLog.entries (fors_private_key target_ht target_tree target_index)].
proof.
  proc; exists* OriginalTargetState.revealed,Independent.secrethistory,Independent.rawhistory,message;
    elim* => flag s0 h0 message0.
  wp; call (_ : OriginalTargetState.revealed=flag /\
    TargetConfig.input=fors_private_key target_ht target_tree target_index /\
    WrapperSession.seed=seed0 /\ WrapperSession.root=root0 /\ message=message0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    (OriginalTargetState.revealed => flag \/
      (res<>None /\ signature_opens_input Independent.rawhistory seed0 root0 message0 (oget res)
        (fors_private_key target_ht target_tree target_index)))).
  + conseq (wrapper_target_session_histories s0 h0)
      (wrapper_target_session_opening flag target_ht target_tree target_index seed0 root0 message0); smt().
  auto; rewrite /wrapper_opening_accounted;
    smt(extends_refl returned_input_extends signature_opening_returned returned_input_rcons).
qed.

lemma wrapper_target_hash_histories s0 h0 :
  hoare [TargetWrapperExposure(ObservedTarget(Independent)).hash :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc; call (_ : extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory).
  + proc; sp 1; if; last auto.
    wp; call (independent_hash_extends s0 h0); auto.
  auto.
qed.

lemma wrapper_target_hash_opening seed0 root0 input :
  hoare [TargetWrapperExposure(ObservedTarget(Independent)).hash :
    wrapper_opening_accounted OriginalTargetState.revealed Independent.rawhistory seed0 root0 ExposureLog.entries input ==>
    wrapper_opening_accounted OriginalTargetState.revealed Independent.rawhistory seed0 root0 ExposureLog.entries input].
proof.
  exists* Independent.secrethistory,Independent.rawhistory; elim* => s0 h0.
  conseq (wrapper_target_hash_histories s0 h0);
    rewrite /wrapper_opening_accounted; smt(extends_refl returned_input_extends).
qed.

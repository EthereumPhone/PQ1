(* Openings from successful requests are attributable to returned signatures. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes ForsPrivateLeaves RawSigner FullSession.
require import PersistentGrind AcceptedContexts ForestReferenceHistory.
require import ExposureLog ClientQueryLog LeafSessionView TargetByteView TargetOracleSplit.
require import TargetTableProjection TargetSignerProjection TargetSignerOpenings.

module TargetSession (O : TargetOracle) = LeafSession(TargetPrefix(O),TargetLeaf(O)).
module TargetExposureSession (O : TargetOracle) = LeafExposureSession(TargetPrefix(O),TargetLeaf(O)).

lemma observed_session_projection :
  equiv [TargetSession(ObservedTarget(Independent)).sign ~ FullSession(Independent).sign :
    ={arg,glob Independent,glob FullSession} ==> ={res,glob Independent,glob FullSession}].
proof. proc; sp 1 1; if; auto; wp; call observed_signer_projection; auto; smt(). qed.

lemma observed_session_histories s0 h0 :
  hoare [TargetSession(ObservedTarget(Independent)).sign :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof. conseq observed_session_projection (full_sign_histories s0 h0); smt(). qed.

lemma observed_session_opening flag target_ht target_tree target_index seed0 root0 message0 :
  hoare [TargetSession(ObservedTarget(Independent)).sign :
    OriginalTargetState.revealed=flag /\
    TargetConfig.input=fors_private_key target_ht target_tree target_index /\
    FullSession.seed=seed0 /\ FullSession.root=root0 /\ message=message0 ==>
    OriginalTargetState.revealed => flag \/ FullSession.failed \/
      (res<>None /\ signature_opens_input Independent.rawhistory seed0 root0 message0 (oget res)
        (fors_private_key target_ht target_tree target_index))].
proof.
  proc; sp 1; if; last by auto; smt().
  wp; call (target_signer_opening flag target_ht target_tree target_index seed0 root0 message0).
  auto; smt().
qed.

lemma observed_session_failure_absorbing :
  hoare [TargetSession(ObservedTarget(Independent)).sign : FullSession.failed ==> FullSession.failed].
proof. proc; sp 1; rcondf 1; auto; smt(). qed.

lemma observed_session_failure_monotone failed0 :
  hoare [TargetSession(ObservedTarget(Independent)).sign :
    FullSession.failed=failed0 ==> failed0 => FullSession.failed].
proof.
  proc; sp 1; if; last by auto.
  wp; call (_ : true ==> true); first by trivial.
  auto; smt().
qed.

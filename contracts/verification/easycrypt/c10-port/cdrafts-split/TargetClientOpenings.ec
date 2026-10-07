(* Adaptive client invariant: every nonfailed opening is in the response log. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid ForsPrivateLeaves RawSigner FullSession.
require import PersistentGrind AcceptedContexts MonotoneHistory VerifierHistory.
require import ExposureLog ReturnedPrivateInputs ClientQueryLog LeafSessionView.
require import TargetOracleSplit TargetByteView TargetTableProjection TargetSessionOpenings TargetExposureOpenings TargetReturnedOpenings.

lemma observed_client_openings
  (A <: FullClient {-Independent,-OriginalTargetState,-TargetConfig,-FullSession,-ExposureLog,-ClientQueryLog})
  target_ht target_tree target_index seed0 root0 :
  hoare [A(TargetExposureSession(ObservedTarget(Independent))).run :
    TargetConfig.input=fors_private_key target_ht target_tree target_index /\
    FullSession.seed=seed0 /\ FullSession.root=root0 /\
    opening_accounted OriginalTargetState.revealed FullSession.failed Independent.rawhistory
      seed0 root0 ExposureLog.entries (fors_private_key target_ht target_tree target_index) ==>
    TargetConfig.input=fors_private_key target_ht target_tree target_index /\
    FullSession.seed=seed0 /\ FullSession.root=root0 /\
    opening_accounted OriginalTargetState.revealed FullSession.failed Independent.rawhistory
      seed0 root0 ExposureLog.entries (fors_private_key target_ht target_tree target_index)].
proof.
  proc (TargetConfig.input=fors_private_key target_ht target_tree target_index /\
    FullSession.seed=seed0 /\ FullSession.root=root0 /\
    opening_accounted OriginalTargetState.revealed FullSession.failed Independent.rawhistory
      seed0 root0 ExposureLog.entries (fors_private_key target_ht target_tree target_index)) => //.
  + conseq (observed_exposure_hash target_ht target_tree target_index seed0 root0); smt().
  conseq (observed_exposure_opening target_ht target_tree target_index seed0 root0); smt().
qed.

lemma observed_verifier_accounting
  (V <: PublicVerifier {-Independent,-OriginalTargetState,-FullSession,-ExposureLog,-TargetConfig})
  seed0 root0 input :
  hoare [V(TargetPrefix(ObservedTarget(Independent))).verify :
    opening_accounted OriginalTargetState.revealed FullSession.failed Independent.rawhistory
      seed0 root0 ExposureLog.entries input ==>
    opening_accounted OriginalTargetState.revealed FullSession.failed Independent.rawhistory
      seed0 root0 ExposureLog.entries input].
proof.
  proc (opening_accounted OriginalTargetState.revealed FullSession.failed Independent.rawhistory
    seed0 root0 ExposureLog.entries input) => //.
  exists* Independent.secrethistory, Independent.rawhistory; elim* => s0 h0.
  conseq (independent_hash_extends s0 h0); rewrite /opening_accounted;
    smt(extends_refl returned_input_extends).
qed.

lemma observed_driver_openings
  (A <: FullClient {-Independent,-OriginalTargetState,-TargetConfig,-FullSession,-ExposureLog,-ClientQueryLog})
  target_ht target_tree target_index seed0 root0 :
  hoare [LeafQueryDriver(A,TargetPrefix(ObservedTarget(Independent)),TargetLeaf(ObservedTarget(Independent))).run :
    !OriginalTargetState.revealed /\ TargetConfig.input=fors_private_key target_ht target_tree target_index /\
    seed=seed0 /\ root=root0 ==>
    FullSession.seed=seed0 /\ FullSession.root=root0 /\
    (res => !FullSession.failed /\
      (OriginalTargetState.revealed => returned_private_input Independent.rawhistory
        seed0 root0 ExposureLog.entries (fors_private_key target_ht target_tree target_index)))].
proof.
  proc; seq 5 : (seed=seed0 /\ root=root0 /\
    FullSession.seed=seed0 /\ FullSession.root=root0 /\
    opening_accounted OriginalTargetState.revealed FullSession.failed Independent.rawhistory
      seed0 root0 ExposureLog.entries (fors_private_key target_ht target_tree target_index)).
  + call (observed_client_openings A target_ht target_tree target_index seed0 root0).
    wp; inline FullSession(TargetPrefix(ObservedTarget(Independent))).init.
    auto; rewrite /opening_accounted; smt().
  sp 2; if; last by auto.
  call (observed_verifier_accounting RawSigner seed0 root0 (fors_private_key target_ht target_tree target_index)).
  auto; rewrite /opening_accounted; smt().
qed.

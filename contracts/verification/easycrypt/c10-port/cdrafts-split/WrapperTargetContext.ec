(* The initialized adaptive wrapper's target observer accounts only for
   externally returned signatures, across every refusal and retry. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawSigner WrapperSession WrapperByteSession.
require import PersistentGrind AcceptedContexts MonotoneHistory VerifierHistory.
require import ForsPrivateLeaves ExposureLog ClientQueryLog ReturnedPrivateInputs.
require import TargetOracleSplit TargetByteView TargetTableProjection TargetOpeningFrames TargetReturnedOpenings.
require import WrapperTargetSession.

module TargetWrapperByteCandidates (A : WrapperByteClient) (O : TargetOracle) = {
  proc run() : raw_input list = {
    var accepted, outputs;
    accepted <@ TargetWrapperContext(WrapperByteLift(A),O).run();
    outputs <- [];
    if (accepted) { outputs <- ordinary_output_candidates ClientQueryLog.output.`2; }
    return outputs;
  }
}.

lemma wrapper_observed_client_openings
  (A <: WrapperClient {-Independent,-OriginalTargetState,-TargetConfig,-WrapperSession,-ExposureLog,-ClientQueryLog})
  target_ht target_tree target_index seed0 root0 :
  hoare [A(TargetWrapperExposure(ObservedTarget(Independent))).run :
    TargetConfig.input=fors_private_key target_ht target_tree target_index /\
    WrapperSession.seed=seed0 /\ WrapperSession.root=root0 /\
    wrapper_opening_accounted OriginalTargetState.revealed Independent.rawhistory
      seed0 root0 ExposureLog.entries (fors_private_key target_ht target_tree target_index) ==>
    TargetConfig.input=fors_private_key target_ht target_tree target_index /\
    WrapperSession.seed=seed0 /\ WrapperSession.root=root0 /\
    wrapper_opening_accounted OriginalTargetState.revealed Independent.rawhistory
      seed0 root0 ExposureLog.entries (fors_private_key target_ht target_tree target_index)].
proof.
  proc (TargetConfig.input=fors_private_key target_ht target_tree target_index /\
    WrapperSession.seed=seed0 /\ WrapperSession.root=root0 /\
    wrapper_opening_accounted OriginalTargetState.revealed Independent.rawhistory
      seed0 root0 ExposureLog.entries (fors_private_key target_ht target_tree target_index)) => //.
  + conseq (wrapper_target_hash_opening seed0 root0 (fors_private_key target_ht target_tree target_index)); smt().
  conseq (wrapper_target_exposure_opening target_ht target_tree target_index seed0 root0); smt().
qed.

lemma wrapper_observed_verifier_accounting
  (V <: PublicVerifier {-Independent,-OriginalTargetState,-WrapperSession,-ExposureLog,-TargetConfig}) seed0 root0 input :
  hoare [V(TargetPrefix(ObservedTarget(Independent))).verify :
    wrapper_opening_accounted OriginalTargetState.revealed Independent.rawhistory seed0 root0 ExposureLog.entries input ==>
    wrapper_opening_accounted OriginalTargetState.revealed Independent.rawhistory seed0 root0 ExposureLog.entries input].
proof.
  proc (wrapper_opening_accounted OriginalTargetState.revealed Independent.rawhistory seed0 root0 ExposureLog.entries input) => //.
  exists* Independent.secrethistory,Independent.rawhistory; elim* => s0 h0.
  conseq (independent_hash_extends s0 h0); rewrite /wrapper_opening_accounted;
    smt(extends_refl returned_input_extends).
qed.

lemma wrapper_observed_driver_openings
  (A <: WrapperClient {-Independent,-OriginalTargetState,-TargetConfig,-WrapperSession,-ExposureLog,-ClientQueryLog})
  target_ht target_tree target_index seed0 root0 :
  hoare [TargetWrapperDriver(A,ObservedTarget(Independent)).run :
    !OriginalTargetState.revealed /\ TargetConfig.input=fors_private_key target_ht target_tree target_index /\
    seed=seed0 /\ root=root0 ==>
    WrapperSession.seed=seed0 /\ WrapperSession.root=root0 /\
    wrapper_opening_accounted OriginalTargetState.revealed Independent.rawhistory
      seed0 root0 ExposureLog.entries (fors_private_key target_ht target_tree target_index)].
proof.
  proc; seq 5 : (seed=seed0 /\ root=root0 /\
    WrapperSession.seed=seed0 /\ WrapperSession.root=root0 /\
    wrapper_opening_accounted OriginalTargetState.revealed Independent.rawhistory
      seed0 root0 ExposureLog.entries (fors_private_key target_ht target_tree target_index)).
  + call (wrapper_observed_client_openings A target_ht target_tree target_index seed0 root0).
    wp; inline WrapperSession(TargetPrefix(ObservedTarget(Independent))).init.
    auto; rewrite /wrapper_opening_accounted; smt().
  sp 2; if; last auto.
  call (wrapper_observed_verifier_accounting RawSigner seed0 root0 (fors_private_key target_ht target_tree target_index)); auto.
qed.

lemma wrapper_observed_context_openings
  (A <: WrapperClient {-Independent,-OriginalTargetState,-TargetConfig,-WrapperSession,-WrapperLimits,
    -KeygenInputs,-ExposureLog,-ClientQueryLog}) target_ht target_tree target_index :
  hoare [TargetWrapperContext(A,ObservedTarget(Independent)).run :
    !OriginalTargetState.revealed /\ TargetConfig.input=fors_private_key target_ht target_tree target_index ==>
    wrapper_opening_accounted OriginalTargetState.revealed Independent.rawhistory
      WrapperSession.seed WrapperSession.root ExposureLog.entries (fors_private_key target_ht target_tree target_index)].
proof.
  proc; seq 1 : (!OriginalTargetState.revealed /\
    TargetConfig.input=fors_private_key target_ht target_tree target_index).
  + call (observed_keygen_preserves_opening false target_ht target_tree target_index); auto; smt().
  exists* inputs; elim* => key.
  call (wrapper_observed_driver_openings A target_ht target_tree target_index key.`3 key.`4); auto; smt().
qed.

lemma wrapper_observed_candidates_unopened
  (A <: WrapperByteClient {-Independent,-OriginalTargetState,-TargetConfig,-WrapperSession,-WrapperLimits,
    -KeygenInputs,-ExposureLog,-ClientQueryLog}) target_ht target_tree target_index :
  hoare [TargetWrapperByteCandidates(A,ObservedTarget(Independent)).run :
    !OriginalTargetState.revealed /\ TargetConfig.input=fors_private_key target_ht target_tree target_index ==>
    !returned_private_input Independent.rawhistory WrapperSession.seed WrapperSession.root ExposureLog.entries
      (fors_private_key target_ht target_tree target_index) => !OriginalTargetState.revealed].
proof.
  proc; wp; call (wrapper_observed_context_openings (WrapperByteLift(A)) target_ht target_tree target_index).
  auto; rewrite /wrapper_opening_accounted; smt().
qed.

lemma wrapper_target_candidate_count
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog})
  (O <: TargetOracle {-A,-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog}) :
  hoare [TargetWrapperByteCandidates(A,O).run : true ==> size res<=12].
proof.
  proc; wp; call (_ : true ==> true); first by trivial.
  auto; smt(ordinary_output_candidates_size).
qed.

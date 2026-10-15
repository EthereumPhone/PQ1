(* Variable candidates include initialization, all admitted requests and final verification. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion.
require import RawKeygen RoleGrindCost RawSigner FullSession FullPrefix ByteSession ExposureLog ClientQueryLog.
require import LeafSessionView LeafOpeningBound TargetOracleSplit TargetByteView TargetSessionOpenings.
require import TargetAdapterCost LeafTargetSignerCost LeafBudgetKeygen LeafCandidateCount.

op leaf_candidate_budget qr qs = 155135+qr+qs*364892+771.

lemma leaf_candidate_budget_ge0 qr qs : 0<=qr => 0<=qs => 0<=leaf_candidate_budget qr qs.
proof. rewrite /leaf_candidate_budget; smt(). qed.

lemma leaf_target_session_candidate_cost q0 :
  hoare [TargetSession(IdealTarget).sign :
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    leaf_variable_count Independent.queries<=q0+FullSession.raw_calls+FullSession.sign_calls*(364892) ==>
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    leaf_variable_count Independent.queries<=q0+FullSession.raw_calls+FullSession.sign_calls*(364892)].
proof.
  proc; sp 1; if; last by auto.
  wp; exists* Independent.queries; elim* => qs; call (leaf_target_signer_sign_candidate_cost (leaf_variable_count qs)); auto; smt().
qed.
lemma leaf_target_exposure_candidate_cost q0 :
  hoare [TargetExposureSession(IdealTarget).sign :
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    leaf_variable_count Independent.queries<=q0+FullSession.raw_calls+FullSession.sign_calls*(364892) ==>
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    leaf_variable_count Independent.queries<=q0+FullSession.raw_calls+FullSession.sign_calls*(364892)].
proof. proc; wp; call (leaf_target_session_candidate_cost q0); auto. qed.
lemma leaf_target_client_hash_candidate_cost q0 :
  hoare [TargetExposureSession(IdealTarget).hash :
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    leaf_variable_count Independent.queries<=q0+FullSession.raw_calls+FullSession.sign_calls*(364892) ==>
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    leaf_variable_count Independent.queries<=q0+FullSession.raw_calls+FullSession.sign_calls*(364892)].
proof.
  proc; inline FullSession(IdealPrefix).hash; sp 0; if.
  + rcondt 4; first by auto.
    wp; exists* Independent.queries; elim* => qs; call (leaf_variable_hash_bound (leaf_variable_count qs)); auto; smt().
  rcondf 3; first by auto.
  auto.
qed.
lemma leaf_target_client_candidate_cost
  (A <: FullClient {-FullSession,-ExposureLog,-ClientQueryLog,-Independent,-OtherPrivate,-RedactedLeafState,-TargetConfig}) q0 :
  hoare [A(TargetExposureSession(IdealTarget)).run :
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    leaf_variable_count Independent.queries<=q0+FullSession.raw_calls+FullSession.sign_calls*(364892) ==>
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    leaf_variable_count Independent.queries<=q0+FullSession.raw_calls+FullSession.sign_calls*(364892)].
proof.
  proc (0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    leaf_variable_count Independent.queries<=q0+FullSession.raw_calls+FullSession.sign_calls*(364892)) => //.
  + exact (leaf_target_client_hash_candidate_cost q0).
  exact (leaf_target_exposure_candidate_cost q0).
qed.
lemma leaf_target_driver_candidate_cost
  (A <: FullClient {-FullSession,-ExposureLog,-ClientQueryLog,-Independent,-OtherPrivate,-RedactedLeafState,-TargetConfig}) q0 qr0 qs0 :
  0<=qr0 => 0<=qs0 =>
  hoare [LeafQueryDriver(A,IdealPrefix,IdealLeaf).run :
    qr=qr0 /\ qs=qs0 /\ leaf_variable_count Independent.queries<=q0 ==>
    leaf_variable_count Independent.queries<=q0+qr0+qs0*(364892)+771].
proof.
  move=> hqr hqs; proc; seq 5 : (leaf_variable_count Independent.queries<=q0+qr0+qs0*(364892)).
  + call (leaf_target_client_candidate_cost A q0); wp; inline FullSession(IdealPrefix).init.
    auto; rewrite /signing_budget; smt().
  sp 2; if; last by auto; smt().
  exists* Independent.queries; elim* => zs; call (leaf_target_signer_verify_candidate_cost (leaf_variable_count zs)); auto; smt().
qed.
lemma leaf_target_keygen_candidate_cost q :
  hoare [KeygenPreparation(IdealPreparation).run : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q+155135].
proof. proc; call (leaf_budget_root_cost q); auto; smt(). qed.
lemma leaf_target_context_candidate_cost
  (A <: FullClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,
    -OtherPrivate,-RedactedLeafState,-TargetConfig}) qr qs :
  0<=qr => 0<=qs =>
  hoare [TargetQueryContext(A,IdealTarget).run :
    FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs /\ Independent.queries=[] ==>
    leaf_variable_count Independent.queries<=leaf_candidate_budget qr qs].
proof.
  move=> hqr hqs; proc; call (leaf_target_driver_candidate_cost A 155135 qr qs hqr hqs).
  call (leaf_target_keygen_candidate_cost 0); auto; rewrite /leaf_candidate_budget; smt().
qed.
lemma leaf_target_byte_candidate_cost
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,
    -OtherPrivate,-RedactedLeafState,-TargetConfig}) qr qs :
  0<=qr => 0<=qs =>
  hoare [TargetByteCandidates(A,IdealTarget).run :
    FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs /\ Independent.queries=[] ==>
    leaf_variable_count Independent.queries<=leaf_candidate_budget qr qs /\ size res<=12].
proof.
  move=> hqr hqs; proc; wp; call (leaf_target_context_candidate_cost (ByteLift(A)) qr qs hqr hqs).
  auto; smt(ordinary_output_candidates_size).
qed.

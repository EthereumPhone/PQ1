(* Include internal keygen, every permitted signing request, and final verification. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion.
require import RawKeygen RoleGrindCost RawSigner FullSession FullPrefix ByteSession ExposureLog ClientQueryLog.
require import LeafSessionView LeafOpeningBound TargetOracleSplit TargetByteView TargetSessionOpenings.
require import TargetAdapterCost TargetSignerCost.

lemma target_session_public_cost q0 :
  hoare [TargetSession(IdealTarget).sign :
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    size Independent.queries<=q0+FullSession.raw_calls+FullSession.sign_calls*(3*signing_budget+364892) ==>
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    size Independent.queries<=q0+FullSession.raw_calls+FullSession.sign_calls*(3*signing_budget+364892)].
proof.
  proc; sp 1; if; last by auto.
  wp; exists* Independent.queries; elim* => qs; call (target_signer_sign_public_cost (size qs)); auto; smt().
qed.
lemma target_exposure_public_cost q0 :
  hoare [TargetExposureSession(IdealTarget).sign :
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    size Independent.queries<=q0+FullSession.raw_calls+FullSession.sign_calls*(3*signing_budget+364892) ==>
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    size Independent.queries<=q0+FullSession.raw_calls+FullSession.sign_calls*(3*signing_budget+364892)].
proof. proc; wp; call (target_session_public_cost q0); auto. qed.
lemma target_client_hash_public_cost q0 :
  hoare [TargetExposureSession(IdealTarget).hash :
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    size Independent.queries<=q0+FullSession.raw_calls+FullSession.sign_calls*(3*signing_budget+364892) ==>
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    size Independent.queries<=q0+FullSession.raw_calls+FullSession.sign_calls*(3*signing_budget+364892)].
proof.
  proc; inline FullSession(IdealPrefix).hash; sp 0; if.
  + rcondt 4; first by auto.
    wp; exists* Independent.queries; elim* => qs; call (independent_hash_count (size qs)); auto; smt().
  rcondf 3; first by auto.
  auto.
qed.
lemma target_client_public_cost
  (A <: FullClient {-FullSession,-ExposureLog,-ClientQueryLog,-Independent,-OtherPrivate,-RedactedLeafState,-TargetConfig}) q0 :
  hoare [A(TargetExposureSession(IdealTarget)).run :
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    size Independent.queries<=q0+FullSession.raw_calls+FullSession.sign_calls*(3*signing_budget+364892) ==>
    0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    size Independent.queries<=q0+FullSession.raw_calls+FullSession.sign_calls*(3*signing_budget+364892)].
proof.
  proc (0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    size Independent.queries<=q0+FullSession.raw_calls+FullSession.sign_calls*(3*signing_budget+364892)) => //.
  + exact (target_client_hash_public_cost q0).
  exact (target_exposure_public_cost q0).
qed.
lemma target_driver_public_cost
  (A <: FullClient {-FullSession,-ExposureLog,-ClientQueryLog,-Independent,-OtherPrivate,-RedactedLeafState,-TargetConfig}) q0 qr0 qs0 :
  0<=qr0 => 0<=qs0 =>
  hoare [LeafQueryDriver(A,IdealPrefix,IdealLeaf).run :
    qr=qr0 /\ qs=qs0 /\ size Independent.queries<=q0 ==>
    size Independent.queries<=q0+qr0+qs0*(3*signing_budget+364892)+771].
proof.
  move=> hqr hqs; proc; seq 5 : (size Independent.queries<=q0+qr0+qs0*(3*signing_budget+364892)).
  + call (target_client_public_cost A q0); wp; inline FullSession(IdealPrefix).init.
    auto; rewrite /signing_budget; smt().
  sp 2; if; last by auto; smt().
  exists* Independent.queries; elim* => zs; call (target_signer_verify_public_cost (size zs)); auto; smt().
qed.
lemma target_keygen_public_cost q :
  hoare [KeygenPreparation(IdealPreparation).run : size Independent.queries=q ==>
    q<=size Independent.queries<=q+155135].
proof. proc; call (target_root_public_cost q); auto; smt(). qed.
lemma target_context_public_cost
  (A <: FullClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,
    -OtherPrivate,-RedactedLeafState,-TargetConfig}) qr qs :
  0<=qr => 0<=qs =>
  hoare [TargetQueryContext(A,IdealTarget).run :
    FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs /\ Independent.queries=[] ==>
    size Independent.queries<=full_public_budget qr qs].
proof.
  move=> hqr hqs; proc; call (target_driver_public_cost A 155135 qr qs hqr hqs).
  call (target_keygen_public_cost 0); auto; rewrite /full_public_budget; smt().
qed.
lemma target_byte_public_cost
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,
    -OtherPrivate,-RedactedLeafState,-TargetConfig}) qr qs :
  0<=qr => 0<=qs =>
  hoare [TargetByteCandidates(A,IdealTarget).run :
    FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs /\ Independent.queries=[] ==>
    size Independent.queries<=full_public_budget qr qs /\ size res<=12].
proof.
  move=> hqr hqs; proc; wp; call (target_context_public_cost (ByteLift(A)) qr qs hqr hqs).
  auto; smt(ordinary_output_candidates_size).
qed.

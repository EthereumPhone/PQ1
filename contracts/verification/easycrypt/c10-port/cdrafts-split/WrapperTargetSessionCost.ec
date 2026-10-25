(* Redacted-view budgets include key generation, every admitted attempt,
   external hash calls and the final verifier. Refused attempts are charged. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RoleGrindCost.
require import RawSigner RawWrapperCost WrapperSession WrapperByteSession WrapperPrefixBound ExposureLog ClientQueryLog.
require import LeafOpeningBound TargetOracleSplit TargetByteView TargetAdapterCost TargetSignerCost TargetSessionCost.
require import WrapperTargetSession WrapperTargetContext WrapperTargetCost.

lemma wrapper_target_session_cost q0 :
  hoare [TargetWrapperSession(IdealTarget).sign :
    0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    size Independent.queries<=q0+WrapperSession.raw_calls+WrapperSession.sign_calls*wrapper_public_budget ==>
    0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    size Independent.queries<=q0+WrapperSession.raw_calls+WrapperSession.sign_calls*wrapper_public_budget].
proof.
  proc; sp 1; if; last auto.
  wp; exists* Independent.queries; elim* => zs; call (wrapper_target_release_cost (size zs)); auto; smt().
qed.

lemma wrapper_target_exposure_cost q0 :
  hoare [TargetWrapperExposure(IdealTarget).sign :
    0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    size Independent.queries<=q0+WrapperSession.raw_calls+WrapperSession.sign_calls*wrapper_public_budget ==>
    0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    size Independent.queries<=q0+WrapperSession.raw_calls+WrapperSession.sign_calls*wrapper_public_budget].
proof. proc; wp; call (wrapper_target_session_cost q0); auto. qed.

lemma wrapper_target_hash_cost q0 :
  hoare [TargetWrapperExposure(IdealTarget).hash :
    0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    size Independent.queries<=q0+WrapperSession.raw_calls+WrapperSession.sign_calls*wrapper_public_budget ==>
    0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    size Independent.queries<=q0+WrapperSession.raw_calls+WrapperSession.sign_calls*wrapper_public_budget].
proof.
  proc; call (_ :
    0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    size Independent.queries<=q0+WrapperSession.raw_calls+WrapperSession.sign_calls*wrapper_public_budget ==>
    0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    size Independent.queries<=q0+WrapperSession.raw_calls+WrapperSession.sign_calls*wrapper_public_budget).
  + proc; sp 1; if; last auto.
    wp; exists* Independent.queries; elim* => zs; call (independent_hash_count (size zs)); auto; smt().
  auto; smt().
qed.

lemma wrapper_target_client_cost
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog,-Independent,-OtherPrivate,-RedactedLeafState,-TargetConfig}) q0 :
  hoare [A(TargetWrapperExposure(IdealTarget)).run :
    0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    size Independent.queries<=q0+WrapperSession.raw_calls+WrapperSession.sign_calls*wrapper_public_budget ==>
    0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    size Independent.queries<=q0+WrapperSession.raw_calls+WrapperSession.sign_calls*wrapper_public_budget].
proof.
  proc (0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    size Independent.queries<=q0+WrapperSession.raw_calls+WrapperSession.sign_calls*wrapper_public_budget) => //.
  + exact (wrapper_target_hash_cost q0).
  exact (wrapper_target_exposure_cost q0).
qed.

lemma wrapper_target_driver_cost
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog,-Independent,-OtherPrivate,-RedactedLeafState,-TargetConfig}) q0 qr0 qs0 :
  0<=qr0 => 0<=qs0 =>
  hoare [TargetWrapperDriver(A,IdealTarget).run : qr=qr0 /\ qs=qs0 /\ size Independent.queries<=q0 ==>
    size Independent.queries<=q0+qr0+qs0*wrapper_public_budget+771].
proof.
  move=> hqr hqs; proc; seq 5 : (size Independent.queries<=q0+qr0+qs0*wrapper_public_budget).
  + call (wrapper_target_client_cost A q0); wp; inline WrapperSession(IdealPrefix).init.
    auto; rewrite /wrapper_public_budget /signing_budget; smt().
  sp 2; if; last by auto; smt().
  exists* Independent.queries; elim* => zs; call (target_signer_verify_public_cost (size zs)); auto; smt().
qed.

lemma wrapper_target_context_cost
  (A <: WrapperClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,
    -OtherPrivate,-RedactedLeafState,-TargetConfig}) qr qs :
  0<=qr => 0<=qs =>
  hoare [TargetWrapperContext(A,IdealTarget).run :
    WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs /\ Independent.queries=[] ==>
    size Independent.queries<=wrapper_total_public_budget qr qs].
proof.
  move=> hqr hqs; proc; call (wrapper_target_driver_cost A 155135 qr qs hqr hqs).
  call (target_keygen_public_cost 0); auto; rewrite /wrapper_total_public_budget; smt().
qed.

lemma wrapper_target_byte_cost
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,
    -OtherPrivate,-RedactedLeafState,-TargetConfig}) qr qs :
  0<=qr => 0<=qs =>
  hoare [TargetWrapperByteCandidates(A,IdealTarget).run :
    WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs /\ Independent.queries=[] ==>
    size Independent.queries<=wrapper_total_public_budget qr qs /\ size res<=12].
proof.
  move=> hqr hqs; proc; wp; call (wrapper_target_context_cost (WrapperByteLift(A)) qr qs hqr hqs).
  auto; smt(ordinary_output_candidates_size).
qed.

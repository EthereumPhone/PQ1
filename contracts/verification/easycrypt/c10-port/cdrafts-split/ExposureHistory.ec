(* Accumulated references for all responses survive later adaptive calls. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid FullSession ExposureLog ExposureSupport.
require import PersistentGrind AcceptedContexts MonotoneHistory ForestReferenceHistory VerifierHistory.

lemma exposure_hash_supported seed0 root0 :
  hoare [ExposureSession(Independent).hash :
    exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries ==>
    exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (full_hash_histories s0 h0); smt(extends_refl exposures_supported_extends).
qed.

lemma exposure_sign_supported seed0 root0 :
  hoare [ExposureSession(Independent).sign :
    FullSession.seed=seed0 /\ FullSession.root=root0 /\
    exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries ==>
    exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries].
proof.
  proc; exists* Independent.rawhistory,Independent.secrethistory,message;
    elim* => h0 s0 message0.
  wp; call (full_sign_exposure_history seed0 root0 message0 s0 h0).
  auto; smt(extends_refl exposures_supported_extends exposures_supported_rcons).
qed.

lemma exposure_client_supported
  (A <: FullClient {-FullSession,-ExposureLog,-Independent}) seed0 root0 :
  hoare [A(ExposureSession(Independent)).run :
    FullSession.seed=seed0 /\ FullSession.root=root0 /\
    exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries ==>
    FullSession.seed=seed0 /\ FullSession.root=root0 /\
    exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries].
proof.
  proc (FullSession.seed=seed0 /\ FullSession.root=root0 /\
    exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries) => //.
  + conseq (exposure_hash_supported seed0 root0); smt().
  conseq (exposure_sign_supported seed0 root0); smt().
qed.

lemma verifier_exposures_preserved (V <: PublicVerifier {-Independent,-ExposureLog}) seed0 root0 :
  hoare [V(Independent).verify :
    exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries ==>
    exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries].
proof.
  proc (exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries) => //.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (independent_hash_extends s0 h0); smt(extends_refl exposures_supported_extends).
qed.

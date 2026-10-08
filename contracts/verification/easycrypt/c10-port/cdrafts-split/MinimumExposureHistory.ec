(* Retain the actual first-accepting WOTS counts through this observer layer. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid FullSession ExposureLog MinimumExposureSupport.
require import PersistentGrind AcceptedContexts MonotoneHistory ForestReferenceHistory VerifierHistory.

lemma minimum_exposure_hash_supported seed0 root0 :
  hoare [ExposureSession(Independent).hash :
    minimum_entries Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries ==>
    minimum_entries Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (full_hash_histories s0 h0); smt(extends_refl minimum_entries_extends).
qed.

lemma minimum_exposure_sign_supported seed0 root0 :
  hoare [ExposureSession(Independent).sign :
    FullSession.seed=seed0 /\ FullSession.root=root0 /\
    minimum_entries Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries ==>
    minimum_entries Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries].
proof.
  proc; exists* Independent.rawhistory,Independent.secrethistory,message;
    elim* => h0 s0 message0.
  wp; call (full_sign_minimum_history seed0 root0 message0 s0 h0).
  auto; smt(extends_refl minimum_entries_extends minimum_entries_rcons).
qed.

lemma minimum_exposure_client_supported
  (A <: FullClient {-FullSession,-ExposureLog,-Independent}) seed0 root0 :
  hoare [A(ExposureSession(Independent)).run :
    FullSession.seed=seed0 /\ FullSession.root=root0 /\
    minimum_entries Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries ==>
    FullSession.seed=seed0 /\ FullSession.root=root0 /\
    minimum_entries Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries].
proof.
  proc (FullSession.seed=seed0 /\ FullSession.root=root0 /\
    minimum_entries Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries) => //.
  + conseq (minimum_exposure_hash_supported seed0 root0); smt().
  conseq (minimum_exposure_sign_supported seed0 root0); smt().
qed.

lemma minimum_verifier_exposures_preserved (V <: PublicVerifier {-Independent,-ExposureLog}) seed0 root0 :
  hoare [V(Independent).verify :
    minimum_entries Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries ==>
    minimum_entries Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries].
proof.
  proc (minimum_entries Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries) => //.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (independent_hash_extends s0 h0); smt(extends_refl minimum_entries_extends).
qed.

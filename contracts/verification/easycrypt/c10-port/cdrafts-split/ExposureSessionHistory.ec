(* All-entry construction support and exact count/message accounting in one session. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawSigner FullSession.
require import ExposureLog ExposureDriver ExposureSupport ExposureHistory ExposureAccounting.

lemma exposure_client_history
  (A <: FullClient {-FullSession,-ExposureLog,-Independent}) seed0 root0 :
  hoare [A(ExposureSession(Independent)).run :
    FullSession.seed=seed0 /\ FullSession.root=root0 /\
    exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries /\
    exposure_accounting ExposureLog.entries FullSession.signed_messages FullSession.sign_calls FullSession.sign_limit ==>
    FullSession.seed=seed0 /\ FullSession.root=root0 /\
    exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries /\
    exposure_accounting ExposureLog.entries FullSession.signed_messages FullSession.sign_calls FullSession.sign_limit].
proof.
  conseq (exposure_client_supported A seed0 root0) (exposure_client_accounting A Independent); smt().
qed.

lemma exposure_driver_history
  (A <: FullClient {-FullSession,-ExposureLog,-Independent}) seed0 root0 qs0 :
  0<=qs0 =>
  hoare [ExposureDriver(A,Independent).run : seed=seed0 /\ root=root0 /\ qs=qs0 ==>
    FullSession.seed=seed0 /\ FullSession.root=root0 /\ FullSession.sign_limit=qs0 /\
    exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries /\
    exposure_accounting ExposureLog.entries FullSession.signed_messages FullSession.sign_calls qs0].
proof.
  move=> hqs; proc; seq 3 : (seed=seed0 /\ root=root0 /\
    FullSession.seed=seed0 /\ FullSession.root=root0 /\ FullSession.sign_limit=qs0 /\
    exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries /\
    exposure_accounting ExposureLog.entries FullSession.signed_messages FullSession.sign_calls qs0).
  + call (exposure_client_history A seed0 root0); wp; inline FullSession(Independent).init.
    auto; rewrite /exposures_supported /exposure_accounting /exposure_messages; smt(mem_nil).
  sp 1; if; last auto.
  call (verifier_exposures_preserved RawSigner seed0 root0); auto.
qed.

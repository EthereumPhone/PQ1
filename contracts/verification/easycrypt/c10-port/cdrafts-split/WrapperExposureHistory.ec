(* Every externally released wrapper signature retains its forest/subtree
   references and first-accepted WOTS counts throughout the adaptive game. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawSigner WrapperSession WrapperByteSession WrapperExposureLog WrapperQueryDriver.
require import ExposureLog ClientQueryLog ExposureSupport MinimumExposureSupport ExposureAccounting.
require import PersistentGrind AcceptedContexts MonotoneHistory VerifierHistory.
require import WrapperHistory WrapperQueryAccounting.

op wrapper_exposures_supported h s seed root entries =
  exposures_supported h s seed root entries /\ minimum_entries h s seed root entries.

lemma wrapper_exposures_extends h h' s s' seed root entries :
  extends h h' => extends s s' => wrapper_exposures_supported h s seed root entries =>
  wrapper_exposures_supported h' s' seed root entries.
proof.
  rewrite /wrapper_exposures_supported; smt(exposures_supported_extends minimum_entries_extends).
qed.

lemma wrapper_exposures_rcons h s seed root entries entry :
  wrapper_exposures_supported h s seed root (rcons entries entry) =
  (wrapper_exposures_supported h s seed root entries /\ wrapper_entry_supported h s seed root entry).
proof.
  rewrite /wrapper_exposures_supported /wrapper_entry_supported
    exposures_supported_rcons minimum_entries_rcons; smt().
qed.

lemma wrapper_query_hash_supported seed0 root0 :
  hoare [WrapperQueryExposureSession(Independent).hash :
    wrapper_exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries ==>
    wrapper_exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries].
proof.
  proc; exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  call (wrapper_hash_histories s0 h0); auto; smt(extends_refl wrapper_exposures_extends).
qed.

lemma wrapper_query_sign_supported seed0 root0 :
  hoare [WrapperQueryExposureSession(Independent).sign :
    WrapperSession.seed=seed0 /\ WrapperSession.root=root0 /\
    wrapper_exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries ==>
    wrapper_exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries].
proof.
  proc; exists* Independent.rawhistory,Independent.secrethistory,message;
    elim* => h0 s0 message0.
  wp; call (wrapper_sign_supported_history seed0 root0 message0 s0 h0).
  auto; smt(extends_refl wrapper_exposures_extends wrapper_exposures_rcons).
qed.

lemma wrapper_query_client_supported
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog,-Independent}) seed0 root0 :
  hoare [A(WrapperQueryExposureSession(Independent)).run :
    WrapperSession.seed=seed0 /\ WrapperSession.root=root0 /\
    wrapper_exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries ==>
    WrapperSession.seed=seed0 /\ WrapperSession.root=root0 /\
    wrapper_exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries].
proof.
  proc (WrapperSession.seed=seed0 /\ WrapperSession.root=root0 /\
    wrapper_exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries) => //.
  + conseq (wrapper_query_hash_supported seed0 root0); smt().
  conseq (wrapper_query_sign_supported seed0 root0); smt().
qed.

lemma wrapper_verifier_exposures_preserved
  (V <: PublicVerifier {-Independent,-ExposureLog}) seed0 root0 :
  hoare [V(Independent).verify :
    wrapper_exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries ==>
    wrapper_exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (wrapper_verifier_histories V s0 h0); smt(extends_refl wrapper_exposures_extends).
qed.

lemma wrapper_query_client_history
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog,-Independent}) seed0 root0 :
  hoare [A(WrapperQueryExposureSession(Independent)).run :
    WrapperSession.seed=seed0 /\ WrapperSession.root=root0 /\
    wrapper_exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries /\
    exposure_accounting ExposureLog.entries WrapperSession.signed_messages WrapperSession.sign_calls WrapperSession.sign_limit ==>
    WrapperSession.seed=seed0 /\ WrapperSession.root=root0 /\
    wrapper_exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries /\
    exposure_accounting ExposureLog.entries WrapperSession.signed_messages WrapperSession.sign_calls WrapperSession.sign_limit].
proof.
  conseq (wrapper_query_client_supported A seed0 root0) (wrapper_exposure_client_accounting A Independent); smt().
qed.

lemma wrapper_query_driver_history
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog,-Independent}) seed0 root0 qs0 :
  0<=qs0 =>
  hoare [WrapperQueryDriver(A,Independent).run : seed=seed0 /\ root=root0 /\ qs=qs0 ==>
    WrapperSession.seed=seed0 /\ WrapperSession.root=root0 /\ WrapperSession.sign_limit=qs0 /\
    wrapper_exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries /\
    exposure_accounting ExposureLog.entries WrapperSession.signed_messages WrapperSession.sign_calls qs0].
proof.
  move=> hqs; proc; seq 5 : (seed=seed0 /\ root=root0 /\
    WrapperSession.seed=seed0 /\ WrapperSession.root=root0 /\ WrapperSession.sign_limit=qs0 /\
    wrapper_exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries /\
    exposure_accounting ExposureLog.entries WrapperSession.signed_messages WrapperSession.sign_calls qs0).
  + call (wrapper_query_client_history A seed0 root0); wp; inline WrapperSession(Independent).init.
    auto; rewrite /wrapper_exposures_supported /exposures_supported /minimum_entries
      /exposure_accounting /exposure_messages; smt(mem_nil).
  sp 2; if; last auto.
  call (wrapper_verifier_exposures_preserved RawSigner seed0 root0); auto.
qed.

lemma wrapper_query_context_history
  (A <: WrapperClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) qs0 :
  0<=qs0 =>
  hoare [WrapperQueryContext(A,Independent).run : WrapperLimits.sign_cap=qs0 ==>
    wrapper_exposures_supported Independent.rawhistory Independent.secrethistory
      WrapperSession.seed WrapperSession.root ExposureLog.entries /\
    exposure_accounting ExposureLog.entries WrapperSession.signed_messages WrapperSession.sign_calls qs0].
proof.
  move=> hqs; proc; seq 1 : (WrapperLimits.sign_cap=qs0).
  + call (_ : true ==> true); first by trivial. auto.
  exists* inputs; elim* => inputs0.
  call (wrapper_query_driver_history A inputs0.`3 inputs0.`4 qs0 hqs); auto; smt().
qed.

lemma wrapper_byte_canonical_history
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) qs0 :
  0<=qs0 =>
  hoare [IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run : WrapperLimits.sign_cap=qs0 ==>
    exposures_supported Independent.rawhistory Independent.secrethistory
      WrapperSession.seed WrapperSession.root ExposureLog.entries /\
    minimum_entries Independent.rawhistory Independent.secrethistory
      WrapperSession.seed WrapperSession.root ExposureLog.entries /\
    exposure_accounting ExposureLog.entries WrapperSession.signed_messages WrapperSession.sign_calls qs0].
proof.
  move=> hqs; proc; call (wrapper_query_context_history (WrapperByteLift(A)) qs0 hqs);
    inline Independent.init; auto; rewrite /wrapper_exposures_supported; smt().
qed.

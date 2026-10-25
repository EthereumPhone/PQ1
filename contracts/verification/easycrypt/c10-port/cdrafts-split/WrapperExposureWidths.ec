(* The first returned signature has the native width even after the second
   signing pass and the wrapper's public verification calls. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawSigner RawSignature RawWrapper WrapperSession WrapperByteSession.
require import WrapperExposureLog WrapperQueryDriver ExposureLog ClientQueryLog ExposureWidths.
require import SignerTrace VerifierHistory IndependentWidths IndependentSignerWidth.

lemma wrapper_verifier_valid (V <: PublicVerifier {-Independent}) :
  hoare [V(Independent).verify : independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc (independent_tables_valid Independent.rawhistory Independent.secrethistory) => //.
  conseq independent_hash_width; smt().
qed.

lemma raw_wrapper_valid_width :
  hoare [RawWrapper(Independent).sign : independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    (res<>None => signature_width (oget res))].
proof.
  have hw : hoare [RawSigner(Independent).sign :
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    (res<>None => signature_width (oget res))]
    by conseq (complete_signer_valid RawSigner) independent_signer_width; smt().
  proc; sp 1; if; last auto.
  seq 1 : (result=None /\ independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    (first<>None => signature_width (oget first))).
  + call hw; auto.
  if; last auto.
  seq 1 : (result=None /\ independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    signature_width (oget first)).
  + call (complete_signer_valid RawSigner); auto; smt().
  if; last auto.
  wp; call (wrapper_verifier_valid RawSigner); auto.
qed.

lemma wrapper_sign_valid_width :
  hoare [WrapperSession(Independent).sign : independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    (res<>None => signature_width (oget res))].
proof.
  proc; sp 1; if; last auto.
  wp; call raw_wrapper_valid_width; auto.
qed.

lemma wrapper_query_hash_width :
  hoare [WrapperQueryExposureSession(Independent).hash :
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ exposures_width ExposureLog.entries ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ exposures_width ExposureLog.entries].
proof.
  proc; call (_ : independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + proc; sp 1; if; auto; wp; call independent_hash_width; auto; smt().
  auto.
qed.

lemma wrapper_query_sign_width :
  hoare [WrapperQueryExposureSession(Independent).sign :
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ exposures_width ExposureLog.entries ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ exposures_width ExposureLog.entries].
proof. proc; wp; call wrapper_sign_valid_width; auto; smt(exposures_width_rcons). qed.

lemma wrapper_query_client_width
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog,-Independent}) :
  hoare [A(WrapperQueryExposureSession(Independent)).run :
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ exposures_width ExposureLog.entries ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ exposures_width ExposureLog.entries].
proof.
  proc (independent_tables_valid Independent.rawhistory Independent.secrethistory /\ exposures_width ExposureLog.entries) => //.
  + exact wrapper_query_hash_width.
  exact wrapper_query_sign_width.
qed.

lemma wrapper_query_driver_width
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog,-Independent}) :
  hoare [WrapperQueryDriver(A,Independent).run :
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ exposures_width ExposureLog.entries].
proof.
  proc; seq 5 : (independent_tables_valid Independent.rawhistory Independent.secrethistory /\ exposures_width ExposureLog.entries).
  + call (wrapper_query_client_width A); wp; inline WrapperSession(Independent).init.
    auto; rewrite /exposures_width; smt(mem_nil).
  sp 2; if; last auto.
  call (verifier_exposure_width RawSigner); auto.
qed.

lemma wrapper_query_context_width
  (A <: WrapperClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) :
  hoare [WrapperQueryContext(A,Independent).run :
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exposures_width ExposureLog.entries].
proof.
  proc; call (wrapper_query_driver_width A); inline KeygenPreparation(PreparationView(Independent)).run.
  wp; call (width_keygen_valid RawKeygen); auto.
qed.

lemma wrapper_byte_exposure_width
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) :
  hoare [IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run : true ==> exposures_width ExposureLog.entries].
proof. proc; call (wrapper_query_context_width (WrapperByteLift(A))); call independent_init_valid; auto. qed.

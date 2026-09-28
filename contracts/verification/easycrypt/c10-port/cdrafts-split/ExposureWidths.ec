(* Every returned response retains its exact signature widths. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawSigner RawSignature FullSession ByteSession ExposureLog ExposureDriver.
require import SignerTrace VerifierHistory IndependentWidths IndependentSignerWidth.

op exposures_width (entries : signing_exposure list) =
  forall entry, List.mem entries entry => signature_width entry.`2.

lemma exposures_width_rcons entries entry :
  exposures_width (rcons entries entry) = (exposures_width entries /\ signature_width entry.`2).
proof. rewrite /exposures_width; smt(mem_rcons). qed.

lemma complete_signer_valid (S <: CompleteSigner {-Independent}) :
  hoare [S(Independent).sign : independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc (independent_tables_valid Independent.rawhistory Independent.secrethistory) => //.
  + conseq independent_hash_width; smt().
  conseq independent_derive_width; smt().
qed.

lemma full_sign_valid_width :
  hoare [FullSession(Independent).sign : independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    (res<>None => signature_width (oget res))].
proof.
  have hw : hoare [RawSigner(Independent).sign :
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    (res<>None => signature_width (oget res))]
    by conseq (complete_signer_valid RawSigner) independent_signer_width; smt().
  proc; sp 1; if; last auto.
  wp; call hw; auto.
qed.

lemma exposure_hash_width :
  hoare [ExposureSession(Independent).hash :
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ exposures_width ExposureLog.entries ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ exposures_width ExposureLog.entries].
proof. proc; sp 1; if; auto; wp; call independent_hash_width; auto; smt(). qed.

lemma exposure_sign_width :
  hoare [ExposureSession(Independent).sign :
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ exposures_width ExposureLog.entries ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ exposures_width ExposureLog.entries].
proof. proc; wp; call full_sign_valid_width; auto; smt(exposures_width_rcons). qed.

lemma exposure_client_width (A <: FullClient {-FullSession,-ExposureLog,-Independent}) :
  hoare [A(ExposureSession(Independent)).run :
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ exposures_width ExposureLog.entries ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ exposures_width ExposureLog.entries].
proof.
  proc (independent_tables_valid Independent.rawhistory Independent.secrethistory /\ exposures_width ExposureLog.entries) => //.
  + exact exposure_hash_width.
  exact exposure_sign_width.
qed.

lemma verifier_exposure_width (V <: PublicVerifier {-Independent,-ExposureLog}) :
  hoare [V(Independent).verify :
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ exposures_width ExposureLog.entries ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ exposures_width ExposureLog.entries].
proof.
  proc (independent_tables_valid Independent.rawhistory Independent.secrethistory /\ exposures_width ExposureLog.entries) => //.
  conseq independent_hash_width; smt().
qed.

lemma exposure_driver_width (A <: FullClient {-FullSession,-ExposureLog,-Independent}) :
  hoare [ExposureDriver(A,Independent).run :
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ exposures_width ExposureLog.entries].
proof.
  proc; seq 3 : (independent_tables_valid Independent.rawhistory Independent.secrethistory /\ exposures_width ExposureLog.entries).
  + call (exposure_client_width A); wp; inline FullSession(Independent).init.
    auto; rewrite /exposures_width; smt(mem_nil).
  sp 1; if; last auto.
  call (verifier_exposure_width RawSigner); auto.
qed.

lemma exposure_context_width
  (A <: FullClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-Independent}) :
  hoare [ExposureContext(A,Independent).run :
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exposures_width ExposureLog.entries].
proof.
  proc; call (exposure_driver_width A); inline KeygenPreparation(PreparationView(Independent)).run.
  wp; call (width_keygen_valid RawKeygen); auto.
qed.

lemma byte_exposure_width
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-Independent}) :
  hoare [IndependentGame(ExposureContext(ByteLift(A))).run : true ==> exposures_width ExposureLog.entries].
proof. proc; call (exposure_context_width (ByteLift(A))); call independent_init_valid; auto. qed.

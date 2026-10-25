(* Admitted attempts are charged even if nothing is released. Freshness and
   exposure counts track only released signatures; raw logs track only client
   queries forwarded through the public-query cap. *)
require import AllCore List.
require import C10RawOracle PrefixGuess PrefixHybrid RawSigner WrapperSession.
require import ExposureLog ExposureAccounting ClientQueryLog WrapperExposureLog.

lemma wrapper_exposure_hash_accounting
  (O <: PrefixOracle {-WrapperSession,-ExposureLog,-ClientQueryLog}) :
  hoare [WrapperQueryExposureSession(O).hash :
    exposure_accounting ExposureLog.entries WrapperSession.signed_messages WrapperSession.sign_calls WrapperSession.sign_limit ==>
    exposure_accounting ExposureLog.entries WrapperSession.signed_messages WrapperSession.sign_calls WrapperSession.sign_limit].
proof.
  proc; call (_ : true ==> true); first by trivial.
  auto.
qed.

lemma wrapper_exposure_sign_accounting
  (O <: PrefixOracle {-WrapperSession,-ExposureLog,-ClientQueryLog}) :
  hoare [WrapperQueryExposureSession(O).sign :
    exposure_accounting ExposureLog.entries WrapperSession.signed_messages WrapperSession.sign_calls WrapperSession.sign_limit ==>
    exposure_accounting ExposureLog.entries WrapperSession.signed_messages WrapperSession.sign_calls WrapperSession.sign_limit].
proof.
  proc; inline WrapperSession(O).sign; wp; sp 7; if.
  + wp; call (_ : true ==> true); first by trivial.
    auto; rewrite /exposure_accounting; smt(exposure_messages_rcons size_rcons).
  auto; rewrite /exposure_accounting; smt().
qed.

lemma wrapper_exposure_client_accounting
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-WrapperSession,-ExposureLog,-ClientQueryLog}) :
  hoare [A(WrapperQueryExposureSession(O)).run :
    exposure_accounting ExposureLog.entries WrapperSession.signed_messages WrapperSession.sign_calls WrapperSession.sign_limit ==>
    exposure_accounting ExposureLog.entries WrapperSession.signed_messages WrapperSession.sign_calls WrapperSession.sign_limit].
proof.
  proc (exposure_accounting ExposureLog.entries WrapperSession.signed_messages WrapperSession.sign_calls WrapperSession.sign_limit) => //.
  + exact (wrapper_exposure_hash_accounting O).
  exact (wrapper_exposure_sign_accounting O).
qed.

lemma wrapper_query_hash_accounting
  (O <: PrefixOracle {-WrapperSession,-ExposureLog,-ClientQueryLog}) :
  hoare [WrapperQueryExposureSession(O).hash :
    client_query_accounting ClientQueryLog.inputs WrapperSession.raw_calls WrapperSession.raw_limit ==>
    client_query_accounting ClientQueryLog.inputs WrapperSession.raw_calls WrapperSession.raw_limit].
proof.
  proc; inline WrapperSession(O).hash; sp 0; if.
  + rcondt 4; first by auto.
    wp; call (_ : true ==> true); first by trivial.
    auto; rewrite /client_query_accounting; smt(size_rcons).
  rcondf 3; first by auto.
  auto.
qed.

lemma wrapper_query_sign_accounting
  (O <: PrefixOracle {-WrapperSession,-ExposureLog,-ClientQueryLog}) :
  hoare [WrapperQueryExposureSession(O).sign :
    client_query_accounting ClientQueryLog.inputs WrapperSession.raw_calls WrapperSession.raw_limit ==>
    client_query_accounting ClientQueryLog.inputs WrapperSession.raw_calls WrapperSession.raw_limit].
proof.
  proc; wp; call (_ : true ==> true); first by trivial.
  auto.
qed.

lemma wrapper_query_client_accounting
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-WrapperSession,-ExposureLog,-ClientQueryLog}) :
  hoare [A(WrapperQueryExposureSession(O)).run :
    client_query_accounting ClientQueryLog.inputs WrapperSession.raw_calls WrapperSession.raw_limit ==>
    client_query_accounting ClientQueryLog.inputs WrapperSession.raw_calls WrapperSession.raw_limit].
proof.
  proc (client_query_accounting ClientQueryLog.inputs WrapperSession.raw_calls WrapperSession.raw_limit) => //.
  + exact (wrapper_query_hash_accounting O).
  exact (wrapper_query_sign_accounting O).
qed.

lemma wrapper_query_sign_keeps_inputs
  (O <: PrefixOracle {-WrapperSession,-ExposureLog,-ClientQueryLog}) inputs0 :
  hoare [WrapperQueryExposureSession(O).sign : ClientQueryLog.inputs=inputs0 ==>
    ClientQueryLog.inputs=inputs0].
proof.
  proc; wp; call (_ : true ==> true); first by trivial.
  auto.
qed.

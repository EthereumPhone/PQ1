(* Exact key and released-message widths for the wrapper accepted-pool game. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion WrapperSession.
require import ExposureLog ClientQueryLog WrapperExposureLog WrapperQueryDriver RawSignature.
require import IndependentWidths CoveredOutputPool AcceptedPrefixSampling HmsgMemoOracle HmsgMemoFacts.
require import HmsgSessionCount HmsgSessionMetadata WrapperHmsgCount.

lemma wrapper_sign_message_width (O <: PrefixOracle {-WrapperSession,-ExposureLog,-ClientQueryLog}) message0 :
  hoare[WrapperSession(O).sign : message=message0 ==> res<>None => size message0=32].
proof.
  proc; sp 1; if; last by auto.
  wp; call (_ : true ==> true); first by trivial.
  auto; smt().
qed.
lemma wrapper_query_client_message_width
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-WrapperSession,-ExposureLog,-ClientQueryLog}) :
  hoare[A(WrapperQueryExposureSession(O)).run : logged_message_width ExposureLog.entries ==>
    logged_message_width ExposureLog.entries].
proof.
  proc (logged_message_width ExposureLog.entries)=> //.
  + proc; call (_ : true ==> true); first by trivial.
    auto.
  proc; wp; exists* message; elim*=> m; call (wrapper_sign_message_width O m); auto; smt(logged_message_rcons).
qed.
lemma wrapper_query_driver_metadata
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-WrapperSession,-ExposureLog,-ClientQueryLog}) :
  hoare[WrapperQueryDriver(A,O).run : size seed=32 /\ size root=32 ==>
    size WrapperSession.seed=32 /\ size WrapperSession.root=32 /\ logged_message_width ExposureLog.entries].
proof.
  proc; seq 5 : (size WrapperSession.seed=32 /\ size WrapperSession.root=32 /\ logged_message_width ExposureLog.entries).
  + call (wrapper_query_client_message_width A O); wp; inline WrapperSession(O).init; auto; rewrite /logged_message_width; smt().
  sp 2; if; last by auto.
  call (_ : true ==> true); first by trivial.
  auto.
qed.
lemma hmsg_wrapper_query_context_metadata
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog,-HmsgMemo,-AcceptedSamples,-KeygenInputs,-WrapperLimits}) :
  hoare[WrapperQueryContext(A,HmsgMemo(AcceptedSamples)).run :
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=0 ==>
    size WrapperSession.seed=32 /\ size WrapperSession.root=32 /\ logged_message_width ExposureLog.entries].
proof.
  proc; call (wrapper_query_driver_metadata A (HmsgMemo(AcceptedSamples))).
  call (hmsg_keygen_preparation_count 0); auto; smt().
qed.

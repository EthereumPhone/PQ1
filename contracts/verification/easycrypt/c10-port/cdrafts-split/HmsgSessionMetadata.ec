(* Public-key and logged-message widths for the accepted-pool game. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion FullSession.
require import ExposureLog ClientQueryLog ClientQueryDriver RawSignature.
require import IndependentWidths.
require import CoveredOutputPool AcceptedPrefixSampling HmsgMemoOracle HmsgMemoFacts HmsgSessionCount.

lemma logged_message_rcons entries message signature :
  logged_message_width entries => size message=32 => logged_message_width (rcons entries (message,signature)).
proof. rewrite /logged_message_width; smt(mem_rcons). qed.
lemma full_sign_message_width (O <: PrefixOracle {-FullSession,-ExposureLog,-ClientQueryLog}) message0 :
  hoare[FullSession(O).sign : message=message0 ==> res<>None => size message0=32].
proof.
  proc; sp 1; if; last by auto.
  wp; call (_ : true ==> true); first by trivial.
  auto; smt().
qed.
lemma query_client_message_width
  (A <: FullClient {-FullSession,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-FullSession,-ExposureLog,-ClientQueryLog}) :
  hoare[A(QueryExposureSession(O)).run : logged_message_width ExposureLog.entries ==>
    logged_message_width ExposureLog.entries].
proof.
  proc (logged_message_width ExposureLog.entries)=> //.
  + proc; call (_ : true ==> true); first by trivial.
    auto.
  proc; wp; exists* message; elim*=> m; call (full_sign_message_width O m); auto; smt(logged_message_rcons).
qed.
lemma query_driver_metadata
  (A <: FullClient {-FullSession,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-FullSession,-ExposureLog,-ClientQueryLog}) :
  hoare[ClientQueryDriver(A,O).run : size seed=32 /\ size root=32 ==>
    size FullSession.seed=32 /\ size FullSession.root=32 /\ logged_message_width ExposureLog.entries].
proof.
  proc; seq 5 : (size FullSession.seed=32 /\ size FullSession.root=32 /\ logged_message_width ExposureLog.entries).
  + call (query_client_message_width A O); wp; inline FullSession(O).init; auto; rewrite /logged_message_width; smt().
  sp 2; if; last by auto.
  call (_ : true ==> true); first by trivial.
  auto.
qed.
lemma hmsg_query_context_metadata
  (A <: FullClient {-FullSession,-ExposureLog,-ClientQueryLog,-HmsgMemo,-AcceptedSamples,-KeygenInputs,-FullLimits}) :
  hoare[ClientQueryContext(A,HmsgMemo(AcceptedSamples)).run :
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=0 ==>
    size FullSession.seed=32 /\ size FullSession.root=32 /\ logged_message_width ExposureLog.entries].
proof.
  proc; call (query_driver_metadata A (HmsgMemo(AcceptedSamples))).
  call (hmsg_keygen_preparation_count 0); auto; smt().
qed.

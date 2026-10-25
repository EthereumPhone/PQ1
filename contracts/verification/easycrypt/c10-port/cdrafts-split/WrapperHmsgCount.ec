(* Accepted H_msg evaluations include both internal sign calls and internal
   verification, even when the wrapper withholds the final signature. *)
require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen RawSigner RawSignature.
require import RawWrapper WrapperSession WrapperExposureLog WrapperQueryDriver.
require import ExposureLog ClientQueryLog IndependentWidths.
require import AcceptedPrefixSampling HmsgMemoOracle HmsgMemoFacts HmsgShapes HmsgKeygenCount HmsgSignerCount HmsgSessionCount.

lemma hmsg_raw_wrapper_count c :
  hoare[RawWrapper(HmsgMemo(AcceptedSamples)).sign :
    size seed=32 /\ size shuffle_a=32 /\ size shuffle_b=32 /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ c<=HmsgMemo.accepted_calls<=c+3 /\
    (res<>None => signature_width (oget res))].
proof.
  proc; sp 1; if; last by auto; smt().
  seq 1 : (size seed=32 /\ size shuffle_b=32 /\ result=None /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ c<=HmsgMemo.accepted_calls<=c+1 /\
    (first<>None => signature_width (oget first))).
  + call (hmsg_sign_count c); auto.
  if; last by auto; smt().
  seq 1 : (size seed=32 /\ result=None /\ signature_width (oget first) /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ c<=HmsgMemo.accepted_calls<=c+2).
  + exists* HmsgMemo.accepted_calls; elim*=> k; call (hmsg_sign_count k); auto; smt().
  if; last by auto; smt().
  wp; exists* HmsgMemo.accepted_calls; elim*=> k; call (hmsg_verify_count k); auto; smt().
qed.

lemma hmsg_wrapper_hash_count c :
  hoare[WrapperSession(HmsgMemo(AcceptedSamples)).hash :
    size WrapperSession.seed=32 /\ 0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    HmsgMemo.accepted_calls<=c+WrapperSession.raw_calls+3*WrapperSession.sign_calls ==>
    size WrapperSession.seed=32 /\ 0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    HmsgMemo.accepted_calls<=c+WrapperSession.raw_calls+3*WrapperSession.sign_calls].
proof.
  proc; sp 1; if; last by auto.
  wp; exists* HmsgMemo.accepted_calls; elim*=> k;
    call (hmsg_hash_width_increment k); auto; smt().
qed.
lemma hmsg_wrapper_sign_count c :
  hoare[WrapperSession(HmsgMemo(AcceptedSamples)).sign :
    size WrapperSession.seed=32 /\ 0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    HmsgMemo.accepted_calls<=c+WrapperSession.raw_calls+3*WrapperSession.sign_calls ==>
    size WrapperSession.seed=32 /\ 0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    HmsgMemo.accepted_calls<=c+WrapperSession.raw_calls+3*WrapperSession.sign_calls].
proof.
  proc; sp 1; if; last by auto.
  wp; exists* HmsgMemo.accepted_calls; elim*=> k;
    call (hmsg_raw_wrapper_count k); auto; smt().
qed.
lemma hmsg_wrapper_query_client_count
  (A <: WrapperClient {-WrapperSession,-HmsgMemo,-AcceptedSamples,-ExposureLog,-ClientQueryLog}) c :
  hoare[A(WrapperQueryExposureSession(HmsgMemo(AcceptedSamples))).run :
    size WrapperSession.seed=32 /\ 0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    HmsgMemo.accepted_calls<=c+WrapperSession.raw_calls+3*WrapperSession.sign_calls ==>
    size WrapperSession.seed=32 /\ 0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    HmsgMemo.accepted_calls<=c+WrapperSession.raw_calls+3*WrapperSession.sign_calls].
proof.
  proc (size WrapperSession.seed=32 /\ 0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    HmsgMemo.accepted_calls<=c+WrapperSession.raw_calls+3*WrapperSession.sign_calls) => //.
  + proc; call (hmsg_wrapper_hash_count c); auto.
  proc; wp; call (hmsg_wrapper_sign_count c); auto.
qed.
lemma hmsg_wrapper_query_driver_count
  (A <: WrapperClient {-WrapperSession,-HmsgMemo,-AcceptedSamples,-ExposureLog,-ClientQueryLog}) c qr0 qs0 :
  0<=qr0 => 0<=qs0 =>
  hoare[WrapperQueryDriver(A,HmsgMemo(AcceptedSamples)).run :
    size seed=32 /\ qr=qr0 /\ qs=qs0 /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls<=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls<=c+qr0+3*qs0+1].
proof.
  move=> hr hs; proc; seq 5 : (size seed=32 /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls<=c+qr0+3*qs0).
  + call (hmsg_wrapper_query_client_count A c); wp; inline WrapperSession(HmsgMemo(AcceptedSamples)).init; auto; smt().
  sp 2; if; last by auto; smt().
  exists* HmsgMemo.accepted_calls; elim*=> k; call (hmsg_verify_count k); auto; smt().
qed.
lemma hmsg_wrapper_query_context_count
  (A <: WrapperClient {-WrapperSession,-HmsgMemo,-AcceptedSamples,-ExposureLog,-ClientQueryLog,-WrapperLimits,-KeygenInputs}) qr qs :
  0<=qr => 0<=qs =>
  hoare[WrapperQueryContext(A,HmsgMemo(AcceptedSamples)).run :
    WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=0 ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls<=qr+3*qs+1].
proof.
  move=> hr hs; proc; call (hmsg_wrapper_query_driver_count A 0 qr qs hr hs).
  call (hmsg_keygen_preparation_count 0); auto; smt().
qed.

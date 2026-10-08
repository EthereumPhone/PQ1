(* Complete initialized adaptive session: accepted H_msg calls <= qr+qs+1. *)
require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen RawSigner RawSignature FullSession.
require import ExposureLog ClientQueryLog ClientQueryDriver IndependentWidths.
require import AcceptedPrefixSampling HmsgMemoOracle HmsgMemoFacts HmsgShapes HmsgKeygenCount HmsgSignerCount.

lemma hmsg_keygen_preparation_count c :
  hoare[KeygenPreparation(HmsgPreparation).run :
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c /\
    size res.`3=32 /\ size res.`4=32].
proof. proc; call (hmsg_keygen_root_count c); auto; smt(node_width pad_node_width). qed.

lemma hmsg_full_hash_count c :
  hoare[FullSession(HmsgMemo(AcceptedSamples)).hash :
    size FullSession.seed=32 /\ 0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    HmsgMemo.accepted_calls<=c+FullSession.raw_calls+FullSession.sign_calls ==>
    size FullSession.seed=32 /\ 0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    HmsgMemo.accepted_calls<=c+FullSession.raw_calls+FullSession.sign_calls].
proof.
  proc; sp 1; if; last by auto.
  wp; exists* HmsgMemo.accepted_calls; elim*=> k;
    call (hmsg_hash_width_increment k); auto; smt().
qed.
lemma hmsg_full_sign_count c :
  hoare[FullSession(HmsgMemo(AcceptedSamples)).sign :
    size FullSession.seed=32 /\ 0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    HmsgMemo.accepted_calls<=c+FullSession.raw_calls+FullSession.sign_calls ==>
    size FullSession.seed=32 /\ 0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    HmsgMemo.accepted_calls<=c+FullSession.raw_calls+FullSession.sign_calls].
proof.
  proc; sp 1; if; last by auto.
  wp; exists* HmsgMemo.accepted_calls; elim*=> k;
    call (hmsg_sign_count k); auto; smt().
qed.
lemma hmsg_query_client_count
  (A <: FullClient {-FullSession,-HmsgMemo,-AcceptedSamples,-ExposureLog,-ClientQueryLog}) c :
  hoare[A(QueryExposureSession(HmsgMemo(AcceptedSamples))).run :
    size FullSession.seed=32 /\ 0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    HmsgMemo.accepted_calls<=c+FullSession.raw_calls+FullSession.sign_calls ==>
    size FullSession.seed=32 /\ 0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    HmsgMemo.accepted_calls<=c+FullSession.raw_calls+FullSession.sign_calls].
proof.
  proc (size FullSession.seed=32 /\ 0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    HmsgMemo.accepted_calls<=c+FullSession.raw_calls+FullSession.sign_calls) => //.
  + proc; call (hmsg_full_hash_count c); auto.
  proc; wp; call (hmsg_full_sign_count c); auto.
qed.
lemma hmsg_query_driver_count
  (A <: FullClient {-FullSession,-HmsgMemo,-AcceptedSamples,-ExposureLog,-ClientQueryLog}) c qr0 qs0 :
  0<=qr0 => 0<=qs0 =>
  hoare[ClientQueryDriver(A,HmsgMemo(AcceptedSamples)).run :
    size seed=32 /\ qr=qr0 /\ qs=qs0 /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls<=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls<=c+qr0+qs0+1].
proof.
  move=> hr hs; proc; seq 5 : (size seed=32 /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls<=c+qr0+qs0).
  + call (hmsg_query_client_count A c); wp; inline FullSession(HmsgMemo(AcceptedSamples)).init; auto; smt().
  sp 2; if; last by auto; smt().
  exists* HmsgMemo.accepted_calls; elim*=> k; call (hmsg_verify_count k); auto; smt().
qed.
lemma hmsg_query_context_count
  (A <: FullClient {-FullSession,-HmsgMemo,-AcceptedSamples,-ExposureLog,-ClientQueryLog,-FullLimits,-KeygenInputs}) qr qs :
  0<=qr => 0<=qs =>
  hoare[ClientQueryContext(A,HmsgMemo(AcceptedSamples)).run :
    FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=0 ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls<=qr+qs+1].
proof.
  move=> hr hs; proc; call (hmsg_query_driver_count A 0 qr qs hr hs).
  call (hmsg_keygen_preparation_count 0); auto; smt().
qed.

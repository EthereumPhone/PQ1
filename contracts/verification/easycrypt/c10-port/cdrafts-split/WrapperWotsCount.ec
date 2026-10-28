(* Accepted WOTS evaluations include both internal sign calls and internal
   verification, even when the wrapper withholds the final signature. *)
require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen RawSigner RawSignature.
require import RawWrapper WrapperSession WrapperExposureLog WrapperQueryDriver.
require import ExposureLog ClientQueryLog IndependentWidths.
require import WotsAcceptedPrefix WotsMemoOracle WotsMemoFacts HmsgShapes WotsCountShapes WotsKeygenCount WotsSignerCount WotsSessionCount.

lemma wots_census_raw_wrapper_count c :
  hoare[RawWrapper(WotsMemo(WotsAcceptedSamples)).sign :
    size seed=32 /\ size shuffle_a=32 /\ size shuffle_b=32 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ c<=WotsMemo.accepted_calls<=c+10 /\
    (res<>None => signature_width (oget res))].
proof.
  proc; sp 1; if; last by auto; smt().
  seq 1 : (size seed=32 /\ size shuffle_b=32 /\ result=None /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ c<=WotsMemo.accepted_calls<=c+4 /\
    (first<>None => signature_width (oget first))).
  + call (wots_census_sign_count c); auto.
  if; last by auto; smt().
  seq 1 : (size seed=32 /\ result=None /\ signature_width (oget first) /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ c<=WotsMemo.accepted_calls<=c+8).
  + exists* WotsMemo.accepted_calls; elim*=> k; call (wots_census_sign_count k); auto; smt().
  if; last by auto; smt().
  wp; exists* WotsMemo.accepted_calls; elim*=> k; call (wots_census_verify_count k); auto; smt().
qed.

lemma wots_census_wrapper_hash_count c :
  hoare[WrapperSession(WotsMemo(WotsAcceptedSamples)).hash :
    size WrapperSession.seed=32 /\ 0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    WotsMemo.accepted_calls<=c+WrapperSession.raw_calls+10*WrapperSession.sign_calls ==>
    size WrapperSession.seed=32 /\ 0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    WotsMemo.accepted_calls<=c+WrapperSession.raw_calls+10*WrapperSession.sign_calls].
proof.
  proc; sp 1; if; last by auto.
  wp; exists* WotsMemo.accepted_calls; elim*=> k;
    call (wots_census_hash_width_increment k); auto; smt().
qed.
lemma wots_census_wrapper_sign_count c :
  hoare[WrapperSession(WotsMemo(WotsAcceptedSamples)).sign :
    size WrapperSession.seed=32 /\ 0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    WotsMemo.accepted_calls<=c+WrapperSession.raw_calls+10*WrapperSession.sign_calls ==>
    size WrapperSession.seed=32 /\ 0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    WotsMemo.accepted_calls<=c+WrapperSession.raw_calls+10*WrapperSession.sign_calls].
proof.
  proc; sp 1; if; last by auto.
  wp; exists* WotsMemo.accepted_calls; elim*=> k;
    call (wots_census_raw_wrapper_count k); auto; smt().
qed.
lemma wots_census_wrapper_query_client_count
  (A <: WrapperClient {-WrapperSession,-WotsMemo,-WotsAcceptedSamples,-ExposureLog,-ClientQueryLog}) c :
  hoare[A(WrapperQueryExposureSession(WotsMemo(WotsAcceptedSamples))).run :
    size WrapperSession.seed=32 /\ 0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    WotsMemo.accepted_calls<=c+WrapperSession.raw_calls+10*WrapperSession.sign_calls ==>
    size WrapperSession.seed=32 /\ 0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    WotsMemo.accepted_calls<=c+WrapperSession.raw_calls+10*WrapperSession.sign_calls].
proof.
  proc (size WrapperSession.seed=32 /\ 0<=WrapperSession.raw_calls<=WrapperSession.raw_limit /\
    0<=WrapperSession.sign_calls<=WrapperSession.sign_limit /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    WotsMemo.accepted_calls<=c+WrapperSession.raw_calls+10*WrapperSession.sign_calls) => //.
  + proc; call (wots_census_wrapper_hash_count c); auto.
  proc; wp; call (wots_census_wrapper_sign_count c); auto.
qed.
lemma wots_census_wrapper_query_driver_count
  (A <: WrapperClient {-WrapperSession,-WotsMemo,-WotsAcceptedSamples,-ExposureLog,-ClientQueryLog}) c qr0 qs0 :
  0<=qr0 => 0<=qs0 =>
  hoare[WrapperQueryDriver(A,WotsMemo(WotsAcceptedSamples)).run :
    size seed=32 /\ qr=qr0 /\ qs=qs0 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls<=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls<=c+qr0+10*qs0+2].
proof.
  move=> hr hs; proc; seq 5 : (size seed=32 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls<=c+qr0+10*qs0).
  + call (wots_census_wrapper_query_client_count A c); wp; inline WrapperSession(WotsMemo(WotsAcceptedSamples)).init; auto; smt().
  sp 2; if; last by auto; smt().
  exists* WotsMemo.accepted_calls; elim*=> k; call (wots_census_verify_count k); auto; smt().
qed.
lemma wots_census_wrapper_query_context_count
  (A <: WrapperClient {-WrapperSession,-WotsMemo,-WotsAcceptedSamples,-ExposureLog,-ClientQueryLog,-WrapperLimits,-KeygenInputs}) qr qs :
  0<=qr => 0<=qs =>
  hoare[WrapperQueryContext(A,WotsMemo(WotsAcceptedSamples)).run :
    WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=0 ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls<=qr+10*qs+2].
proof.
  move=> hr hs; proc; call (wots_census_wrapper_query_driver_count A 0 qr qs hr hs).
  call (wots_census_keygen_preparation_count 0); auto; smt().
qed.

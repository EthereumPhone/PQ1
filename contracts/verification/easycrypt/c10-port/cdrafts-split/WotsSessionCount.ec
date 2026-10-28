(* Complete initialized adaptive session: accepted WOTS calls <= qr+4*qs+2. *)
require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen RawSigner RawSignature FullSession.
require import ExposureLog ClientQueryLog ClientQueryDriver IndependentWidths.
require import WotsAcceptedPrefix WotsMemoOracle WotsMemoFacts HmsgShapes WotsCountShapes WotsKeygenCount WotsSignerCount.

lemma wots_census_keygen_preparation_count c :
  hoare[KeygenPreparation(WotsPreparation).run :
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c /\
    size res.`3=32 /\ size res.`4=32].
proof. proc; call (wots_census_keygen_root_count c); auto; smt(node_width pad_node_width). qed.

lemma wots_census_full_hash_count c :
  hoare[FullSession(WotsMemo(WotsAcceptedSamples)).hash :
    size FullSession.seed=32 /\ 0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    WotsMemo.accepted_calls<=c+FullSession.raw_calls+4*FullSession.sign_calls ==>
    size FullSession.seed=32 /\ 0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    WotsMemo.accepted_calls<=c+FullSession.raw_calls+4*FullSession.sign_calls].
proof.
  proc; sp 1; if; last by auto.
  wp; exists* WotsMemo.accepted_calls; elim*=> k;
    call (wots_census_hash_width_increment k); auto; smt().
qed.
lemma wots_census_full_sign_count c :
  hoare[FullSession(WotsMemo(WotsAcceptedSamples)).sign :
    size FullSession.seed=32 /\ 0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    WotsMemo.accepted_calls<=c+FullSession.raw_calls+4*FullSession.sign_calls ==>
    size FullSession.seed=32 /\ 0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    WotsMemo.accepted_calls<=c+FullSession.raw_calls+4*FullSession.sign_calls].
proof.
  proc; sp 1; if; last by auto.
  wp; exists* WotsMemo.accepted_calls; elim*=> k;
    call (wots_census_sign_count k); auto; smt().
qed.
lemma wots_census_query_client_count
  (A <: FullClient {-FullSession,-WotsMemo,-WotsAcceptedSamples,-ExposureLog,-ClientQueryLog}) c :
  hoare[A(QueryExposureSession(WotsMemo(WotsAcceptedSamples))).run :
    size FullSession.seed=32 /\ 0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    WotsMemo.accepted_calls<=c+FullSession.raw_calls+4*FullSession.sign_calls ==>
    size FullSession.seed=32 /\ 0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    WotsMemo.accepted_calls<=c+FullSession.raw_calls+4*FullSession.sign_calls].
proof.
  proc (size FullSession.seed=32 /\ 0<=FullSession.raw_calls<=FullSession.raw_limit /\
    0<=FullSession.sign_calls<=FullSession.sign_limit /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    WotsMemo.accepted_calls<=c+FullSession.raw_calls+4*FullSession.sign_calls) => //.
  + proc; call (wots_census_full_hash_count c); auto.
  proc; wp; call (wots_census_full_sign_count c); auto.
qed.
lemma wots_census_query_driver_count
  (A <: FullClient {-FullSession,-WotsMemo,-WotsAcceptedSamples,-ExposureLog,-ClientQueryLog}) c qr0 qs0 :
  0<=qr0 => 0<=qs0 =>
  hoare[ClientQueryDriver(A,WotsMemo(WotsAcceptedSamples)).run :
    size seed=32 /\ qr=qr0 /\ qs=qs0 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls<=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls<=c+qr0+4*qs0+2].
proof.
  move=> hr hs; proc; seq 5 : (size seed=32 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls<=c+qr0+4*qs0).
  + call (wots_census_query_client_count A c); wp; inline FullSession(WotsMemo(WotsAcceptedSamples)).init; auto; smt().
  sp 2; if; last by auto; smt().
  exists* WotsMemo.accepted_calls; elim*=> k; call (wots_census_verify_count k); auto; smt().
qed.
lemma wots_census_query_context_count
  (A <: FullClient {-FullSession,-WotsMemo,-WotsAcceptedSamples,-ExposureLog,-ClientQueryLog,-FullLimits,-KeygenInputs}) qr qs :
  0<=qr => 0<=qs =>
  hoare[ClientQueryContext(A,WotsMemo(WotsAcceptedSamples)).run :
    FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=0 ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls<=qr+4*qs+2].
proof.
  move=> hr hs; proc; call (wots_census_query_driver_count A 0 qr qs hr hs).
  call (wots_census_keygen_preparation_count 0); auto; smt().
qed.

(* One WOTS search accepts at most one call; recovery adds at most one more.
   Cached accepted replies are included and never treated as fresh samples. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawWots RawShuffle RawSignature RawWidths.
require import IndependentWidths ClientGuessCandidates HmsgShapes WotsCountDomain.
require import WotsAcceptedPrefix WotsMemoOracle WotsMemoFacts WotsCountShapes.

lemma wots_census_wots_count c :
  hoare[RawWots(WotsPreparation).count : size seed=32 /\ size message=16 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    c<=WotsMemo.accepted_calls<=c+1 /\ (res=None => WotsMemo.accepted_calls=c) /\
    (res<>None => 0<=(oget res).`1<signing_budget)].
proof.
  proc; while (size seed=32 /\ size message=16 /\ 0<=i<=signing_budget /\
    (result<>None => 0<=(oget result).`1<signing_budget) /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    c<=WotsMemo.accepted_calls<=c+b2i(result<>None)).
  + exists* WotsMemo.accepted_calls; elim*=> k.
    wp; call (wots_census_hash_width_increment k); auto; rewrite /b2i; smt().
  auto; rewrite /b2i; smt().
qed.

lemma wots_census_wots_chain_count c :
  hoare[RawWots(WotsPreparation).chain : size seed=32 /\ size current=16 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c /\ size res=16].
proof.
  proc; while (size seed=32 /\ size current=16 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c).
  + wp; call (wots_noncount_width c); auto; smt(wots_census_noncount_chain raw_address_width node_width).
  auto.
qed.

lemma wots_census_wots_sign_count c :
  hoare[RawWots(WotsPreparation).sign : size seed=32 /\ size message=16 /\ size shuffle=32 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ c<=WotsMemo.accepted_calls<=c+1 /\
    (res<>None => rows_width 43 (oget res).`1 /\ 0<=(oget res).`2<signing_budget)].
proof.
  proc; seq 1 : (size seed=32 /\ size shuffle=32 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ c<=WotsMemo.accepted_calls<=c+1 /\
    (accepted<>None => 0<=(oget accepted).`1<signing_budget)).
  + call (wots_census_wots_count c); auto; smt().
  sp 1; if; last by auto.
  exists* WotsMemo.accepted_calls; elim*=> k.
  wp; while (size seed=32 /\ rows_width 43 sigma /\ 0<=(oget accepted).`1<signing_budget /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=k).
  + wp; call (wots_census_wots_chain_count k); call (wots_census_wots_private k);
      auto; smt(node_width rows_put).
  wp; call (wots_census_shuffle_permutation k); auto; smt(rows_zeros).
qed.

lemma wots_census_wots_recover_count c :
  hoare[RawWots(WotsPreparation).recover : size seed=32 /\ size message=16 /\ rows_width 43 sigma /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ c<=WotsMemo.accepted_calls<=c+1 /\ size res=16].
proof.
  proc; seq 1 : (size seed=32 /\ rows_width 43 sigma /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ c<=WotsMemo.accepted_calls<=c+1).
  + call (wots_census_hash_width_increment c); auto; smt().
  sp 1; if; last by auto; smt(size_nseq).
  exists* WotsMemo.accepted_calls; elim*=> k.
  wp; call (wots_noncount_width k); wp.
  while (size seed=32 /\ rows_width 43 sigma /\ 0<=i<=43 /\ size elements=i /\
    all (fun (x : raw_input) => size x=32) elements /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=k).
  + wp; call (wots_census_wots_chain_count k); auto;
      smt(rows_nth_width pad_node_width all_cat cats1 size_rcons).
  auto; smt(count_query_no_other_kind wots_census_compress_kind node_width).
qed.

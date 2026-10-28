(* Full FORS forest preserves the accepted WOTS-entry count. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawFors RawForest RawShuffle RawSignature RawWidths.
require import IndependentWidths ClientGuessCandidates WotsAcceptedPrefix WotsMemoOracle WotsMemoFacts HmsgShapes WotsCountShapes WotsCountDomain NodeQueryDomain WotsTreeCount.

lemma wots_census_auths_nth_width auths i : size auths=12 => all (rows_width 11) auths =>
  0<=i<12 => rows_width 11 (nth [] auths i).
proof. move=> hs /allP ha hi; apply ha; apply mem_nth; smt(). qed.
lemma wots_census_rows_rcons n rows x : rows_width n rows => size x=16 => rows_width (n+1) (rcons rows x).
proof. rewrite /rows_width size_rcons -cats1 all_cat /=; smt(). qed.
lemma wots_census_forest_compression_width seed ht roots : size seed=32 => rows_width 13 roots =>
  size (seed++address 0 ht 4 0 0 0 0++flatten (map pad roots))=480.
proof. move=> hs hr; by rewrite size_cat size_cat hs raw_address_width (padded_flatten_width roots 13 hr). qed.

lemma wots_census_forest_one_count c :
  hoare[RawForest(WotsPreparation).one : size seed=32 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c /\
    size res.`1=16 /\ rows_width 11 res.`2 /\ size res.`3=16].
proof. proc; call (wots_census_fors_recover_count c); call (wots_census_fors_sign_count c); auto. qed.
lemma wots_census_forest_sign_count c :
  hoare[RawForest(WotsPreparation).sign : size seed=32 /\ size shuffle=32 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c /\
    rows_width 13 res.`1 /\ size res.`2=12 /\ all (rows_width 11) res.`2 /\ size res.`3=16].
proof.
  proc; call (wots_noncount_width c); wp; call (wots_noncount_width c); wp;
    call (wots_census_fors_root_count c).
  while (size seed=32 /\ rows_width 13 secrets /\ size auths=12 /\ all (rows_width 11) auths /\
    rows_width 13 roots /\ independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c).
  + wp; call (wots_census_forest_one_count c); auto; smt(rows_put size_put all_put_preserved).
  wp; call (wots_census_shuffle_permutation c); call (wots_census_shuffle_derive c); auto;
    smt(all_nseq rows_zeros size_nseq rows_put node_width wots_census_noncount_chain raw_address_width wots_census_forest_compression_width count_query_no_other_kind wots_census_forest_kind).
qed.
lemma wots_census_forest_recover_count c :
  hoare[RawForest(WotsPreparation).recover : size seed=32 /\ rows_width 13 secrets /\
    size auths=12 /\ all (rows_width 11) auths /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c /\ size res=16].
proof.
  proc; call (wots_noncount_width c); wp; call (wots_noncount_width c).
  while (size seed=32 /\ rows_width 13 secrets /\ size auths=12 /\ all (rows_width 11) auths /\
    0<=t<=12 /\ rows_width t roots /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c).
  + wp; call (wots_census_fors_recover_count c); auto; smt(wots_census_auths_nth_width rows_nth_width wots_census_rows_rcons).
  auto;
    smt(rows_nth_width wots_census_rows_rcons wots_census_forest_compression_width wots_census_noncount_chain raw_address_width node_width count_query_no_other_kind wots_census_forest_kind).
qed.

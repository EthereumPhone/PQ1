(* Internal FORS and Merkle hashes do not consume accepted WOTS entries. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawKeygenCost RawFors RawMerkle RawSignature RawWidths RawTreeWidths.
require import IndependentWidths ClientGuessCandidates WotsAcceptedPrefix WotsMemoOracle WotsMemoFacts HmsgShapes WotsCountShapes WotsCountDomain NodeQueryDomain WotsKeygenCount.

lemma wots_census_fors_tree_count c :
  hoare[RawFors(WotsPreparation).tree : size seed=32 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c /\
    size res.`1=16 /\ rows_width 11 res.`2].
proof.
  proc; while (size seed=32 /\ valid_stack stack /\ rows_width 11 auth /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c).
  + wp; while (size seed=32 /\ valid_stack stack /\ rows_width 11 auth /\ size current=16 /\
      independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c).
    - wp; call (wots_noncount_width c); auto;
        smt(wots_census_noncount_pair node_query_merkle_kind node_query_fors_kind node_width valid_stack_tail stack_first_width rows_put).
    wp; call (wots_noncount_width c); wp; call (wots_census_fors_private c).
    auto; rewrite /valid_stack /=; smt(wots_census_noncount_chain raw_address_width node_width count_query_no_other_kind wots_census_forest_kind).
  auto; rewrite /valid_stack /=; smt(rows_zeros valid_stack_head).
qed.

lemma wots_census_fors_sign_count c :
  hoare[RawFors(WotsPreparation).sign : size seed=32 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c /\
    size res.`1=16 /\ rows_width 11 res.`2].
proof.
  proc; call (wots_census_fors_tree_count c); wp; call (wots_census_fors_private c); auto; smt(node_width).
qed.
lemma wots_census_fors_root_count c :
  hoare[RawFors(WotsPreparation).root : size seed=32 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c /\ size res=16].
proof. proc; call (wots_census_fors_tree_count c); auto. qed.

lemma wots_census_fors_recover_count c :
  hoare[RawFors(WotsPreparation).recover : size seed=32 /\ size secret=16 /\ rows_width 11 auth /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c /\ size res=16].
proof.
  proc; while (size seed=32 /\ rows_width 11 auth /\ size current=16 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c).
  + wp; call (wots_noncount_width c); auto;
      smt(wots_census_noncount_pair node_query_merkle_kind node_query_fors_kind node_width rows_nth_width).
  wp; call (wots_noncount_width c); auto; smt(wots_census_noncount_chain raw_address_width node_width count_query_no_other_kind wots_census_forest_kind).
qed.

lemma wots_census_merkle_build_count c :
  hoare[RawMerkle(WotsPreparation).build : size seed=32 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c /\
    rows_width 9 res.`1 /\ size res.`2=16].
proof.
  proc; while (size seed=32 /\ valid_stack stack /\ rows_width 9 keep /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c).
  + wp; while (size seed=32 /\ valid_stack stack /\ rows_width 9 keep /\ size current=16 /\
      independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c).
    - wp; call (wots_noncount_width c); auto;
        smt(wots_census_noncount_pair node_query_merkle_kind node_query_fors_kind node_width valid_stack_tail stack_first_width rows_put).
    wp; call (wots_census_leaf_count c); auto; rewrite /valid_stack /=; smt().
  auto; rewrite /valid_stack /=; smt(rows_zeros valid_stack_head).
qed.
lemma wots_census_merkle_recover_count c :
  hoare[RawMerkle(WotsPreparation).recover : size seed=32 /\ size leaf=16 /\ rows_width 9 auth /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c /\ size res=16].
proof.
  proc; while (size seed=32 /\ rows_width 9 auth /\ size current=16 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c).
  + wp; call (wots_noncount_width c); auto;
      smt(wots_census_noncount_pair node_query_merkle_kind node_query_fors_kind node_width rows_nth_width).
  auto.
qed.

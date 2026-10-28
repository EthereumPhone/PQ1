(* Key generation consumes no accepted WOTS entries. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawKeygenCost.
require import RawTreeWidths RawSignature IndependentWidths ClientGuessCandidates.
require import WotsAcceptedPrefix WotsMemoOracle WotsMemoFacts HmsgShapes WotsCountShapes WotsCountDomain NodeQueryDomain.

lemma wots_census_leaf_count c :
  hoare [RawKeygen(WotsPreparation).leaf :
    size seed=32 /\ independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    WotsMemo.accepted_calls=c /\ size res=16].
proof.
  proc; call (wots_noncount_width c); wp.
  while (size seed=32 /\ 0<=i<=43 /\ size elements=i /\ all (fun (x : raw_input) => size x=32) elements /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c).
  + wp; while (size seed=32 /\ size current=16 /\
      independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c).
    - wp; call (wots_noncount_width c); auto; smt(wots_census_noncount_chain raw_address_width node_width count_query_no_other_kind wots_census_forest_kind).
    wp; call (wots_census_wots_private c); auto; smt(node_width pad_node_width all_cat cats1 size_rcons).
  auto; smt(count_query_no_other_kind wots_census_compress_kind node_width).
qed.

lemma wots_census_keygen_root_count c :
  hoare [RawKeygen(WotsPreparation).root :
    size seed=32 /\ independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    WotsMemo.accepted_calls=c /\ size res=16].
proof.
  proc; while (size seed=32 /\ valid_stack stack /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c).
  + wp; while (size seed=32 /\ valid_stack stack /\ size current=16 /\
      independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c).
    - wp; call (wots_noncount_width c); auto;
        smt(wots_census_noncount_pair node_query_merkle_kind node_query_fors_kind node_width valid_stack_tail stack_first_width).
    wp; call (wots_census_leaf_count c); auto; rewrite /valid_stack /=; smt().
  auto; rewrite /valid_stack /=; smt(valid_stack_head).
qed.

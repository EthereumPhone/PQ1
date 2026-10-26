(* Actual signing charges at most two exceptional-address node queries per
   attempt. Header exhaustion and later WOTS failures retain their real paths. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle C10RawGrind C10Randomizer C10HashDomains PrefixGuess PrefixHybrid.
require import RawKeygen RawForest RawLayer RawSigner RoleGrind IndependentWidths NodeQueryDomain.
require import AddressedForsException AddressedForsExceptionCount AddressedShuffleExceptions.
require import AddressedForestExceptionCount AddressedWotsExceptionCount AddressedLayerExceptionCount.

lemma role_grind_exception_count q :
  hoare [RoleGrind(Independent).run :
    size seed=32 /\ size root=32 /\ size message=32 /\
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc; while (size seed=32 /\ size root=32 /\ size message=32 /\
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + wp; call (exceptional_hash_count_width q); wp; call (exceptional_derive_count_valid q).
    auto; smt(randomizer_width node_query_no_hmsg exceptional_fors_non_node size_cat size_nseq).
  auto.
qed.

lemma raw_signer_finish_exception_count q :
  hoare [RawSigner(Independent).finish :
    size seed=32 /\ size shuffle=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries=q+2 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc; wp; while (size seed=32 /\ size shuffle=32 /\
    exceptional_fors_count Independent.queries=q+2 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + wp; call (raw_layer_sign_exceptions (q+2)); auto.
  wp; call (raw_forest_sign_exception_count q); auto.
qed.

lemma raw_signer_sign_exception_bound q :
  hoare [RawSigner(Independent).sign :
    size seed=32 /\ size root=32 /\ size message=32 /\ size shuffle=32 /\
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    q<=exceptional_fors_count Independent.queries<=q+2 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc; seq 1 : (size seed=32 /\ size shuffle=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + call (role_grind_exception_count q); auto.
  sp 1; if; last by auto; smt().
  call (raw_signer_finish_exception_count q); auto; smt().
qed.

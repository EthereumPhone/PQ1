(* Full signer accounting removes only proved non-node grinder calls. *)
require import AllCore List Distr.
require import C10RawOracle C10RawGrind C10Counter C10Randomizer C10HashDomains.
require import PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawSigner RawForest RawLayer RoleGrind.
require import DomainQueryCount NodeQueryDomain DomainForestCost DomainLayerCost IndependentWidths HmsgShapes.

lemma domain_derive_width q :
  hoare[Independent.derive : independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    node_query_count Independent.queries<=q ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    node_query_count Independent.queries<=q /\ size res=256].
proof. conseq independent_derive_width (domain_derive_bound q); smt(). qed.
lemma domain_nonnode_width q :
  hoare[Independent.hash : independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    !node_query x /\ node_query_count Independent.queries<=q ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    node_query_count Independent.queries<=q /\ size res=256].
proof. conseq independent_hash_width (domain_hash_nonnode q); smt(). qed.

lemma domain_role_grind_cost q :
  hoare[RoleGrind(Independent).run : size seed=32 /\ size root=32 /\ size message=32 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ node_query_count Independent.queries<=q ==>
    node_query_count Independent.queries<=q].
proof.
  proc; while (size seed=32 /\ size root=32 /\ size message=32 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ node_query_count Independent.queries<=q).
  + seq 2 : (size seed=32 /\ size root=32 /\ size message=32 /\ size r=16 /\
      independent_tables_valid Independent.rawhistory Independent.secrethistory /\ node_query_count Independent.queries<=q).
    - wp; call (domain_derive_width q); auto; smt(randomizer_width).
    wp; call (domain_nonnode_width q); auto; smt(node_query_no_hmsg size_cat size_nseq).
  auto.
qed.

lemma domain_signer_finish_cost q :
  hoare[RawSigner(Independent).finish : size seed=32 /\ node_query_count Independent.queries <= q ==>
    node_query_count Independent.queries <= q+364892].
proof.
  proc; seq 2 : (size seed=32 /\ size forest.`3=16 /\ node_query_count Independent.queries <= q+53386).
  + call (domain_forest_sign_cost q); auto; smt().
  wp; while (size seed=32 /\ size current=16 /\ 0 <= layer <= 2 /\ node_query_count Independent.queries <= q+53386+layer*155753).
  + wp; exists* Independent.queries; elim* => zs; call (domain_layer_sign_cost (node_query_count zs)); auto; smt().
  auto; rewrite /signing_budget; smt().
qed.

lemma domain_signer_sign_cost q :
  hoare[RawSigner(Independent).sign : size seed=32 /\ size root=32 /\ size message=32 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ node_query_count Independent.queries<=q ==>
    node_query_count Independent.queries<=q+364892].
proof.
  proc; seq 1 : (size seed=32 /\ node_query_count Independent.queries<=q).
  + call (domain_role_grind_cost q); auto.
  sp 1; if; last by auto; smt().
  call (domain_signer_finish_cost q); auto.
qed.

lemma domain_signer_verify_cost q :
  hoare[RawSigner(Independent).verify : node_query_count Independent.queries <= q ==>
    node_query_count Independent.queries <= q+771].
proof.
  proc; seq 1 : (node_query_count Independent.queries <= q+1).
  + call (domain_hash_bound q); auto.
  sp 1; if; last by auto; smt().
  seq 2 : (node_query_count Independent.queries <= q+147).
  + call (domain_forest_recover_cost (q+1)); auto; smt().
  wp; while (0 <= layer <= 2 /\ node_query_count Independent.queries <= q+147+312*layer).
  + wp; exists* Independent.queries; elim* => zs; call (domain_layer_recover_cost (node_query_count zs)); auto; smt().
  auto; smt().
qed.

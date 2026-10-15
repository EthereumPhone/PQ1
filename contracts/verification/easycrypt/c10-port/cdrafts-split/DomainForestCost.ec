(* Conservative node-domain costs; other public inputs may remain charged. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.
require import RawFors RawForsCost RawShuffle RawForest PhysicalKeygenCost RoleGrindCost.
require import RawForestCost.
require import DomainQueryCount DomainForsCost DomainShuffleCost.

lemma domain_forest_one_cost q :
  hoare[RawForest(PreparationView(Independent)).one : node_query_count Independent.queries <= q ==>
    node_query_count Independent.queries <= q+4107].
proof.
  proc; seq 1 : (node_query_count Independent.queries <= q+4095).
  + call (domain_fors_sign_cost q); auto; smt().
  exists* Independent.queries; elim* => zs; call (domain_fors_recover_cost (node_query_count zs)); auto; smt().
qed.

lemma domain_forest_sign_cost q :
  hoare[RawForest(PreparationView(Independent)).sign : node_query_count Independent.queries <= q ==>
    node_query_count Independent.queries <= q+53386 /\ size res.`3 = 16].
proof.
  proc; seq 5 : (node_query_count Independent.queries <= q+5).
  + seq 4 : (node_query_count Independent.queries <= q+1).
    - call (domain_shuffle_derive_cost q); auto.
    exists* Independent.queries; elim* => zs; call (domain_shuffle_permutation_cost (node_query_count zs)); auto; smt().
  seq 2 : (node_query_count Independent.queries <= q+49289).
  + while (0 <= step <= 12 /\ node_query_count Independent.queries <= q+5+4107*step).
    - wp; exists* Independent.queries; elim* => zs; call (domain_forest_one_cost (node_query_count zs)); auto; smt().
    auto; smt().
  seq 1 : (node_query_count Independent.queries <= q+53384).
  + exists* Independent.queries; elim* => zs; call (domain_fors_root_cost (node_query_count zs)); auto; smt().
  seq 2 : (node_query_count Independent.queries <= q+53385).
  + exists* Independent.queries; elim* => zs; call (domain_hash_bound (node_query_count zs)); auto; smt().
  exists* Independent.queries; elim* => zs; call (domain_hash_bound (node_query_count zs)); auto; smt(node_width).
qed.

lemma domain_forest_recover_cost q :
  hoare[RawForest(PreparationView(Independent)).recover : node_query_count Independent.queries <= q ==>
    node_query_count Independent.queries <= q+146 /\ size res = 16].
proof.
  proc; call (domain_hash_bound (q+145)); wp; call (domain_hash_bound (q+144)).
  while (0 <= t <= 12 /\ node_query_count Independent.queries <= q+12*t).
  + exists* t; elim* => t0; wp; call (domain_fors_recover_cost (q+12*t0)); auto; smt().
  auto; smt(node_width).
qed.

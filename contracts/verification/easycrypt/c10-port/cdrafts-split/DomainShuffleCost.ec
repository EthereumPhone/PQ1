(* Conservative node-domain costs; other public inputs may remain charged. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle C10Bytes PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.
require import PhysicalKeygenCost RoleGrindCost.
require import RawShuffle.
require import DomainQueryCount .

lemma domain_shuffle_derive_cost q :
  hoare[RawShuffle(PreparationView(Independent)).derive : node_query_count Independent.queries <= q ==>
    node_query_count Independent.queries <= q+1].
proof. proc; sp 1; if.
  + wp; call (domain_hash_bound q); auto; smt().
  auto; smt(). qed.

lemma domain_shuffle_permutation_cost q :
  hoare[RawShuffle(PreparationView(Independent)).permutation : node_query_count Independent.queries <= q ==>
    node_query_count Independent.queries <= q+4].
proof.
  proc; sp 1; if; last by auto; smt().
  while (node_query_count Independent.queries <= q+4); first by auto.
  wp; while (0 <= blk <= 4 /\ node_query_count Independent.queries <= q+blk).
  + exists* blk; elim* => b; wp; call (domain_hash_bound (q+b)); auto; smt().
  auto; smt().
qed.

(* Conservative node-domain costs; other public inputs may remain charged. *)
require import AllCore List Distr BitEncoding IntDiv.
require import C10RawOracle C10RawGrind C10Bytes C10Counter.
require import PrefixGuess PrefixHybrid RoleGrindCost KeygenPrefixes.
require import RawKeygen.
require import AllCore List Distr IntDiv.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid RoleGrindCost KeygenPrefixes RawKeygen.
require import RawKeygenCost.
require import DomainQueryCount RawKeygenCost.

lemma domain_leaf_cost q0 :
  hoare[RawKeygen(PreparationView(Independent)).leaf : node_query_count Independent.queries <= q0 ==>
    node_query_count Independent.queries <= q0 + 302 /\ size res = 16].
proof.
  proc; call (domain_hash_bound (q0+301)); wp.
  while (0 <= i <= 43 /\ node_query_count Independent.queries <= q0+7*i).
  + wp; while (0 <= j <= 7 /\ node_query_count Independent.queries <= q0+7*i+j).
    - exists* i, j; elim* => i0 j0; wp.
      call (domain_hash_bound (q0+7*i0+j0)); auto; smt().
    wp; exists* i; elim* => i0; call (domain_wots_bound (q0+7*i0)); auto; smt().
  auto; smt(node_width).
qed.

lemma domain_root_cost q0 :
  hoare[RawKeygen(PreparationView(Independent)).root : node_query_count Independent.queries <= q0 ==>
    node_query_count Independent.queries <= q0 + 155135 /\ size res = 16].
proof.
  proc; while (0 <= kp <= 512 /\ size stack <= kp /\ (0 < kp => stack <> []) /\
    valid_stack stack /\ node_query_count Independent.queries <= q0+303*kp-size stack).
  + wp; while (0 <= kp < 512 /\ size stack <= kp /\ valid_stack stack /\
      size current = 16 /\ node_query_count Independent.queries <= q0+303*kp+302-size stack).
    - exists* kp, stack; elim* => kp0 st0.
      wp; call (domain_hash_bound (q0+303*kp0+302-size st0)); auto.
      smt(node_width size_behead size_ge0 valid_stack_tail).
    wp; exists* kp, stack; elim* => kp0 st0.
    call (domain_leaf_cost (q0+303*kp0-size st0)); auto.
    rewrite /valid_stack /=; smt(size_ge0).
  auto; rewrite /valid_stack /=; smt(size_ge0 size_eq0 valid_stack_head).
qed.

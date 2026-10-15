(* Conservative node-domain costs; other public inputs may remain charged. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawKeygenCost.
require import PhysicalKeygenCost RoleGrindCost RawFors.
require import RawForsCost.
require import DomainQueryCount DomainKeygenCost.

lemma domain_fors_tree_cost q :
  hoare[RawFors(PreparationView(Independent)).tree : node_query_count Independent.queries <= q ==>
    node_query_count Independent.queries <= q+4095 /\ size res.`1 = 16].
proof.
  proc; while (0 <= j <= 2048 /\ size stack <= j /\ (0 < j => stack <> []) /\
    valid_stack stack /\ node_query_count Independent.queries <= q+2*j-size stack).
  + wp; while (0 <= j < 2048 /\ size stack <= j /\ valid_stack stack /\
      size current = 16 /\ node_query_count Independent.queries <= q+2*j+1-size stack).
    - exists* j, stack; elim* => j0 st0.
      wp; call (domain_hash_bound (q+2*j0+1-size st0)); auto.
      smt(node_width size_behead size_ge0 valid_stack_tail).
    wp; exists* j, stack; elim* => j0 st0.
    call (domain_hash_bound (q+2*j0-size st0)); wp.
    call (domain_fors_bound (q+2*j0-size st0)); auto.
    rewrite /valid_stack /=; smt(node_width size_ge0).
  auto; rewrite /valid_stack /=; smt(size_ge0 size_eq0 valid_stack_head).
qed.

lemma domain_fors_sign_cost q :
  hoare[RawFors(PreparationView(Independent)).sign : node_query_count Independent.queries <= q ==>
    node_query_count Independent.queries <= q+4095 /\ size res.`1 = 16].
proof.
  proc; call (domain_fors_tree_cost q); wp.
  call (domain_fors_bound q); auto; smt(node_width).
qed.

lemma domain_fors_root_cost q :
  hoare[RawFors(PreparationView(Independent)).root : node_query_count Independent.queries <= q ==>
    node_query_count Independent.queries <= q+4095 /\ size res = 16].
proof. proc; call (domain_fors_tree_cost q); auto. qed.

lemma domain_fors_recover_cost q :
  hoare[RawFors(PreparationView(Independent)).recover : node_query_count Independent.queries <= q ==>
    node_query_count Independent.queries <= q+12 /\ size res = 16].
proof.
  proc; while (0 <= h <= 11 /\ node_query_count Independent.queries <= q+1+h /\ size current = 16).
  + exists* h; elim* => h0; wp; call (domain_hash_bound (q+1+h0)); auto; smt(node_width).
  wp; call (domain_hash_bound q); auto; smt(node_width).
qed.

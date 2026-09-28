(* All FORS Treehash calls are charged, including repeated secret queries. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawKeygenCost.
require import PhysicalKeygenCost RoleGrindCost RawFors.

lemma physical_fors_count c :
  hoare[PreparationView(Physical).fors : Shared.calls = c ==> Shared.calls = c+1].
proof.
  proc; inline Physical.derive; wp; exists* Shared.draws; elim* => d.
  call (hash_cost c d); auto.
qed.
lemma fors_public_count q :
  hoare[PreparationView(Independent).fors : size Independent.queries = q ==>
    size Independent.queries = q].
proof. proc; call (independent_derive_count q); auto. qed.

lemma fors_tree_physical_cost c :
  hoare[RawFors(PreparationView(Physical)).tree : Shared.calls = c ==>
    c <= Shared.calls <= c+6143 /\ size res.`1 = 16].
proof.
  proc; while (0 <= j <= 2048 /\ size stack <= j /\ (0 < j => stack <> []) /\
    valid_stack stack /\ Shared.calls = c+3*j-size stack).
  + wp; while (0 <= j < 2048 /\ size stack <= j /\ valid_stack stack /\
      size current = 16 /\ Shared.calls = c+3*j+2-size stack).
    - exists* j, stack; elim* => j0 st0.
      wp; call (physical_hash_count (c+3*j0+2-size st0)); auto.
      smt(node_width size_behead size_ge0 valid_stack_tail).
    wp; exists* j, stack; elim* => j0 st0.
    call (physical_hash_count (c+3*j0+1-size st0)); wp.
    call (physical_fors_count (c+3*j0-size st0)); auto.
    rewrite /valid_stack /=; smt(node_width size_ge0).
  auto; rewrite /valid_stack /=; smt(size_ge0 size_eq0 valid_stack_head).
qed.

lemma fors_tree_public_cost q :
  hoare[RawFors(PreparationView(Independent)).tree : size Independent.queries = q ==>
    q <= size Independent.queries <= q+4095 /\ size res.`1 = 16].
proof.
  proc; while (0 <= j <= 2048 /\ size stack <= j /\ (0 < j => stack <> []) /\
    valid_stack stack /\ size Independent.queries = q+2*j-size stack).
  + wp; while (0 <= j < 2048 /\ size stack <= j /\ valid_stack stack /\
      size current = 16 /\ size Independent.queries = q+2*j+1-size stack).
    - exists* j, stack; elim* => j0 st0.
      wp; call (independent_hash_count (q+2*j0+1-size st0)); auto.
      smt(node_width size_behead size_ge0 valid_stack_tail).
    wp; exists* j, stack; elim* => j0 st0.
    call (independent_hash_count (q+2*j0-size st0)); wp.
    call (fors_public_count (q+2*j0-size st0)); auto.
    rewrite /valid_stack /=; smt(node_width size_ge0).
  auto; rewrite /valid_stack /=; smt(size_ge0 size_eq0 valid_stack_head).
qed.

lemma fors_sign_physical_cost c :
  hoare[RawFors(PreparationView(Physical)).sign : Shared.calls = c ==>
    c <= Shared.calls <= c+6144 /\ size res.`1 = 16].
proof.
  proc; call (fors_tree_physical_cost (c+1)); wp.
  call (physical_fors_count c); auto; smt(node_width).
qed.
lemma fors_root_physical_cost c :
  hoare[RawFors(PreparationView(Physical)).root : Shared.calls = c ==>
    c <= Shared.calls <= c+6143 /\ size res = 16].
proof. proc; call (fors_tree_physical_cost c); auto. qed.
lemma fors_sign_public_cost q :
  hoare[RawFors(PreparationView(Independent)).sign : size Independent.queries = q ==>
    q <= size Independent.queries <= q+4095 /\ size res.`1 = 16].
proof.
  proc; call (fors_tree_public_cost q); wp.
  call (fors_public_count q); auto; smt(node_width).
qed.
lemma fors_root_public_cost q :
  hoare[RawFors(PreparationView(Independent)).root : size Independent.queries = q ==>
    q <= size Independent.queries <= q+4095 /\ size res = 16].
proof. proc; call (fors_tree_public_cost q); auto. qed.

lemma fors_recover_physical_cost c :
  hoare[RawFors(PreparationView(Physical)).recover : Shared.calls = c ==>
    Shared.calls = c+12 /\ size res = 16].
proof.
  proc; while (0 <= h <= 11 /\ Shared.calls = c+1+h /\ size current = 16).
  + exists* h; elim* => h0; wp; call (physical_hash_count (c+1+h0)); auto; smt(node_width).
  wp; call (physical_hash_count c); auto; smt(node_width).
qed.
lemma fors_recover_public_cost q :
  hoare[RawFors(PreparationView(Independent)).recover : size Independent.queries = q ==>
    size Independent.queries = q+12 /\ size res = 16].
proof.
  proc; while (0 <= h <= 11 /\ size Independent.queries = q+1+h /\ size current = 16).
  + exists* h; elim* => h0; wp; call (independent_hash_count (q+1+h0)); auto; smt(node_width).
  wp; call (independent_hash_count q); auto; smt(node_width).
qed.

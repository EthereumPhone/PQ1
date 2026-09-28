(* Physical/public bounds for the actual authentication-path builder. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawKeygenCost.
require import PhysicalKeygenCost RoleGrindCost RawFors RawMerkle.

lemma merkle_build_physical_cost c :
  hoare[RawMerkle(PreparationView(Physical)).build : Shared.calls = c ==>
    c <= Shared.calls <= c+177151 /\ size res.`2 = 16].
proof.
  proc; while (0 <= kp <= 512 /\ size stack <= kp /\ (0 < kp => stack <> []) /\
    valid_stack stack /\ Shared.calls = c+346*kp-size stack).
  + wp; while (0 <= kp < 512 /\ size stack <= kp /\ valid_stack stack /\
      size current = 16 /\ Shared.calls = c+346*kp+345-size stack).
    - exists* kp, stack; elim* => kp0 st0.
      wp; call (physical_hash_count (c+346*kp0+345-size st0)); auto.
      smt(node_width size_behead size_ge0 valid_stack_tail).
    wp; exists* kp, stack; elim* => kp0 st0.
    call (leaf_physical_cost (c+346*kp0-size st0)); auto.
    rewrite /valid_stack /=; smt(size_ge0).
  auto; rewrite /valid_stack /=; smt(size_ge0 size_eq0 valid_stack_head).
qed.

lemma merkle_recover_physical_cost c :
  hoare[RawMerkle(PreparationView(Physical)).recover : Shared.calls = c ==>
    Shared.calls = c+9 /\ size res = 16].
proof.
  proc; while (0 <= h <= 9 /\ Shared.calls = c+h /\ (0 < h => size current = 16)).
  + exists* h; elim* => h0; wp; call (physical_hash_count (c+h0)); auto; smt(node_width).
  auto; smt().
qed.

lemma merkle_build_public_cost q :
  hoare[RawMerkle(PreparationView(Independent)).build : size Independent.queries = q ==>
    q <= size Independent.queries <= q+155135 /\ size res.`2 = 16].
proof.
  proc; while (0 <= kp <= 512 /\ size stack <= kp /\ (0 < kp => stack <> []) /\
    valid_stack stack /\ size Independent.queries = q+303*kp-size stack).
  + wp; while (0 <= kp < 512 /\ size stack <= kp /\ valid_stack stack /\
      size current = 16 /\ size Independent.queries = q+303*kp+302-size stack).
    - exists* kp, stack; elim* => kp0 st0.
      wp; call (independent_hash_count (q+303*kp0+302-size st0)); auto.
      smt(node_width size_behead size_ge0 valid_stack_tail).
    wp; exists* kp, stack; elim* => kp0 st0.
    call (leaf_public_cost (q+303*kp0-size st0)); auto.
    rewrite /valid_stack /=; smt(size_ge0).
  auto; rewrite /valid_stack /=; smt(size_ge0 size_eq0 valid_stack_head).
qed.

lemma merkle_recover_public_cost q :
  hoare[RawMerkle(PreparationView(Independent)).recover : size Independent.queries = q ==>
    size Independent.queries = q+9 /\ size res = 16].
proof.
  proc; while (0 <= h <= 9 /\ size Independent.queries = q+h /\ (0 < h => size current = 16)).
  + exists* h; elim* => h0; wp; call (independent_hash_count (q+h0)); auto; smt(node_width).
  auto; smt().
qed.

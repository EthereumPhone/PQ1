(* Query accounting under the opening-redacted private oracle. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawKeygenCost.
require import PhysicalKeygenCost RoleGrindCost RawFors.

require import ChainValueView RedactedChainOracle RedactedBasicCost.

lemma redacted_fors_public_count q :
  hoare[PreparationView(ChainPrefix(RedactedCachedChain)).fors : size Independent.queries = q ==>
    size Independent.queries = q].
proof. proc; call (redacted_derive_count q); auto. qed.

lemma redacted_fors_tree_public_cost q :
  hoare[RawFors(PreparationView(ChainPrefix(RedactedCachedChain))).tree : size Independent.queries = q ==>
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
    call (redacted_fors_public_count (q+2*j0-size st0)); auto.
    rewrite /valid_stack /=; smt(node_width size_ge0).
  auto; rewrite /valid_stack /=; smt(size_ge0 size_eq0 valid_stack_head).
qed.

lemma redacted_fors_sign_public_cost q :
  hoare[RawFors(PreparationView(ChainPrefix(RedactedCachedChain))).sign : size Independent.queries = q ==>
    q <= size Independent.queries <= q+4095 /\ size res.`1 = 16].
proof.
  proc; call (redacted_fors_tree_public_cost q); wp.
  call (redacted_fors_public_count q); auto; smt(node_width).
qed.

lemma redacted_fors_root_public_cost q :
  hoare[RawFors(PreparationView(ChainPrefix(RedactedCachedChain))).root : size Independent.queries = q ==>
    q <= size Independent.queries <= q+4095 /\ size res = 16].
proof. proc; call (redacted_fors_tree_public_cost q); auto. qed.

lemma redacted_fors_recover_public_cost q :
  hoare[RawFors(PreparationView(ChainPrefix(RedactedCachedChain))).recover : size Independent.queries = q ==>
    size Independent.queries = q+12 /\ size res = 16].
proof.
  proc; while (0 <= h <= 11 /\ size Independent.queries = q+1+h /\ size current = 16).
  + exists* h; elim* => h0; wp; call (independent_hash_count (q+1+h0)); auto; smt(node_width).
  wp; call (independent_hash_count q); auto; smt(node_width).
qed.


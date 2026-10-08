(* Authentication paths preserve the original worst-case query budget. *)
require import AllCore List IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawKeygenCost RoleGrindCost.
require import RawMerkle ChainMerkleView RedactedChainOracle RedactedKeygenCost.

lemma redacted_merkle_build_public_cost q :
  hoare[ChainMerkle(RedactedCachedChain).build : size Independent.queries = q ==>
    q <= size Independent.queries <= q+155135 /\ size res.`2 = 16].
proof.
  proc; while (0 <= kp <= 512 /\ size stack <= kp /\ (0 < kp => stack <> []) /\
    valid_stack stack /\ q <= size Independent.queries <= q+303*kp-size stack).
  + wp; while (0 <= kp < 512 /\ size stack <= kp /\ valid_stack stack /\
      size current = 16 /\ q <= size Independent.queries <= q+303*kp+302-size stack).
    - exists* Independent.queries; elim* => qs.
      wp; call (independent_hash_count (size qs)); auto.
      smt(node_width size_behead size_ge0 valid_stack_tail).
    wp; exists* Independent.queries; elim* => qs.
    call (redacted_leaf_public_cost (size qs)); auto.
    rewrite /valid_stack /=; smt(size_ge0).
  auto; rewrite /valid_stack /=; smt(size_ge0 size_eq0 valid_stack_head).
qed.

lemma redacted_merkle_recover_public_cost q :
  hoare[ChainMerkle(RedactedCachedChain).recover : size Independent.queries = q ==>
    size Independent.queries = q+9 /\ size res = 16].
proof.
  proc; while (0 <= h <= 9 /\ size Independent.queries = q+h /\ (0 < h => size current = 16)).
  + exists* h; elim* => h0; wp; call (independent_hash_count (q+h0)); auto; smt(node_width).
  auto; smt().
qed.


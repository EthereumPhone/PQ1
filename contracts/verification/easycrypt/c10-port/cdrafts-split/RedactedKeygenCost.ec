(* Worst-case key-generation accounting for the partially cached chain backend. *)
require import AllCore List IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawKeygenCost RoleGrindCost.
require import ChainKeygenView RedactedChainOracle RedactedBasicCost.

lemma redacted_leaf_public_cost q :
  hoare[ChainKeygen(RedactedCachedChain).leaf : size Independent.queries=q ==>
    q<=size Independent.queries<=q+302 /\ size res=16].
proof.
  proc; seq 3 : (q<=size Independent.queries<=q+301).
  + while (0<=i<=43 /\ q<=size Independent.queries<=q+7*i).
    - wp; exists* Independent.queries; elim* => qs;
        call (redacted_cached_value_cost (size qs)); auto; smt().
    auto; smt().
  wp; exists* Independent.queries; elim* => qs;
    call (independent_hash_count (size qs)); auto; smt(node_width).
qed.

lemma redacted_root_public_cost q0 :
  hoare[ChainKeygen(RedactedCachedChain).root : size Independent.queries = q0 ==>
    q0 <= size Independent.queries <= q0 + 155135 /\ size res = 16].
proof.
  proc; while (0 <= kp <= 512 /\ size stack <= kp /\ (0 < kp => stack <> []) /\
    valid_stack stack /\ q0 <= size Independent.queries <= q0+303*kp-size stack).
  + wp; while (0 <= kp < 512 /\ size stack <= kp /\ valid_stack stack /\
      size current = 16 /\ q0 <= size Independent.queries <= q0+303*kp+302-size stack).
    - exists* Independent.queries; elim* => qs.
      wp; call (independent_hash_count (size qs)); auto.
      smt(node_width size_behead size_ge0 valid_stack_tail).
    wp; exists* Independent.queries; elim* => qs.
    call (redacted_leaf_public_cost (size qs)); auto.
    rewrite /valid_stack /=; smt(size_ge0).
  auto; rewrite /valid_stack /=; smt(size_ge0 size_eq0 valid_stack_head).
qed.

(* Variable-candidate accounting for the actual opening-redacted chain backend. *)
require import AllCore List IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawKeygenCost RoleGrindCost.
require import ChainKeygenView RedactedChainOracle ChainVariableBasicCost.

require import LeafCandidateCount LeafGrindingCandidates.

lemma chain_variable_leaf_public_cost q :
  hoare[ChainKeygen(RedactedCachedChain).leaf : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q+302 /\ size res=16].
proof.
  proc; seq 3 : (leaf_variable_count Independent.queries<=q+301).
  + while (0<=i<=43 /\ leaf_variable_count Independent.queries<=q+7*i).
    - wp; exists* Independent.queries; elim* => qs;
        call (chain_variable_cached_value_cost (leaf_variable_count qs)); auto; smt().
    auto; smt().
  wp; exists* Independent.queries; elim* => qs;
    call (leaf_variable_hash_bound (leaf_variable_count qs)); auto; smt(node_width).
qed.

lemma chain_variable_root_public_cost q0 :
  hoare[ChainKeygen(RedactedCachedChain).root : leaf_variable_count Independent.queries<=q0 ==>
    leaf_variable_count Independent.queries <= q0 + 155135 /\ size res = 16].
proof.
  proc; while (0 <= kp <= 512 /\ size stack <= kp /\ (0 < kp => stack <> []) /\
    valid_stack stack /\ leaf_variable_count Independent.queries <= q0+303*kp-size stack).
  + wp; while (0 <= kp < 512 /\ size stack <= kp /\ valid_stack stack /\
      size current = 16 /\ leaf_variable_count Independent.queries <= q0+303*kp+302-size stack).
    - exists* Independent.queries; elim* => qs.
      wp; call (leaf_variable_hash_bound (leaf_variable_count qs)); auto.
      smt(node_width size_behead size_ge0 valid_stack_tail).
    wp; exists* Independent.queries; elim* => qs.
    call (chain_variable_leaf_public_cost (leaf_variable_count qs)); auto.
    rewrite /valid_stack /=; smt(size_ge0).
  auto; rewrite /valid_stack /=; smt(size_ge0 size_eq0 valid_stack_head).
qed.

(* Variable-candidate accounting for the actual opening-redacted chain backend. *)
require import AllCore List IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawKeygenCost RoleGrindCost.
require import RawMerkle ChainMerkleView RedactedChainOracle ChainVariableKeygenCost.

require import LeafCandidateCount LeafGrindingCandidates.

lemma chain_variable_merkle_build_public_cost q :
  hoare[ChainMerkle(RedactedCachedChain).build : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries <= q+155135 /\ size res.`2 = 16].
proof.
  proc; while (0 <= kp <= 512 /\ size stack <= kp /\ (0 < kp => stack <> []) /\
    valid_stack stack /\ leaf_variable_count Independent.queries <= q+303*kp-size stack).
  + wp; while (0 <= kp < 512 /\ size stack <= kp /\ valid_stack stack /\
      size current = 16 /\ leaf_variable_count Independent.queries <= q+303*kp+302-size stack).
    - exists* Independent.queries; elim* => qs.
      wp; call (leaf_variable_hash_bound (leaf_variable_count qs)); auto.
      smt(node_width size_behead size_ge0 valid_stack_tail).
    wp; exists* Independent.queries; elim* => qs.
    call (chain_variable_leaf_public_cost (leaf_variable_count qs)); auto.
    rewrite /valid_stack /=; smt(size_ge0).
  auto; rewrite /valid_stack /=; smt(size_ge0 size_eq0 valid_stack_head).
qed.

lemma chain_variable_merkle_recover_public_cost q :
  hoare[ChainMerkle(RedactedCachedChain).recover : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q+9 /\ size res = 16].
proof.
  proc; while (0 <= h <= 9 /\ leaf_variable_count Independent.queries<=q+h /\ (0 < h => size current = 16)).
  + exists* h; elim* => h0; wp; call (leaf_variable_hash_bound (q+h0)); auto; smt(node_width).
  auto; smt().
qed.


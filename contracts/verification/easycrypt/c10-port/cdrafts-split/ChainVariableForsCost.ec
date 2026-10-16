(* Variable-candidate accounting for the actual opening-redacted chain backend. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawKeygenCost.
require import PhysicalKeygenCost RoleGrindCost RawFors.

require import ChainValueView RedactedChainOracle ChainVariableBasicCost.

require import LeafCandidateCount LeafGrindingCandidates.

lemma chain_variable_fors_public_count q :
  hoare[PreparationView(ChainPrefix(RedactedCachedChain)).fors : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q].
proof. proc; call (chain_variable_derive_count q); auto. qed.

lemma chain_variable_fors_tree_public_cost q :
  hoare[RawFors(PreparationView(ChainPrefix(RedactedCachedChain))).tree : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries <= q+4095 /\ size res.`1 = 16].
proof.
  proc; while (0 <= j <= 2048 /\ size stack <= j /\ (0 < j => stack <> []) /\
    valid_stack stack /\ leaf_variable_count Independent.queries<=q+2*j-size stack).
  + wp; while (0 <= j < 2048 /\ size stack <= j /\ valid_stack stack /\
      size current = 16 /\ leaf_variable_count Independent.queries<=q+2*j+1-size stack).
    - exists* j, stack; elim* => j0 st0.
      wp; call (leaf_variable_hash_bound (q+2*j0+1-size st0)); auto.
      smt(node_width size_behead size_ge0 valid_stack_tail).
    wp; exists* j, stack; elim* => j0 st0.
    call (leaf_variable_hash_bound (q+2*j0-size st0)); wp.
    call (chain_variable_fors_public_count (q+2*j0-size st0)); auto.
    rewrite /valid_stack /=; smt(node_width size_ge0).
  auto; rewrite /valid_stack /=; smt(size_ge0 size_eq0 valid_stack_head).
qed.

lemma chain_variable_fors_sign_public_cost q :
  hoare[RawFors(PreparationView(ChainPrefix(RedactedCachedChain))).sign : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries <= q+4095 /\ size res.`1 = 16].
proof.
  proc; call (chain_variable_fors_tree_public_cost q); wp.
  call (chain_variable_fors_public_count q); auto; smt(node_width).
qed.

lemma chain_variable_fors_root_public_cost q :
  hoare[RawFors(PreparationView(ChainPrefix(RedactedCachedChain))).root : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries <= q+4095 /\ size res = 16].
proof. proc; call (chain_variable_fors_tree_public_cost q); auto. qed.

lemma chain_variable_fors_recover_public_cost q :
  hoare[RawFors(PreparationView(ChainPrefix(RedactedCachedChain))).recover : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q+12 /\ size res = 16].
proof.
  proc; while (0 <= h <= 11 /\ leaf_variable_count Independent.queries<=q+1+h /\ size current = 16).
  + exists* h; elim* => h0; wp; call (leaf_variable_hash_bound (q+1+h0)); auto; smt(node_width).
  wp; call (leaf_variable_hash_bound q); auto; smt(node_width).
qed.


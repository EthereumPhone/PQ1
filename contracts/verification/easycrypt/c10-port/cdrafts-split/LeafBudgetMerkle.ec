(* Conservative variable-candidate costs in the existing target game. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawKeygenCost.
require import PhysicalKeygenCost RoleGrindCost RawFors RawMerkle.
require import RawMerkleCost.
require import LeafTargetOracleCost LeafCandidateCount LeafBudgetKeygen.

require import TargetAdapterCost.

lemma leaf_budget_merkle_build_cost q :
  hoare[RawMerkle(IdealPreparation).build : leaf_variable_count Independent.queries <= q ==>
    leaf_variable_count Independent.queries <= q+155135 /\ size res.`2 = 16].
proof.
  proc; while (0 <= kp <= 512 /\ size stack <= kp /\ (0 < kp => stack <> []) /\
    valid_stack stack /\ leaf_variable_count Independent.queries <= q+303*kp-size stack).
  + wp; while (0 <= kp < 512 /\ size stack <= kp /\ valid_stack stack /\
      size current = 16 /\ leaf_variable_count Independent.queries <= q+303*kp+302-size stack).
    - exists* kp, stack; elim* => kp0 st0.
      wp; call (leaf_variable_hash_bound (q+303*kp0+302-size st0)); auto.
      smt(node_width size_behead size_ge0 valid_stack_tail).
    wp; exists* kp, stack; elim* => kp0 st0.
    call (leaf_budget_leaf_cost (q+303*kp0-size st0)); auto.
    rewrite /valid_stack /=; smt(size_ge0).
  auto; rewrite /valid_stack /=; smt(size_ge0 size_eq0 valid_stack_head).
qed.

lemma leaf_budget_merkle_recover_cost q :
  hoare[RawMerkle(IdealPreparation).recover : leaf_variable_count Independent.queries <= q ==>
    leaf_variable_count Independent.queries <= q+9 /\ size res = 16].
proof.
  proc; while (0 <= h <= 9 /\ leaf_variable_count Independent.queries <= q+h /\ (0 < h => size current = 16)).
  + exists* h; elim* => h0; wp; call (leaf_variable_hash_bound (q+h0)); auto; smt(node_width).
  auto; smt().
qed.

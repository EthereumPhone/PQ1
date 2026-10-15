(* Conservative variable-candidate costs in the existing target game. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle C10Bytes PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.
require import PhysicalKeygenCost RoleGrindCost.
require import RawShuffle.
require import LeafTargetOracleCost LeafCandidateCount .

require import TargetAdapterCost.

lemma leaf_budget_shuffle_derive_cost q :
  hoare[RawShuffle(IdealPreparation).derive : leaf_variable_count Independent.queries <= q ==>
    leaf_variable_count Independent.queries <= q+1].
proof. proc; sp 1; if.
  + wp; call (leaf_variable_hash_bound q); auto; smt().
  auto; smt(). qed.

lemma leaf_budget_shuffle_permutation_cost q :
  hoare[RawShuffle(IdealPreparation).permutation : leaf_variable_count Independent.queries <= q ==>
    leaf_variable_count Independent.queries <= q+4].
proof.
  proc; sp 1; if; last by auto; smt().
  while (leaf_variable_count Independent.queries <= q+4); first by auto.
  wp; while (0 <= blk <= 4 /\ leaf_variable_count Independent.queries <= q+blk).
  + exists* blk; elim* => b; wp; call (leaf_variable_hash_bound (q+b)); auto; smt().
  auto; smt().
qed.

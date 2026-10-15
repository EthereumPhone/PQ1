(* Variable-candidate layer costs retain all tree and reconstruction calls. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawLayer.
require import RawWots RawMerkle RawShuffle LeafTargetOracleCost LeafCandidateCount LeafBudgetWots LeafBudgetMerkle LeafBudgetShuffle.

require import TargetAdapterCost.

lemma leaf_budget_layer_recover_cost q :
  hoare[RawLayer(IdealPreparation).recover : leaf_variable_count Independent.queries <= q ==>
    leaf_variable_count Independent.queries <= q+312 /\ size res = 16].
proof.
  proc; seq 1 : (leaf_variable_count Independent.queries <= q+303).
  + call (leaf_budget_wots_recover_cost q); auto; smt().
  exists* Independent.queries; elim* => zs; call (leaf_budget_merkle_recover_cost (leaf_variable_count zs)); auto; smt().
qed.
lemma leaf_budget_layer_sign_cost q :
  hoare[RawLayer(IdealPreparation).sign :  leaf_variable_count Independent.queries <= q ==>
    leaf_variable_count Independent.queries <= q+155753 /\ (res<>None => size (oget res).`2=16)].
proof.
  proc; seq 1 : ( leaf_variable_count Independent.queries <= q+155135).
  + call (leaf_budget_merkle_build_cost q); auto; smt().
  seq 1 : ( leaf_variable_count Independent.queries <= q+155136).
  + exists* Independent.queries; elim* => zs; call (leaf_budget_shuffle_derive_cost (leaf_variable_count zs)); auto; smt().
  seq 1 : ( leaf_variable_count Independent.queries <= q+155441).
  + exists* Independent.queries; elim* => zs; call (leaf_budget_wots_sign_cost (leaf_variable_count zs)); auto; smt().
  sp 1; if; last by auto; smt().
  wp; exists* Independent.queries; elim* => zs; call (leaf_budget_layer_recover_cost (leaf_variable_count zs)); auto; smt().
qed.

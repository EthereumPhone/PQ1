(* Finite WOTS count queries have one fixed candidate; other calls remain bounded. *)
require import AllCore List Distr IntDiv RadixEncoding.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawShuffle.
require import LeafTargetOracleCost LeafCandidateCount LeafGrindingCandidates LeafBudgetShuffle ClientGuessCandidates.

require import TargetAdapterCost.

lemma leaf_budget_count_cost q :
  hoare[RawWots(IdealPreparation).count :
    leaf_variable_count Independent.queries<=q ==> leaf_variable_count Independent.queries<=q].
proof.
  proc; while (0<=i<=signing_budget /\ leaf_variable_count Independent.queries<=q).
  + wp; call (leaf_variable_hash_fixed q); auto; smt(leaf_wots_trial_fixed).
  auto; smt().
qed.

lemma leaf_budget_chain_cost q :
  hoare[RawWots(IdealPreparation).chain :
    leaf_variable_count Independent.queries <= q /\ 0 <= start <= stop <= 7 ==>
    leaf_variable_count Independent.queries <= q+7].
proof.
  proc; while (0 <= start <= j <= stop <= 7 /\ leaf_variable_count Independent.queries <= q+j-start).
  + exists* j, start; elim* => j0 s; wp; call (leaf_variable_hash_bound (q+j0-s)); auto; smt().
  auto; smt().
qed.

lemma leaf_budget_wots_recover_cost q :
  hoare[RawWots(IdealPreparation).recover : leaf_variable_count Independent.queries <= q ==>
    leaf_variable_count Independent.queries <= q+303 /\ size res = 16].
proof.
  proc; seq 1 : (leaf_variable_count Independent.queries <= q+1).
  + call (leaf_variable_hash_bound q); auto.
  sp 1; if; last by auto; smt(size_nseq).
  seq 3 : (leaf_variable_count Independent.queries <= q+302).
  + while (0 <= i <= 43 /\ leaf_variable_count Independent.queries <= q+1+7*i).
    - wp; exists* Independent.queries; elim* => qs1; call (leaf_budget_chain_cost (leaf_variable_count qs1)); auto; smt(raw_digit_bounds).
    auto; smt().
  wp; exists* Independent.queries; elim* => qs; call (leaf_variable_hash_bound (leaf_variable_count qs)); auto; smt(node_width).
qed.

lemma leaf_budget_wots_sign_cost q :
  hoare[RawWots(IdealPreparation).sign :  leaf_variable_count Independent.queries <= q ==>
    leaf_variable_count Independent.queries <= q+305].
proof.
  proc; seq 1 : (leaf_variable_count Independent.queries <= q).
  + call (leaf_budget_count_cost q); auto.
  sp 1; if; last by auto; smt().
  wp; seq 2 : (leaf_variable_count Independent.queries <= q+4).
  + exists* Independent.queries; elim* => qs; call (leaf_budget_shuffle_permutation_cost (leaf_variable_count qs)); auto; smt().
  while (0 <= step <= 43 /\ leaf_variable_count Independent.queries <= q+4+7*step).
  + seq 2 : (0 <= step < 43 /\ leaf_variable_count Independent.queries <= q+4+7*step).
    - exists* Independent.queries; elim* => qs; call (leaf_target_wots_bound (leaf_variable_count qs)); auto; smt().
    wp; exists* Independent.queries; elim* => qs; call (leaf_budget_chain_cost (leaf_variable_count qs)); auto; smt(raw_digit_bounds).
  auto; smt().
qed.

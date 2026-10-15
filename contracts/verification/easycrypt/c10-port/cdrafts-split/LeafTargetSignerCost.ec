(* Variable-candidate counts through the actual transformed signer. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid RoleGrindCost KeygenPrefixes.
require import RawKeygen RawKeygenCost RawFors RawLayer RawForest RawSigner RoleGrind.
require import ForsLeafView LeafForestView TargetOracleSplit TargetByteView TargetSignerProjection TargetAdapterCost LeafTargetForsCost LeafTargetOracleCost LeafCandidateCount LeafGrindingCandidates LeafBudgetLayer LeafBudgetShuffle.
lemma leaf_target_fors_recover_candidate_cost q :
  hoare[RawFors(IdealPreparation).recover : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q+12 /\ size res = 16].
proof.
  proc; while (0 <= h <= 11 /\ leaf_variable_count Independent.queries<=q+1+h /\ size current = 16).
  + exists* h; elim* => h0; wp; call (leaf_variable_hash_bound (q+1+h0)); auto; smt(node_width).
  wp; call (leaf_variable_hash_bound q); auto; smt(node_width).
qed.

lemma leaf_target_forest_one_candidate_cost q :
  hoare[LeafForest(IdealPreparation,IdealLeaf).one : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<= q+4107].
proof.
  proc; seq 1 : (leaf_variable_count Independent.queries<= q+4095).
  + call (leaf_target_fors_sign_candidate_cost q); auto; smt().
  exists* Independent.queries; elim* => zs; call (leaf_target_fors_recover_candidate_cost (leaf_variable_count zs)); auto; smt().
qed.

lemma leaf_target_forest_sign_candidate_cost q :
  hoare[LeafForest(IdealPreparation,IdealLeaf).sign : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<= q+53386 /\ size res.`3 = 16].
proof.
  proc; seq 5 : (leaf_variable_count Independent.queries<= q+5).
  + seq 4 : (leaf_variable_count Independent.queries<= q+1).
    - call (leaf_budget_shuffle_derive_cost q); auto.
    exists* Independent.queries; elim* => zs; call (leaf_budget_shuffle_permutation_cost (leaf_variable_count zs)); auto; smt().
  seq 2 : (leaf_variable_count Independent.queries<= q+49289).
  + while (0 <= step <= 12 /\ leaf_variable_count Independent.queries<= q+5+4107*step).
    - wp; exists* Independent.queries; elim* => zs; call (leaf_target_forest_one_candidate_cost (leaf_variable_count zs)); auto; smt().
    auto; smt().
  seq 1 : (leaf_variable_count Independent.queries<= q+53384).
  + exists* Independent.queries; elim* => zs; call (leaf_target_fors_root_candidate_cost (leaf_variable_count zs)); auto; smt().
  seq 2 : (leaf_variable_count Independent.queries<= q+53385).
  + exists* Independent.queries; elim* => zs; call (leaf_variable_hash_bound (leaf_variable_count zs)); auto; smt().
  exists* Independent.queries; elim* => zs; call (leaf_variable_hash_bound (leaf_variable_count zs)); auto; smt(node_width).
qed.

lemma leaf_target_forest_recover_candidate_cost q :
  hoare[RawForest(IdealPreparation).recover : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q+146 /\ size res = 16].
proof.
  proc; call (leaf_variable_hash_bound (q+145)); wp; call (leaf_variable_hash_bound (q+144)).
  while (0 <= t <= 12 /\ leaf_variable_count Independent.queries<=q+12*t).
  + exists* t; elim* => t0; wp; call (leaf_target_fors_recover_candidate_cost (q+12*t0)); auto; smt().
  auto; smt(node_width).
qed.

lemma leaf_target_role_grind_candidate_cost q0 :
  hoare[RoleGrind(IdealPrefix).run : leaf_variable_count Independent.queries<=q0 ==>
    leaf_variable_count Independent.queries<=q0].
proof.
  proc; while (leaf_variable_count Independent.queries<=q0).
  + wp; call (leaf_variable_hash_fixed q0).
    wp; call (leaf_target_derive_bound q0); auto; smt(leaf_hmsg_candidate_fixed).
  auto.
qed.

lemma leaf_target_signer_finish_candidate_cost q :
  hoare[TargetSigning(IdealTarget).finish : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<= q+364892].
proof.
  proc; seq 2 : (leaf_variable_count Independent.queries<= q+53386).
  + call (leaf_target_forest_sign_candidate_cost q); auto; smt().
  wp; while (0 <= layer <= 2 /\ leaf_variable_count Independent.queries<= q+53386+layer*(155753)).
  + wp; exists* Independent.queries; elim* => zs; call (leaf_budget_layer_sign_cost (leaf_variable_count zs)); auto; smt().
  auto; rewrite /signing_budget; smt().
qed.

lemma leaf_target_signer_sign_candidate_cost q :
  hoare[TargetSigning(IdealTarget).sign : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<= q+364892].
proof.
  proc; seq 1 : (leaf_variable_count Independent.queries<= q).
  + call (leaf_target_role_grind_candidate_cost q); auto; smt().
  sp 1; if; last by auto; rewrite /signing_budget; smt().
  exists* Independent.queries; elim* => zs; call (leaf_target_signer_finish_candidate_cost (leaf_variable_count zs)); auto; smt().
qed.

lemma leaf_target_signer_verify_candidate_cost q :
  hoare[RawSigner(IdealPrefix).verify : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<= q+771].
proof.
  proc; seq 1 : (leaf_variable_count Independent.queries<=q+1).
  + call (leaf_variable_hash_bound q); auto.
  sp 1; if; last by auto; smt().
  seq 2 : (leaf_variable_count Independent.queries<=q+147).
  + call (leaf_target_forest_recover_candidate_cost (q+1)); auto; smt().
  wp; while (0 <= layer <= 2 /\ leaf_variable_count Independent.queries <= q+147+312*layer).
  + wp; exists* Independent.queries; elim* => zs; call (leaf_budget_layer_recover_cost (leaf_variable_count zs)); auto; smt().
  auto; smt().
qed.

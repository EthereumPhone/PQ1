(* Variable FORS candidates in the actual redacted wrapper plan and release.
   Fixed grinder suffixes remain charged separately by the hiding theorem. *)
require import AllCore List IntDiv.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawForest RawSigner.
require import RoleGrindCost ForsLeafView LeafOpeningBound TargetOracleSplit TargetByteView.
require import TargetAdapterCost LeafCandidateCount LeafTargetForsCost LeafTargetSignerCost LeafBudgetLayer LeafBudgetShuffle.
require import WrapperForsPlan WrapperForestPlan WrapperForestRelease WrapperSigningPlan WrapperPlanSigner WrapperReleasedFors.
require import WrapperOpeningFrames WrapperTargetProjection.

lemma wrapper_leaf_fors_plan_cost q :
  hoare [WrapperForsPublicPlan(IdealLeaf).one : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q+4095].
proof. proc; call (leaf_target_fors_tree_candidate_cost q); auto; smt(). qed.

lemma wrapper_leaf_forest_plan_cost q :
  hoare [WrapperForestPlan(IdealPreparation,IdealLeaf).sign : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q+53386].
proof.
  proc; seq 4 : (leaf_variable_count Independent.queries<=q+5).
  + seq 3 : (leaf_variable_count Independent.queries<=q+1).
    - call (leaf_budget_shuffle_derive_cost q); auto.
    exists* Independent.queries; elim* => zs; call (leaf_budget_shuffle_permutation_cost (leaf_variable_count zs)); auto; smt().
  seq 2 : (leaf_variable_count Independent.queries<=q+49145).
  + while (0<=step<=12 /\ leaf_variable_count Independent.queries<=q+5+4095*step).
    - wp; exists* Independent.queries; elim* => zs; call (wrapper_leaf_fors_plan_cost (leaf_variable_count zs)); auto; smt().
    auto; smt().
  seq 1 : (leaf_variable_count Independent.queries<=q+53240).
  + exists* Independent.queries; elim* => zs; call (leaf_target_fors_root_candidate_cost (leaf_variable_count zs)); auto; smt().
  seq 2 : (leaf_variable_count Independent.queries<=q+53241).
  + wp; exists* Independent.queries; elim* => zs; call (leaf_variable_hash_bound (leaf_variable_count zs)); auto; smt().
  exists* Independent.queries; elim* => zs; call (leaf_variable_hash_bound (leaf_variable_count zs)); auto; smt().
qed.

lemma wrapper_leaf_finish_plan_cost q :
  hoare [WrapperSigningPlan(IdealPrefix,IdealLeaf).finish : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q+364892].
proof.
  proc; seq 2 : (leaf_variable_count Independent.queries<=q+53386).
  + call (wrapper_leaf_forest_plan_cost q); auto.
  wp; while (0<=layer<=2 /\ leaf_variable_count Independent.queries<=q+53386+layer*155753).
  + wp; exists* Independent.queries; elim* => zs; call (leaf_budget_layer_sign_cost (leaf_variable_count zs)); auto; smt().
  auto; smt().
qed.

lemma wrapper_leaf_sign_plan_cost q :
  hoare [TargetWrapperPlan(IdealTarget).sign : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q+364892].
proof.
  proc; seq 1 : (leaf_variable_count Independent.queries<=q).
  + call (leaf_target_role_grind_candidate_cost q); auto.
  sp 1; if; last by auto; smt().
  exists* Independent.queries; elim* => zs; call (wrapper_leaf_finish_plan_cost (leaf_variable_count zs)); auto; smt().
qed.

lemma wrapper_leaf_release_values_cost q :
  hoare [WrapperForestRelease(IdealLeaf).values : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q].
proof.
  proc; while (leaf_variable_count Independent.queries<=q).
  + wp; call (leaf_target_secret_cost q); auto.
  auto.
qed.

lemma wrapper_leaf_release_cost q :
  hoare [TargetWrapperReleased(IdealTarget).sign : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q+2*364892+771].
proof.
  proc; sp 1; if; last by auto; smt().
  seq 1 : (leaf_variable_count Independent.queries<=q+364892).
  + call (wrapper_leaf_sign_plan_cost q); auto.
  if; last by auto; smt().
  seq 1 : (leaf_variable_count Independent.queries<=q+2*364892).
  + exists* Independent.queries; elim* => zs; call (wrapper_leaf_sign_plan_cost (leaf_variable_count zs)); auto; smt().
  if; last by auto; smt().
  if; last by auto; smt().
  wp; exists* Independent.queries; elim* => zs; call (wrapper_leaf_release_values_cost (leaf_variable_count zs)).
  auto; smt().
qed.

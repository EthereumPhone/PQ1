(* Public-query accounting in the redacted target view. These are bounds on
   its actual instructions, not a transfer of the original query log. *)
require import AllCore List IntDiv.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawForest RawSigner RawWrapperCost.
require import RoleGrindCost ForsLeafView LeafOpeningBound TargetOracleSplit TargetByteView.
require import TargetAdapterCost TargetForsCost TargetSignerCost.
require import WrapperForsPlan WrapperForestPlan WrapperForestRelease WrapperSigningPlan WrapperPlanSigner WrapperReleasedFors.
require import WrapperOpeningFrames WrapperTargetProjection.

lemma wrapper_target_fors_plan_cost q :
  hoare [WrapperForsPublicPlan(IdealLeaf).one : size Independent.queries=q ==>
    q<=size Independent.queries<=q+4095].
proof. proc; call (target_fors_tree_public_cost q); auto; smt(). qed.

lemma wrapper_target_forest_plan_cost q :
  hoare [WrapperForestPlan(IdealPreparation,IdealLeaf).sign : size Independent.queries=q ==>
    q<=size Independent.queries<=q+53386].
proof.
  proc; seq 4 : (q<=size Independent.queries<=q+5).
  + seq 3 : (q<=size Independent.queries<=q+1).
    - call (target_shuffle_derive_public_cost q); auto.
    exists* Independent.queries; elim* => zs; call (target_shuffle_permutation_public_cost (size zs)); auto; smt().
  seq 2 : (q<=size Independent.queries<=q+49145).
  + while (0<=step<=12 /\ q<=size Independent.queries<=q+5+4095*step).
    - wp; exists* Independent.queries; elim* => zs; call (wrapper_target_fors_plan_cost (size zs)); auto; smt().
    auto; smt().
  seq 1 : (q<=size Independent.queries<=q+53240).
  + exists* Independent.queries; elim* => zs; call (target_fors_root_public_cost (size zs)); auto; smt().
  seq 2 : (q<=size Independent.queries<=q+53241).
  + wp; exists* Independent.queries; elim* => zs; call (independent_hash_count (size zs)); auto; smt().
  exists* Independent.queries; elim* => zs; call (independent_hash_count (size zs)); auto; smt().
qed.

lemma wrapper_target_finish_plan_cost q :
  hoare [WrapperSigningPlan(IdealPrefix,IdealLeaf).finish : size Independent.queries=q ==>
    q<=size Independent.queries<=q+2*signing_budget+364892].
proof.
  proc; seq 2 : (q<=size Independent.queries<=q+53386).
  + call (wrapper_target_forest_plan_cost q); auto.
  wp; while (0<=layer<=2 /\ q<=size Independent.queries<=q+53386+layer*(signing_budget+155753)).
  + wp; exists* Independent.queries; elim* => zs; call (target_layer_sign_public_cost (size zs)); auto; smt().
  auto; rewrite /signing_budget; smt().
qed.

lemma wrapper_target_sign_plan_cost q :
  hoare [TargetWrapperPlan(IdealTarget).sign : size Independent.queries=q ==>
    q<=size Independent.queries<=q+3*signing_budget+364892].
proof.
  proc; seq 1 : (q<=size Independent.queries<=q+signing_budget).
  + call (target_role_grind_public_cost q); auto.
  sp 1; if; last by auto; rewrite /signing_budget; smt().
  exists* Independent.queries; elim* => zs; call (wrapper_target_finish_plan_cost (size zs)); auto; smt().
qed.

lemma wrapper_target_release_values_cost q :
  hoare [WrapperForestRelease(IdealLeaf).values : size Independent.queries=q ==> size Independent.queries=q].
proof.
  proc; while (size Independent.queries=q).
  + wp; call (target_secret_cost q); auto.
  auto.
qed.

lemma wrapper_target_release_cost q :
  hoare [TargetWrapperReleased(IdealTarget).sign : size Independent.queries=q ==>
    q<=size Independent.queries<=q+wrapper_public_budget].
proof.
  proc; sp 1; if; last by auto; rewrite /wrapper_public_budget /signing_budget; smt().
  seq 1 : (q<=size Independent.queries<=q+3*signing_budget+364892).
  + call (wrapper_target_sign_plan_cost q); auto.
  if; last by auto; rewrite /wrapper_public_budget /signing_budget; smt().
  seq 1 : (q<=size Independent.queries<=q+2*(3*signing_budget+364892)).
  + exists* Independent.queries; elim* => zs; call (wrapper_target_sign_plan_cost (size zs)); auto; smt().
  if; last by auto; rewrite /wrapper_public_budget /signing_budget; smt().
  if; last by auto; rewrite /wrapper_public_budget /signing_budget; smt().
  wp; exists* Independent.queries; elim* => zs; call (wrapper_target_release_values_cost (size zs)).
  auto; rewrite /wrapper_public_budget /signing_budget; smt().
qed.

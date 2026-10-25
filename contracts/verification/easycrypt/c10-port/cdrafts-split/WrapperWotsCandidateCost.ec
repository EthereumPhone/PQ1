(* Variable candidates of the actual release-only chain view. Both internal
   attempts are charged; bounded grinding queries have fixed candidates. *)
require import AllCore List RadixEncoding.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawShuffle.
require import ChainValueView RedactedChainOracle LeafCandidateCount LeafGrindingCandidates.
require import ChainVariableBasicCost ChainVariableMerkleCost ChainVariableForestCost.
require import WrapperWotsValues WrapperWotsPlan WrapperChainLayerPlan WrapperChainWotsPlanSigner.
require import WrapperLayerRelease WrapperWotsRelease WrapperChainReleasedWots.

lemma wrapper_wots_plan_candidate_cost q :
  hoare [WrapperWotsPlan(ChainPrefix(RedactedCachedChain)).plan :
    leaf_variable_count Independent.queries<=q ==> leaf_variable_count Independent.queries<=q+4].
proof.
  proc; seq 1 : (leaf_variable_count Independent.queries<=q).
  + call (chain_variable_count_public_cost q); auto.
  if; last by auto; smt().
  call (chain_variable_shuffle_permutation_public_cost q); auto.
qed.

lemma wrapper_chain_layer_plan_candidate_cost q :
  hoare [WrapperChainLayerPlan(RedactedCachedChain).plan :
    leaf_variable_count Independent.queries<=q ==> leaf_variable_count Independent.queries<=q+155140].
proof.
  proc; seq 1 : (leaf_variable_count Independent.queries<=q+155135).
  + call (chain_variable_merkle_build_public_cost q); auto.
  seq 1 : (leaf_variable_count Independent.queries<=q+155136).
  + call (chain_variable_shuffle_derive_public_cost (q+155135)); auto; smt().
  wp; call (wrapper_wots_plan_candidate_cost (q+155136)); auto; smt().
qed.

lemma wrapper_wots_plan_finish_candidate_cost q :
  hoare [WrapperChainWotsPlanSigner(RedactedCachedChain).finish :
    leaf_variable_count Independent.queries<=q ==> leaf_variable_count Independent.queries<=q+363666].
proof.
  proc; seq 2 : (leaf_variable_count Independent.queries<=q+53386).
  + call (chain_variable_forest_sign_public_cost q); auto.
  wp; while (0<=layer<=2 /\ leaf_variable_count Independent.queries<=q+53386+155140*layer).
  + exists* layer; elim* => k.
    wp; call (wrapper_chain_layer_plan_candidate_cost (q+53386+155140*k)); auto; smt().
  auto; smt().
qed.

lemma wrapper_wots_plan_sign_candidate_cost q :
  hoare [WrapperChainWotsPlanSigner(RedactedCachedChain).sign :
    leaf_variable_count Independent.queries<=q ==> leaf_variable_count Independent.queries<=q+363666].
proof.
  proc; seq 1 : (leaf_variable_count Independent.queries<=q).
  + call (chain_variable_role_grind_public_cost q); auto.
  sp 1; if; last by auto; smt().
  call (wrapper_wots_plan_finish_candidate_cost q); auto.
qed.

lemma wrapper_wots_values_candidate_cost q :
  hoare [WrapperWotsValues(RedactedCachedChain).run :
    leaf_variable_count Independent.queries<=q ==> leaf_variable_count Independent.queries<=q+301].
proof.
  proc; while (0<=step<=43 /\ leaf_variable_count Independent.queries<=q+7*step).
  + exists* step; elim* => k.
    wp; call (chain_variable_cached_value_cost (q+7*k)); auto; smt(raw_digit_bounds).
  auto; smt().
qed.

lemma wrapper_layer_release_candidate_cost q :
  hoare [WrapperLayerRelease(RedactedCachedChain).run :
    leaf_variable_count Independent.queries<=q ==> leaf_variable_count Independent.queries<=q+301].
proof. proc; call (wrapper_wots_values_candidate_cost q); auto. qed.

lemma wrapper_wots_release_candidate_cost q :
  hoare [WrapperWotsRelease(RedactedCachedChain).run :
    leaf_variable_count Independent.queries<=q ==> leaf_variable_count Independent.queries<=q+602].
proof.
  proc; while (0<=layer<=2 /\ leaf_variable_count Independent.queries<=q+301*layer).
  + exists* layer; elim* => k.
    wp; call (wrapper_layer_release_candidate_cost (q+301*k)); auto; smt().
  auto; smt().
qed.

lemma wrapper_wots_sign_candidate_cost q :
  hoare [WrapperChainReleasedWots(RedactedCachedChain).sign :
    leaf_variable_count Independent.queries<=q ==> leaf_variable_count Independent.queries<=q+727934].
proof.
  proc; sp 1; if; last by auto; smt().
  seq 1 : (leaf_variable_count Independent.queries<=q+363666).
  + call (wrapper_wots_plan_sign_candidate_cost q); auto.
  if; last by auto; smt().
  seq 1 : (leaf_variable_count Independent.queries<=q+727332).
  + call (wrapper_wots_plan_sign_candidate_cost (q+363666)); auto; smt().
  if; last by auto; smt().
  if; last by auto; smt().
  wp; call (wrapper_wots_release_candidate_cost (q+727332)); auto; smt().
qed.

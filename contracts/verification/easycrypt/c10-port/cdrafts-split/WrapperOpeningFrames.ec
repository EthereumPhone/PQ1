(* Ordinary FORS planning commits leaves without observing their secrets.
   Randomizer and WOTS derivations remain disjoint from the selected FORS key. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawLayer RoleGrind.
require import ForsPrivateLeaves ForsLeafView TargetOracleSplit TargetByteView TargetTableProjection TargetOpeningFrames.
require import WrapperForsPlan WrapperForestPlan WrapperSigningPlan WrapperPlanSigner.

module TargetWrapperPlan (O : TargetOracle) = WrapperPlanSigner(TargetPrefix(O),TargetLeaf(O)).

lemma wrapper_leaf_tree_no_opening flag :
  hoare [LeafFors(TargetLeaf(ObservedTarget(Independent))).tree :
    OriginalTargetState.revealed=flag ==> OriginalTargetState.revealed=flag].
proof.
  proc; while (OriginalTargetState.revealed=flag).
  + wp; while (OriginalTargetState.revealed=flag).
    - wp; call (_ : true ==> true); first by trivial.
      auto.
    wp; call (_ : true ==> true); first by trivial.
    auto.
  auto.
qed.

lemma wrapper_leaf_root_no_opening flag :
  hoare [LeafFors(TargetLeaf(ObservedTarget(Independent))).root :
    OriginalTargetState.revealed=flag ==> OriginalTargetState.revealed=flag].
proof. proc; call (wrapper_leaf_tree_no_opening flag); auto. qed.

lemma wrapper_public_fors_no_opening flag :
  hoare [WrapperForsPublicPlan(TargetLeaf(ObservedTarget(Independent))).one :
    OriginalTargetState.revealed=flag ==> OriginalTargetState.revealed=flag].
proof. proc; call (wrapper_leaf_tree_no_opening flag); auto. qed.

lemma wrapper_forest_plan_no_opening flag :
  hoare [WrapperForestPlan(PreparationView(TargetPrefix(ObservedTarget(Independent))),
      TargetLeaf(ObservedTarget(Independent))).sign :
    OriginalTargetState.revealed=flag ==> OriginalTargetState.revealed=flag].
proof.
  proc; wp; call (_ : true ==> true); first by trivial.
  wp; call (_ : true ==> true); first by trivial.
  call (wrapper_leaf_root_no_opening flag).
  while (OriginalTargetState.revealed=flag).
  + wp; call (wrapper_public_fors_no_opening flag); auto.
  wp; call (_ : true ==> true); first by trivial.
  call (_ : true ==> true); first by trivial.
  auto.
qed.

lemma wrapper_finish_plan_no_opening flag target_ht target_tree target_index :
  hoare [WrapperSigningPlan(TargetPrefix(ObservedTarget(Independent)),
      TargetLeaf(ObservedTarget(Independent))).finish :
    OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index ==>
    OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index].
proof.
  proc; wp; while (OriginalTargetState.revealed=flag /\
    TargetConfig.input=fors_private_key target_ht target_tree target_index).
  + wp; call (observed_layer_preserves_opening RawLayer flag target_ht target_tree target_index); auto.
  wp; call (wrapper_forest_plan_no_opening flag); auto.
qed.

lemma wrapper_sign_plan_no_opening flag target_ht target_tree target_index :
  hoare [TargetWrapperPlan(ObservedTarget(Independent)).sign :
    OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index ==>
    OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index].
proof.
  proc; seq 1 : (OriginalTargetState.revealed=flag /\
    TargetConfig.input=fors_private_key target_ht target_tree target_index).
  + call (observed_grind_preserves_opening flag target_ht target_tree target_index); auto.
  sp 1; if; last auto.
  call (wrapper_finish_plan_no_opening flag target_ht target_tree target_index); auto.
qed.

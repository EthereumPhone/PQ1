(* Every newly observed ordinary secret belongs to the externally released
   result. Refusal has no absorbing-failure escape in this invariant. *)
require import AllCore List FMap.
require import C10RawOracle C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawForest RawSigner.
require import PersistentGrind AcceptedContexts SignerTrace ForestReferenceHistory.
require import ForsPrivateLeaves ForsLeafView TargetOracleSplit TargetByteView TargetTableProjection.
require import TargetForestOpenings TargetSignerOpenings.
require import WrapperForestRelease WrapperSigningPlan WrapperPlanSigner WrapperReleasedFors.
require import WrapperOpeningFrames WrapperTargetProjection.

lemma wrapper_observed_plan_histories s0 h0 :
  hoare [TargetWrapperPlan(ObservedTarget(Independent)).sign :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  have hc : hoare [TargetWrapperPlan(ConcreteTarget(Independent)).sign :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
  + exists* seed,root,message; elim* => seed0 root0 message0.
    conseq (wrapper_plan_original_projection seed0 root0 message0)
      (complete_signer_histories RawSigner s0 h0); smt().
  conseq (wrapper_target_plan_projection TargetWrapperPlan) hc; smt().
qed.

lemma wrapper_observed_plan_keeps_entry x0 d0 :
  hoare [TargetWrapperPlan(ObservedTarget(Independent)).sign :
    Independent.rawhistory.[x0]=Some d0 ==> Independent.rawhistory.[x0]=Some d0].
proof.
  exists* Independent.secrethistory,Independent.rawhistory; elim* => s0 h0.
  conseq (wrapper_observed_plan_histories s0 h0); rewrite /extends; smt().
qed.

lemma wrapper_release_values_opening flag input ht0 digest0 :
  hoare [WrapperForestRelease(TargetLeaf(ObservedTarget(Independent))).values :
    OriginalTargetState.revealed=flag /\ TargetConfig.input=input /\ ht=ht0 /\ digest=digest0 ==>
    OriginalTargetState.revealed => flag \/ forest_opens_input input ht0 digest0].
proof.
  proc; while (TargetConfig.input=input /\ ht=ht0 /\ digest=digest0 /\ 0<=t<=12 /\
    (OriginalTargetState.revealed => flag \/ forest_opens_input input ht0 digest0)).
  + wp; inline ObservedTarget(Independent).secret ObservedTarget(Independent).derive.
    wp; call (_ : true ==> true); first by trivial.
    auto; rewrite /forest_opens_input; smt().
  auto; smt().
qed.

lemma wrapper_released_opening flag target_ht target_tree target_index seed0 root0 message0 :
  hoare [TargetWrapperReleased(ObservedTarget(Independent)).sign :
    OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index /\
    seed=seed0 /\ root=root0 /\ message=message0 ==>
    OriginalTargetState.revealed => flag \/
      (res<>None /\ signature_opens_input Independent.rawhistory seed0 root0 message0 (oget res)
        (fors_private_key target_ht target_tree target_index))].
proof.
  proc; sp 1; if; last auto.
  seq 1 : (seed=seed0 /\ root=root0 /\ message=message0 /\ result=None /\
    OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index /\
    (first<>None => wrapper_plan_entry Independent.rawhistory seed0 root0 message0 (oget first))).
  + call (_ : seed=seed0 /\ root=root0 /\ message=message0 /\
      OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index ==>
      OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index /\
      (res<>None => wrapper_plan_entry Independent.rawhistory seed0 root0 message0 (oget res))).
    - conseq (wrapper_sign_plan_no_opening flag target_ht target_tree target_index)
        (wrapper_observed_plan_entry seed0 root0 message0); smt().
    auto.
  if; last auto.
  exists* first; elim* => first0.
  seq 1 : (result=None /\ first=first0 /\ first0<>None /\
    OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index /\
    Independent.rawhistory.[hmsg_input seed0 root0 (pad (oget first0).`1) message0]=Some (oget first0).`2).
  + call (_ : OriginalTargetState.revealed=flag /\
      TargetConfig.input=fors_private_key target_ht target_tree target_index /\
      Independent.rawhistory.[hmsg_input seed0 root0 (pad (oget first0).`1) message0]=Some (oget first0).`2 ==>
      OriginalTargetState.revealed=flag /\ TargetConfig.input=fors_private_key target_ht target_tree target_index /\
      Independent.rawhistory.[hmsg_input seed0 root0 (pad (oget first0).`1) message0]=Some (oget first0).`2).
    - conseq (wrapper_sign_plan_no_opening flag target_ht target_tree target_index)
        (wrapper_observed_plan_keeps_entry (hmsg_input seed0 root0 (pad (oget first0).`1) message0) (oget first0).`2); smt().
    auto; rewrite /wrapper_plan_entry; smt().
  if; last auto.
  if; last auto.
  wp; call (wrapper_release_values_opening flag (fors_private_key target_ht target_tree target_index)
    (hypertree_index (oget first0).`2) (oget first0).`2).
  auto; rewrite /signature_opens_input; smt().
qed.

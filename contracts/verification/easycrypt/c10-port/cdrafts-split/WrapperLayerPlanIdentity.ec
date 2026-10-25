(* Comparing public layer plans is equivalent to comparing the actual layer
   signatures when both plans have retained witnesses in the same tables. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawLayer RawWots RawCountRecorded.
require import WotsReferenceRoot WotsRootDeterminism LayerPath LayerWitness WotsFirstCount.
require import WrapperWotsValues WrapperLayerPlan WrapperLayerPlanSupport.

lemma wrapper_layer_plan_public_identity h s seed layer tree leaf message plan plan' :
  wrapper_layer_plan_supported h s seed layer tree leaf message plan =>
  wrapper_layer_plan_supported h s seed layer tree leaf message plan' =>
  plan.`1=plan'.`1 => plan.`3=plan'.`3 => plan=plan'.
proof.
  rewrite /wrapper_layer_plan_supported.
  move=> [he [pk hw]] [he' [pk' hw']] hc ha.
  have hp : pk=pk' by move: hw hw'; rewrite /layer_witness; smt(wots_root_unique).
  have hd : plan.`2=plan'.`2 by move: he he'; rewrite /wrapper_wots_plan_entry; smt(first_wots_count_unique).
  have hr : plan.`4=plan'.`4 by move: hw hw'; rewrite /layer_witness /layer_path; smt().
  smt().
qed.

lemma wrapper_layer_plan_value_identity h s seed layer tree leaf sig root sig' root' plan :
  wrapper_layer_planned h s seed layer tree leaf (Some (sig,root)) (Some plan) =>
  wrapper_layer_planned h s seed layer tree leaf (Some (sig',root')) (Some plan) =>
  sig=sig' /\ root=root'.
proof.
  rewrite /wrapper_layer_planned; smt(wrapper_wots_signature_unique).
qed.

lemma wrapper_layer_plan_signature_comparison h s seed layer tree leaf message sig root sig' root' plan plan' :
  wrapper_layer_plan_supported h s seed layer tree leaf message plan =>
  wrapper_layer_plan_supported h s seed layer tree leaf message plan' =>
  wrapper_layer_planned h s seed layer tree leaf (Some (sig,root)) (Some plan) =>
  wrapper_layer_planned h s seed layer tree leaf (Some (sig',root')) (Some plan') =>
  (sig=sig')=(plan=plan').
proof.
  move=> hs hs' hp hp'.
  have forward : sig=sig' => plan=plan'.
  + move=> he; apply (wrapper_layer_plan_public_identity h s seed layer tree leaf message plan plan' hs hs');
      move: hp hp'; rewrite /wrapper_layer_planned; smt().
  smt(wrapper_layer_plan_value_identity).
qed.

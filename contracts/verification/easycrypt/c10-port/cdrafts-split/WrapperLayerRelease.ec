(* Canonical materialization of a recorded layer plan. The wrapper, rather
   than this helper, will decide whether the resulting values may be released. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawLayer.
require import PersistentGrind AcceptedContexts ChainValueView WotsReference WotsSignatureValue WotsReferenceRoot WotsSignWitness WotsFirstCount.
require import LayerWitness LayerPath LayerSignOpening WrapperWotsValues WrapperWotsPlan WrapperLayerPlan WrapperLayerPlanSupport.

module WrapperLayerRelease (O : ChainOracle) = {
  proc run(seed : raw_input, layer tree leaf : int, plan : wrapper_layer_plan) : layer_signature * raw_input = {
    var sigma;
    sigma <@ WrapperWotsValues(O).run(seed,layer,tree,leaf,plan.`2,range 0 43);
    return ((sigma,plan.`1,plan.`3),plan.`4);
  }
}.

lemma wrapper_layer_release_lossless (O <: ChainOracle) :
  islossless O.value => islossless WrapperLayerRelease(O).run.
proof. move=> hv; proc; call (wrapper_wots_values_lossless O hv); auto. qed.

lemma wrapper_layer_release_total seed0 layer0 tree0 leaf0 sig0 root0 plan0 h0 s0 :
  phoare [WrapperLayerRelease(ConcreteChain(Independent)).run :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=leaf0 /\ plan=plan0 /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    wrapper_layer_planned h0 s0 seed0 layer0 tree0 leaf0 (Some (sig0,root0)) (Some plan0) ==>
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\ res=(sig0,root0)] = 1%r.
proof.
  proc; call (wrapper_wots_values_guarded seed0 layer0 tree0 leaf0 plan0.`2 (range 0 43) h0 s0).
  auto; rewrite /wrapper_layer_planned; smt(perm_eq_refl wrapper_wots_signature_unique).
qed.

lemma wrapper_layer_plan_opening h s seed layer tree leaf message sig root plan :
  wrapper_layer_plan_supported h s seed layer tree leaf message plan =>
  wrapper_layer_planned h s seed layer tree leaf (Some (sig,root)) (Some plan) =>
  layer_opening h s seed layer tree leaf message sig root.
proof.
  rewrite /wrapper_layer_plan_supported /wrapper_wots_plan_entry /wrapper_layer_planned
    /first_wots_count /layer_witness /layer_opening /wots_opening; smt(extends_refl).
qed.

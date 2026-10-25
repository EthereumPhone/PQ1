(* Materialization can newly open a cut only at a requested signature digit.
   The retained first counter ties that digit to this released layer's message. *)
require import AllCore List FMap RadixEncoding.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawLayer.
require import PersistentGrind AcceptedContexts WotsFirstCount ChainValueView ChainStageSampling CachedChainOracle.
require import ChainObserverProjection ObservedValueOpening ObservedHistory ObservedWotsOpening.
require import WrapperWotsValues WrapperLayerPlan WrapperLayerPlanSupport WrapperLayerRelease.

lemma wrapper_wots_values_observer_projection :
  equiv [WrapperWotsValues(ConcreteChain(Independent)).run ~ WrapperWotsValues(ObservedChain(Independent)).run :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  proc; while (={seed,layer,tree,kp,accepted,order,step,sigma,glob Independent}).
  + wp; call observed_value_projection; auto.
  auto.
qed.

lemma wrapper_layer_release_observer_projection :
  equiv [WrapperLayerRelease(ConcreteChain(Independent)).run ~ WrapperLayerRelease(ObservedChain(Independent)).run :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof. proc; call wrapper_wots_values_observer_projection; auto. qed.

lemma wrapper_wots_values_observed seed0 layer0 tree0 kp0 d0 order0 opened0 s0 h0 :
  hoare [WrapperWotsValues(ObservedChain(Independent)).run :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ accepted=d0 /\ order=order0 /\
    perm_eq order0 (range 0 43) /\
    ChainStage.seed=seed0 /\ valid_chain_address layer0 tree0 kp0 0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainRevelation.opened=opened0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    (ChainRevelation.opened => opened0 \/
      ((layer0,tree0,kp0)=(ChainStage.layer,ChainStage.tree,ChainStage.kp) /\
        digit 3 d0 ChainStage.index<=ChainCut.cut))].
proof.
  proc; while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ accepted=d0 /\ order=order0 /\
    perm_eq order0 (range 0 43) /\ 0<=step<=43 /\
    ChainStage.seed=seed0 /\ valid_chain_address layer0 tree0 kp0 0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    (ChainRevelation.opened => opened0 \/
      ((layer0,tree0,kp0)=(ChainStage.layer,ChainStage.tree,ChainStage.kp) /\
        digit 3 d0 ChainStage.index<=ChainCut.cut))).
  + exists* step,ChainRevelation.opened; elim* => st opened.
    wp; call (observed_value_history_opening seed0 layer0 tree0 kp0 (nth 0 order0 st)
      (digit 3 d0 (nth 0 order0 st)) opened s0 h0).
    auto; rewrite /valid_chain_address;
      smt(raw_digit_bounds perm_eq_size size_range mem_nth perm_eq_mem mem_range).
  auto; smt().
qed.

lemma wrapper_layer_release_observed seed0 layer0 tree0 leaf0 message0 plan0 opened0 s0 h0 :
  hoare [WrapperLayerRelease(ObservedChain(Independent)).run :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=leaf0 /\ plan=plan0 /\
    wrapper_layer_plan_supported h0 s0 seed0 layer0 tree0 leaf0 message0 plan0 /\
    ChainStage.seed=seed0 /\ valid_chain_address layer0 tree0 leaf0 0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainRevelation.opened=opened0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    (ChainRevelation.opened => opened0 \/
      ((layer0,tree0,leaf0)=(ChainStage.layer,ChainStage.tree,ChainStage.kp) /\
        opened_wots_count Independent.rawhistory seed0 layer0 tree0 leaf0 message0 res.`1.`2
          ChainStage.index ChainCut.cut))].
proof.
  proc; call (wrapper_wots_values_observed seed0 layer0 tree0 leaf0 plan0.`2 (range 0 43) opened0 s0 h0).
  auto; rewrite /wrapper_layer_plan_supported /wrapper_wots_plan_entry /opened_wots_count;
    smt(perm_eq_refl first_wots_count_extends).
qed.

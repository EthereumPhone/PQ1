(* The complete plan retains the actual lower Merkle root used as the top
   layer message, in addition to its local count/path witnesses. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawForest RawLayer RawSigner.
require import PersistentGrind AcceptedContexts MonotoneHistory MerkleRootWitness LayerReturnedRoot SignerCoordinates.
require import ChainValueView ChainStageSampling CachedChainOracle ObservedHistory.
require import WrapperLayerPlan WrapperChainLayerPlan WrapperWotsPlanObserver WrapperLayerPlanTrace.
require import WrapperWotsSigningPlan WrapperChainWotsPlanSigner.

op wrapper_wots_plan_lower_root h s seed (plan : wrapper_wots_signature_plan) =
  merkle_root_witness h s seed 0 (hypertree_index plan.`2 %/512)
    (nth wrapper_empty_layer_plan plan.`4 0).`4.

lemma wrapper_wots_plan_lower_root_extends h h' s s' seed plan :
  extends h h' => extends s s' => wrapper_wots_plan_lower_root h s seed plan =>
  wrapper_wots_plan_lower_root h' s' seed plan.
proof. rewrite /wrapper_wots_plan_lower_root; smt(merkle_root_witness_extends). qed.

lemma wrapper_chain_planner_histories
  (P <: WrapperChainPlanner {-Independent,-ChainStage,-ChainCut,-ChainRevelation,-CachedChain,-ObservedChain}) s0 h0 :
  hoare [P(ObservedChain(Independent)).plan :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory) => //.
  + exact (independent_hash_extends s0 h0).
  + exact (observed_derive_extends s0 h0).
  exact (observed_value_extends s0 h0).
qed.

lemma wrapper_chain_complete_planner_histories
  (P <: WrapperChainCompletePlanner {-Independent,-ChainStage,-ChainCut,-ChainRevelation,-CachedChain,-ObservedChain}) s0 h0 :
  hoare [P(ObservedChain(Independent)).sign :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory) => //.
  + exact (independent_hash_extends s0 h0).
  + exact (observed_derive_extends s0 h0).
  exact (observed_value_extends s0 h0).
qed.

lemma wrapper_layer_plan_root seed0 layer0 tree0 leaf0 message0 :
  hoare [WrapperLayerPlan(Independent).plan :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=leaf0 /\ message=message0 /\ 0<=leaf0<512 ==>
    res<>None => merkle_root_witness Independent.rawhistory Independent.secrethistory
      seed0 layer0 tree0 (oget res).`4].
proof.
  have he : equiv [WrapperLayerPlan(Independent).plan ~ RawLayer(PreparationView(Independent)).sign :
    seed{1}=seed0 /\ layer{1}=layer0 /\ tree{1}=tree0 /\ leaf{1}=leaf0 /\ message{1}=message0 /\
    0<=leaf0<512 /\ ={arg,Independent.rawhistory,Independent.secrethistory} ==>
    ={Independent.rawhistory,Independent.secrethistory} /\
    wrapper_layer_planned Independent.rawhistory{1} Independent.secrethistory{1}
      seed0 layer0 tree0 leaf0 res{2} res{1}].
  + symmetry; conseq (wrapper_layer_plan_projection seed0 layer0 tree0 leaf0 message0); smt().
  conseq he (raw_layer_returns_recorded_root seed0 layer0 tree0 leaf0 message0);
    rewrite /wrapper_layer_planned; smt().
qed.

lemma wrapper_chain_layer_plan_root seed0 layer0 tree0 leaf0 message0 :
  hoare [WrapperChainLayerPlan(ObservedChain(Independent)).plan :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=leaf0 /\ message=message0 /\ 0<=leaf0<512 ==>
    res<>None => merkle_root_witness Independent.rawhistory Independent.secrethistory
      seed0 layer0 tree0 (oget res).`4].
proof.
  have he : equiv [WrapperChainLayerPlan(ObservedChain(Independent)).plan ~ WrapperLayerPlan(Independent).plan :
    ={arg,glob Independent} ==> ={res,glob Independent}].
  + symmetry; transitivity WrapperChainLayerPlan(ConcreteChain(Independent)).plan
      (={arg,glob Independent} ==> ={res,glob Independent})
      (={arg,glob Independent} ==> ={res,glob Independent}) => //.
    - smt().
    - exact (wrapper_chain_layer_plan_projection Independent).
    exact (wrapper_chain_plan_observer_projection WrapperChainLayerPlan).
  conseq he (wrapper_layer_plan_root seed0 layer0 tree0 leaf0 message0); smt().
qed.

lemma wrapper_chain_layer_plan_history_root seed0 layer0 tree0 leaf0 message0 s0 h0 :
  hoare [WrapperChainLayerPlan(ObservedChain(Independent)).plan :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=leaf0 /\ message=message0 /\ 0<=leaf0<512 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    (res<>None => merkle_root_witness Independent.rawhistory Independent.secrethistory
      seed0 layer0 tree0 (oget res).`4)].
proof.
  conseq (wrapper_chain_layer_plan_root seed0 layer0 tree0 leaf0 message0)
    (wrapper_chain_planner_histories WrapperChainLayerPlan s0 h0); smt().
qed.

lemma wrapper_wots_plan_finish_lower_root seed0 digest0 :
  hoare [WrapperChainWotsPlanSigner(ObservedChain(Independent)).finish :
    seed=seed0 /\ digest=digest0 ==>
    res<>None => wrapper_wots_plan_lower_root Independent.rawhistory Independent.secrethistory seed0 (oget res)].
proof.
  proc; wp; while (seed=seed0 /\ digest=digest0 /\ ht=hypertree_index digest0 /\
    0<=layer<=2 /\ idx_tree=signer_tree ht layer /\
    (ok => size layers=layer /\ (1<=layer =>
      merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 0 (ht %/512)
        (nth wrapper_empty_layer_plan layers 0).`4))).
  + exists* layer,current,layers,Independent.secrethistory,Independent.rawhistory;
      elim* => k cur plans s0 h0.
    wp; call (wrapper_chain_layer_plan_history_root seed0 k (signer_tree (hypertree_index digest0) (k+1))
      (signer_tree (hypertree_index digest0) k %%512) cur s0 h0).
    auto; rewrite /signer_tree;
      smt(size_rcons nth_rcons extends_refl merkle_root_witness_extends hypertree_index_range
        pdiv_small modz_small modz_ge0 ltz_pmod divz_ge0 ltz_divLR).
  wp; call (_ : true ==> true); first by trivial.
  auto; rewrite /signer_tree /wrapper_wots_plan_lower_root; smt().
qed.

lemma wrapper_wots_plan_sign_lower_root seed0 :
  hoare [WrapperChainWotsPlanSigner(ObservedChain(Independent)).sign :
    seed=seed0 ==>
    res<>None => wrapper_wots_plan_lower_root Independent.rawhistory Independent.secrethistory seed0 (oget res)].
proof.
  proc; seq 1 : (seed=seed0).
  + call (_ : true ==> true); first by trivial. auto.
  sp 1; if; last auto.
  exists* accepted; elim* => acc.
  call (wrapper_wots_plan_finish_lower_root seed0 (oget acc).`2); auto.
qed.

(* Each opening during materialization belongs to one of the two returned
   counters. Internal plans remain separate from this release-only step. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawLayer RawForest RawSigner.
require import PersistentGrind AcceptedContexts MerkleRootWitness ForestRootWitness SignerCoordinates.
require import ChainValueView ChainStageSampling CachedChainOracle ObservedValueOpening ObservedWotsOpening ObservedCutEvidence.
require import WrapperLayerPlan WrapperLayerPlanSupport WrapperLayerPlanTrace WrapperLayerRelease WrapperLayerReleaseObserver.
require import WrapperWotsSigningPlan WrapperWotsRelease WrapperWotsPlanRoots.

lemma wrapper_layer_release_observed_recorded seed0 layer0 tree0 leaf0 sig0 root0 plan0 h0 s0 :
  hoare [WrapperLayerRelease(ObservedChain(Independent)).run :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=leaf0 /\ plan=plan0 /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    wrapper_layer_planned h0 s0 seed0 layer0 tree0 leaf0 (Some (sig0,root0)) (Some plan0) ==>
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\ res=(sig0,root0)].
proof.
  have he : equiv [WrapperLayerRelease(ObservedChain(Independent)).run ~ WrapperLayerRelease(ConcreteChain(Independent)).run :
    ={arg,glob Independent} ==> ={res,glob Independent}].
  + symmetry; conseq wrapper_layer_release_observer_projection; smt().
  conseq he (wrapper_layer_release_recorded seed0 layer0 tree0 leaf0 sig0 root0 plan0 h0 s0); smt().
qed.

lemma wrapper_layer_release_recorded_opening seed0 layer0 tree0 leaf0 message0 sig0 root0 plan0 opened0 h0 s0 :
  hoare [WrapperLayerRelease(ObservedChain(Independent)).run :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=leaf0 /\ plan=plan0 /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    wrapper_layer_planned h0 s0 seed0 layer0 tree0 leaf0 (Some (sig0,root0)) (Some plan0) /\
    wrapper_layer_plan_supported h0 s0 seed0 layer0 tree0 leaf0 message0 plan0 /\
    ChainStage.seed=seed0 /\ valid_chain_address layer0 tree0 leaf0 0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainRevelation.opened=opened0 ==>
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\ res=(sig0,root0) /\
    (ChainRevelation.opened => opened0 \/
      ((layer0,tree0,leaf0)=(ChainStage.layer,ChainStage.tree,ChainStage.kp) /\
        opened_wots_count h0 seed0 layer0 tree0 leaf0 message0 sig0.`2 ChainStage.index ChainCut.cut))].
proof.
  conseq (wrapper_layer_release_observed_recorded seed0 layer0 tree0 leaf0 sig0 root0 plan0 h0 s0)
    (wrapper_layer_release_observed seed0 layer0 tree0 leaf0 message0 plan0 opened0 s0 h0);
    smt(extends_refl).
qed.

lemma wrapper_wots_plan_cut h s seed signature plan k index cut :
  wrapper_wots_signature_planned h s seed signature plan =>
  wrapper_wots_plan_lower_root h s seed plan => 0<=k<2 =>
  opened_wots_count h seed k (signer_tree (hypertree_index plan.`2) (k+1))
    (signer_tree (hypertree_index plan.`2) k %%512)
    (wrapper_plan_message plan.`3.`3 plan.`4 k) (nth ([],0,[]) signature.`4 k).`2 index cut =>
  signed_cut_opened h s seed (hypertree_index plan.`2) signature.`4 k
    (signer_tree (hypertree_index plan.`2) (k+1)) (signer_tree (hypertree_index plan.`2) k %%512) index cut.
proof.
  move=> hp hr hk ho.
  have hidx := hypertree_index_range plan.`2.
  have ht : 0<=hypertree_index plan.`2 %/512<512 by smt(divz_ge0 ltz_divLR).
  case (k=0) => he.
  + rewrite /signed_cut_opened; left; rewrite he /signer_tree /=.
    exists plan.`3.`3; move: hp ho; rewrite he /wrapper_wots_signature_planned /wrapper_plan_message /signer_tree /=; smt().
  have he1 : k=1 by smt().
  rewrite /signed_cut_opened; right; rewrite he1 /signer_tree /=.
  split; first smt(modz_small).
  exists (nth wrapper_empty_layer_plan plan.`4 0).`4.
  move: hr ho; rewrite he1 /wrapper_wots_plan_lower_root /wrapper_plan_message /signer_tree /=;
    smt(modz_small).
qed.

lemma wrapper_wots_release_observed seed0 signature0 plan0 opened0 h0 s0 :
  hoare [WrapperWotsRelease(ObservedChain(Independent)).run :
    seed=seed0 /\ plan=plan0 /\ Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    wrapper_wots_signature_planned h0 s0 seed0 signature0 plan0 /\
    wrapper_wots_plan_lower_root h0 s0 seed0 plan0 /\
    ChainStage.seed=seed0 /\ valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainRevelation.opened=opened0 ==>
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\ res=signature0 /\
    (ChainRevelation.opened => opened0 \/
      signed_cut_opened h0 s0 seed0 (hypertree_index plan0.`2) signature0.`4
        ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut)].
proof.
  proc; while (seed=seed0 /\ plan=plan0 /\ ht=hypertree_index plan0.`2 /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    wrapper_wots_signature_planned h0 s0 seed0 signature0 plan0 /\
    wrapper_wots_plan_lower_root h0 s0 seed0 plan0 /\
    ChainStage.seed=seed0 /\ valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    0<=layer<=2 /\ layers=take layer signature0.`4 /\
    (ChainRevelation.opened => opened0 \/
      signed_cut_opened h0 s0 seed0 (hypertree_index plan0.`2) signature0.`4
        ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut)).
  + exists* layer,ChainRevelation.opened; elim* => k opened.
    wp; call (wrapper_layer_release_recorded_opening seed0 k (signer_tree (hypertree_index plan0.`2) (k+1))
      (signer_tree (hypertree_index plan0.`2) k %%512) (wrapper_plan_message plan0.`3.`3 plan0.`4 k)
      (nth ([],0,[]) signature0.`4 k) (nth wrapper_empty_layer_plan plan0.`4 k).`4
      (nth wrapper_empty_layer_plan plan0.`4 k) opened h0 s0).
    auto => &m hp.
    have hk : 0<=k<2 by smt().
    have hv : wrapper_wots_signature_planned h0 s0 seed0 signature0 plan0 by smt().
    have hr : wrapper_wots_plan_lower_root h0 s0 seed0 plan0 by smt().
    have hc : valid_chain_address k (signer_tree (hypertree_index plan0.`2) (k+1))
      (signer_tree (hypertree_index plan0.`2) k %%512) 0.
    - rewrite /valid_chain_address /signer_tree;
        smt(hypertree_index_range pdiv_small modz_small modz_ge0 ltz_pmod divz_ge0 ltz_divLR).
    have ht : wrapper_layer_plan_trace h0 s0 seed0 (hypertree_index plan0.`2) plan0.`3.`3
      signature0.`4 plan0.`4 2 by move: hv; rewrite /wrapper_wots_signature_planned; smt().
    split; first by move: ht; rewrite /wrapper_layer_plan_trace; smt().
    move=> _ result opened1 h1 s1 hpost.
    have ho := wrapper_wots_plan_cut h0 s0 seed0 signature0 plan0 k ChainStage.index{m} ChainCut.cut{m} hv hr hk.
    have hlen : size signature0.`4=2 by move: ht; rewrite /wrapper_layer_plan_trace; smt().
    smt(take_nth).
  auto; rewrite /wrapper_wots_signature_planned /wrapper_layer_plan_trace;
    smt(take0 take_size).
qed.

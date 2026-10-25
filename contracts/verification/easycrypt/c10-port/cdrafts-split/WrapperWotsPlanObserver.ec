(* Internal planning preserves the selected proper cut even when either
   bounded search refuses. The observer is passive for all returned plans. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawForest RawSigner.
require import ChainValueView ChainStageSampling CachedChainOracle ChainObserverProjection.
require import ObservedValueOpening ObservedPrivateOpening SignerCoordinates.
require import WrapperChainLayerPlan WrapperWotsSigningPlan WrapperWotsPlanSigner WrapperChainWotsPlanSigner.

module type WrapperChainCompletePlanner (O : ChainOracle) = {
  proc sign(seed root random message shuffle : raw_input) :
    wrapper_wots_signature_plan option { O.hash,O.derive,O.value }
}.

lemma wrapper_wots_plan_observer_projection
  (P <: WrapperChainCompletePlanner {-Independent,-ChainStage,-ChainCut,-ChainRevelation,-CachedChain,-ObservedChain}) :
  equiv [P(ConcreteChain(Independent)).sign ~ P(ObservedChain(Independent)).sign :
    ={arg,glob P,glob Independent} ==> ={res,glob P,glob Independent}].
proof.
  proc (={glob Independent}) => //.
  + by sim.
  + proc*; call observed_private_projection; auto.
  proc*; call observed_value_projection; auto.
qed.

lemma wrapper_wots_plan_finish_unopened seed0 digest0 opened0 :
  hoare [WrapperChainWotsPlanSigner(ObservedChain(Independent)).finish :
    seed=seed0 /\ digest=digest0 /\ ChainStage.seed=seed0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0 ==>
    ChainRevelation.opened=opened0].
proof.
  proc; wp; while (seed=seed0 /\ digest=digest0 /\ ht=hypertree_index digest0 /\
    0<=layer<=2 /\ idx_tree=signer_tree ht layer /\ ChainStage.seed=seed0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0).
  + exists* layer; elim* => k.
    wp; call (wrapper_chain_layer_plan_unopened seed0 k
      (signer_tree (hypertree_index digest0) (k+1)) opened0).
    auto; rewrite /signer_tree /valid_chain_address;
      smt(hypertree_index_range pdiv_small divz_ge0 ltz_divLR).
  wp; call (observed_forest_unopened opened0).
  auto; rewrite /signer_tree; smt().
qed.

lemma wrapper_wots_plan_sign_unopened seed0 opened0 :
  hoare [WrapperChainWotsPlanSigner(ObservedChain(Independent)).sign :
    seed=seed0 /\ ChainStage.seed=seed0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0 ==>
    ChainRevelation.opened=opened0].
proof.
  proc; seq 1 : (seed=seed0 /\ ChainStage.seed=seed0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0).
  + call (observed_grind_unopened opened0); auto.
  sp 1; if; last auto.
  exists* accepted; elim* => acc.
  call (wrapper_wots_plan_finish_unopened seed0 (oget acc).`2 opened0); auto.
qed.

lemma wrapper_wots_observed_plan_projection seed0 root0 message0 :
  equiv [RawSigner(Independent).sign ~ WrapperChainWotsPlanSigner(ObservedChain(Independent)).sign :
    seed{1}=seed0 /\ root{1}=root0 /\ message{1}=message0 /\
    ={arg,Independent.rawhistory,Independent.secrethistory} ==>
    ={Independent.rawhistory,Independent.secrethistory} /\
    wrapper_wots_signer_supported Independent.rawhistory{1} Independent.secrethistory{1}
      seed0 root0 message0 res{1} res{2}].
proof.
  have hc : equiv [WrapperWotsPlanSigner(Independent).sign ~
    WrapperChainWotsPlanSigner(ObservedChain(Independent)).sign :
    ={arg,glob Independent} ==> ={res,glob Independent}].
  + transitivity WrapperChainWotsPlanSigner(ConcreteChain(Independent)).sign
      (={arg,glob Independent} ==> ={res,glob Independent})
      (={arg,glob Independent} ==> ={res,glob Independent}) => //.
    - smt().
    - exact (wrapper_chain_wots_sign_projection Independent).
    exact (wrapper_wots_plan_observer_projection WrapperChainWotsPlanSigner).
  transitivity WrapperWotsPlanSigner(Independent).sign
    (seed{1}=seed0 /\ root{1}=root0 /\ message{1}=message0 /\
      ={arg,Independent.rawhistory,Independent.secrethistory} ==>
      ={Independent.rawhistory,Independent.secrethistory} /\
      wrapper_wots_signer_supported Independent.rawhistory{1} Independent.secrethistory{1}
        seed0 root0 message0 res{1} res{2})
    (={arg,glob Independent} ==> ={res,glob Independent}) => //.
  + smt().
  + exact (wrapper_wots_plan_signer_projection seed0 root0 message0).
qed.

lemma wrapper_wots_observed_plan_supported seed0 root0 message0 :
  hoare [WrapperChainWotsPlanSigner(ObservedChain(Independent)).sign :
    seed=seed0 /\ root=root0 /\ message=message0 ==>
    exists signature, wrapper_wots_signer_supported Independent.rawhistory Independent.secrethistory
      seed0 root0 message0 signature res].
proof.
  have ht : hoare [RawSigner(Independent).sign : true ==> true] by trivial.
  have he : equiv [WrapperChainWotsPlanSigner(ObservedChain(Independent)).sign ~ RawSigner(Independent).sign :
    seed{1}=seed0 /\ root{1}=root0 /\ message{1}=message0 /\
    ={arg,Independent.rawhistory,Independent.secrethistory} ==>
    ={Independent.rawhistory,Independent.secrethistory} /\
    wrapper_wots_signer_supported Independent.rawhistory{1} Independent.secrethistory{1}
      seed0 root0 message0 res{2} res{1}].
  + symmetry; conseq (wrapper_wots_observed_plan_projection seed0 root0 message0); smt().
  conseq he ht; smt().
qed.

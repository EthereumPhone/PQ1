(* A successful plan carries a reconstructible original signature, its H_msg
   entry, and the lower root. All of this survives a second internal attempt. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawSigner.
require import PersistentGrind AcceptedContexts ChainValueView ChainStageSampling CachedChainOracle ObservedValueOpening.
require import WrapperWotsSigningPlan WrapperWotsPlanSigner WrapperWotsPlanComparison.
require import WrapperChainWotsPlanSigner WrapperWotsPlanObserver WrapperWotsPlanRoots.

op wrapper_wots_plan_ready h s seed root message plan =
  wrapper_wots_hmsg_entry h seed root message plan /\
  wrapper_wots_plan_lower_root h s seed plan /\
  exists signature, wrapper_wots_signature_planned h s seed signature plan.

lemma wrapper_wots_plan_ready_extends h h' s s' seed root message plan :
  extends h h' => extends s s' => wrapper_wots_plan_ready h s seed root message plan =>
  wrapper_wots_plan_ready h' s' seed root message plan.
proof.
  move=> hh hs [he [hr [sig hp]]].
  rewrite /wrapper_wots_plan_ready.
  split; first by move: hh he; rewrite /extends /wrapper_wots_hmsg_entry; smt().
  split; first by smt(wrapper_wots_plan_lower_root_extends).
  exists sig; smt(wrapper_wots_signature_planned_extends).
qed.

lemma wrapper_wots_plan_sign_ready seed0 root0 message0 :
  hoare [WrapperChainWotsPlanSigner(ObservedChain(Independent)).sign :
    seed=seed0 /\ root=root0 /\ message=message0 ==>
    res<>None => wrapper_wots_plan_ready Independent.rawhistory Independent.secrethistory
      seed0 root0 message0 (oget res)].
proof.
  conseq (wrapper_wots_observed_plan_supported seed0 root0 message0)
    (wrapper_wots_plan_sign_lower_root seed0);
    rewrite /wrapper_wots_plan_ready /wrapper_wots_signer_supported /wrapper_wots_result_planned;
    smt().
qed.

lemma wrapper_wots_plan_sign_evidence seed0 root0 message0 opened0 :
  hoare [WrapperChainWotsPlanSigner(ObservedChain(Independent)).sign :
    seed=seed0 /\ root=root0 /\ message=message0 /\ ChainStage.seed=seed0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0 ==>
    ChainRevelation.opened=opened0 /\
    (res<>None => wrapper_wots_plan_ready Independent.rawhistory Independent.secrethistory
      seed0 root0 message0 (oget res))].
proof.
  conseq (wrapper_wots_plan_sign_ready seed0 root0 message0)
    (wrapper_wots_plan_sign_unopened seed0 opened0); smt().
qed.

lemma wrapper_wots_plan_ready_preserved seed0 root0 message0 plan0 :
  hoare [WrapperChainWotsPlanSigner(ObservedChain(Independent)).sign :
    wrapper_wots_plan_ready Independent.rawhistory Independent.secrethistory seed0 root0 message0 plan0 ==>
    wrapper_wots_plan_ready Independent.rawhistory Independent.secrethistory seed0 root0 message0 plan0].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (wrapper_chain_complete_planner_histories WrapperChainWotsPlanSigner s0 h0);
    smt(extends_refl wrapper_wots_plan_ready_extends).
qed.

lemma wrapper_wots_second_plan_evidence seed0 root0 message0 plan0 opened0 :
  hoare [WrapperChainWotsPlanSigner(ObservedChain(Independent)).sign :
    seed=seed0 /\ ChainStage.seed=seed0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0 /\
    wrapper_wots_plan_ready Independent.rawhistory Independent.secrethistory seed0 root0 message0 plan0 ==>
    ChainRevelation.opened=opened0 /\
    wrapper_wots_plan_ready Independent.rawhistory Independent.secrethistory seed0 root0 message0 plan0].
proof.
  conseq (wrapper_wots_plan_ready_preserved seed0 root0 message0 plan0)
    (wrapper_wots_plan_sign_unopened seed0 opened0); smt().
qed.

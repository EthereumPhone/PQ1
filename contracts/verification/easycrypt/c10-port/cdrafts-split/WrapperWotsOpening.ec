(* The observer can open a proper WOTS cut only on an external release.
   Refused internal attempts leave the opening flag unchanged. *)
require import AllCore List FMap.
require import C10RawOracle C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawSigner.
require import PersistentGrind AcceptedContexts ChainValueView ChainStageSampling CachedChainOracle.
require import ObservedValueOpening ObservedCutEvidence ObservedSignerOpening.
require import WrapperWotsSigningPlan WrapperWotsPlanSigner WrapperWotsPlanRoots WrapperWotsPlanEvidence.
require import WrapperChainWotsPlanSigner WrapperChainReleasedWots WrapperWotsRelease WrapperWotsReleaseObserver.

lemma wrapper_wots_release_ready_opening seed0 root0 message0 plan0 opened0 :
  hoare [WrapperWotsRelease(ObservedChain(Independent)).run :
    seed=seed0 /\ plan=plan0 /\
    wrapper_wots_plan_ready Independent.rawhistory Independent.secrethistory seed0 root0 message0 plan0 /\
    ChainStage.seed=seed0 /\ valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainRevelation.opened=opened0 ==>
    ChainRevelation.opened => opened0 \/
      returned_cut_opened Independent.rawhistory Independent.secrethistory seed0 root0 message0 res
        ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (_ : exists signature0,
    seed=seed0 /\ plan=plan0 /\ Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    wrapper_wots_signature_planned h0 s0 seed0 signature0 plan0 /\
    wrapper_wots_hmsg_entry h0 seed0 root0 message0 plan0 /\
    wrapper_wots_plan_lower_root h0 s0 seed0 plan0 /\
    ChainStage.seed=seed0 /\ valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainRevelation.opened=opened0 ==> _) => //.
  + rewrite /wrapper_wots_plan_ready; smt().
  elim* => signature0.
  conseq (wrapper_wots_release_observed seed0 signature0 plan0 opened0 h0 s0);
    rewrite /returned_cut_opened /wrapper_wots_hmsg_entry /wrapper_wots_signature_planned; smt().
qed.

lemma wrapper_released_wots_opening seed0 root0 message0 opened0 :
  hoare [WrapperChainReleasedWots(ObservedChain(Independent)).sign :
    seed=seed0 /\ root=root0 /\ message=message0 /\ ChainStage.seed=seed0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0 ==>
    ChainRevelation.opened => opened0 \/
      (res<>None /\ returned_cut_opened Independent.rawhistory Independent.secrethistory
        seed0 root0 message0 (oget res) ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut)].
proof.
  proc; sp 1; if; last by auto; smt().
  seq 1 : (seed=seed0 /\ root=root0 /\ message=message0 /\ ChainStage.seed=seed0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0 /\
    (first<>None => wrapper_wots_plan_ready Independent.rawhistory Independent.secrethistory
      seed0 root0 message0 (oget first))).
  + call (wrapper_wots_plan_sign_evidence seed0 root0 message0 opened0); auto.
  if; last by auto; smt().
  exists* first; elim* => plan0.
  seq 1 : (seed=seed0 /\ first=plan0 /\ ChainStage.seed=seed0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainRevelation.opened=opened0 /\
    wrapper_wots_plan_ready Independent.rawhistory Independent.secrethistory seed0 root0 message0 (oget plan0)).
  + call (wrapper_wots_second_plan_evidence seed0 root0 message0 (oget plan0) opened0); auto; smt().
  if; last by auto; smt().
  if; last by auto; smt().
  wp; call (wrapper_wots_release_ready_opening seed0 root0 message0 (oget plan0) opened0); auto; smt().
qed.

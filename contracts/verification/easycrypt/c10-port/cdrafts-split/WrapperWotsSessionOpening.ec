(* Adaptive retries retain an external-release ledger. There is no absorbing
   failure premise: every newly opened cut must have a returned signature. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawSigner.
require import WrapperSession ExposureLog ClientQueryLog WrapperExposureLog WrapperWotsReleaseSession.
require import PersistentGrind AcceptedContexts MonotoneHistory ChainValueView ChainStageSampling CachedChainOracle.
require import ObservedValueOpening ObservedHistory ObservedSignerOpening ExposureCutEvidence.
require import WrapperChainReleasedWots WrapperWotsOpening.

module type WrapperChainSigning (O : ChainOracle) = {
  proc sign(seed root random message shuffle_a shuffle_b : raw_input, ready final_guard : bool) :
    raw_signature option { O.hash,O.derive,O.value }
}.

op wrapper_cut_accounted h s seed root entries layer tree kp index cut opened =
  (opened => exposure_cut_opened h s seed root entries layer tree kp index cut).

lemma wrapper_chain_signing_histories
  (S <: WrapperChainSigning {-Independent,-ChainStage,-ChainCut,-ChainRevelation,-CachedChain,-ObservedChain}) s0 h0 :
  hoare [S(ObservedChain(Independent)).sign :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory) => //.
  + exact (independent_hash_extends s0 h0).
  + exact (observed_derive_extends s0 h0).
  exact (observed_value_extends s0 h0).
qed.

lemma wrapper_chain_released_history_opening seed0 root0 message0 opened0 s0 h0 :
  hoare [WrapperChainReleasedWots(ObservedChain(Independent)).sign :
    seed=seed0 /\ root=root0 /\ message=message0 /\ ChainStage.seed=seed0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    (ChainRevelation.opened => opened0 \/
      (res<>None /\ returned_cut_opened Independent.rawhistory Independent.secrethistory seed0 root0 message0
        (oget res) ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut))].
proof.
  conseq (wrapper_released_wots_opening seed0 root0 message0 opened0)
    (wrapper_chain_signing_histories WrapperChainReleasedWots s0 h0); smt().
qed.

lemma wrapper_wots_session_opening seed0 root0 message0 opened0 s0 h0 :
  hoare [WrapperWotsReleaseSession(ChainPrefix(ObservedChain(Independent)),ObservedChain(Independent)).sign :
    WrapperSession.seed=seed0 /\ WrapperSession.root=root0 /\ message=message0 /\ ChainStage.seed=seed0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    (ChainRevelation.opened => opened0 \/
      (res<>None /\ returned_cut_opened Independent.rawhistory Independent.secrethistory seed0 root0 message0
        (oget res) ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut))].
proof.
  proc; sp 1; if; last by auto; smt().
  wp; call (wrapper_chain_released_history_opening seed0 root0 message0 opened0 s0 h0); auto; smt().
qed.

lemma wrapper_wots_exposure_sign_accounted :
  hoare [WrapperWotsReleaseExposure(ChainPrefix(ObservedChain(Independent)),ObservedChain(Independent)).sign :
    ChainStage.seed=WrapperSession.seed /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\ ChainCut.cut<7 /\
    wrapper_cut_accounted Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut ChainRevelation.opened ==>
    ChainStage.seed=WrapperSession.seed /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\ ChainCut.cut<7 /\
    wrapper_cut_accounted Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut ChainRevelation.opened].
proof.
  proc; exists* WrapperSession.seed,WrapperSession.root,message,ChainRevelation.opened,
    Independent.secrethistory,Independent.rawhistory; elim* => seed0 root0 message0 opened0 s0 h0.
  wp; call (wrapper_wots_session_opening seed0 root0 message0 opened0 s0 h0).
  auto; rewrite /wrapper_cut_accounted;
    smt(extends_refl exposure_cut_opened_extends exposure_cut_opened_rcons).
qed.

lemma wrapper_wots_exposure_hash_history s0 h0 :
  hoare [WrapperWotsReleaseExposure(ChainPrefix(ObservedChain(Independent)),ObservedChain(Independent)).hash :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc; inline WrapperSession(ChainPrefix(ObservedChain(Independent))).hash; if.
  + rcondt 4; first by auto.
    wp; call (independent_hash_extends s0 h0); auto.
  rcondf 3; first by auto.
  auto.
qed.

lemma wrapper_wots_exposure_hash_accounted :
  hoare [WrapperWotsReleaseExposure(ChainPrefix(ObservedChain(Independent)),ObservedChain(Independent)).hash :
    ChainStage.seed=WrapperSession.seed /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\ ChainCut.cut<7 /\
    wrapper_cut_accounted Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut ChainRevelation.opened ==>
    ChainStage.seed=WrapperSession.seed /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\ ChainCut.cut<7 /\
    wrapper_cut_accounted Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut ChainRevelation.opened].
proof.
  exists* Independent.secrethistory,Independent.rawhistory; elim* => s0 h0.
  conseq (wrapper_wots_exposure_hash_history s0 h0); rewrite /wrapper_cut_accounted;
    smt(extends_refl exposure_cut_opened_extends).
qed.

lemma wrapper_wots_client_cut_accounted
  (A <: WrapperClient {-Independent,-WrapperSession,-ExposureLog,-ClientQueryLog,-ChainStage,-ChainCut,-ChainRevelation}) :
  hoare [A(WrapperWotsReleaseExposure(ChainPrefix(ObservedChain(Independent)),ObservedChain(Independent))).run :
    ChainStage.seed=WrapperSession.seed /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\ ChainCut.cut<7 /\
    wrapper_cut_accounted Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut ChainRevelation.opened ==>
    ChainStage.seed=WrapperSession.seed /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\ ChainCut.cut<7 /\
    wrapper_cut_accounted Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut ChainRevelation.opened].
proof.
  proc (ChainStage.seed=WrapperSession.seed /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\ ChainCut.cut<7 /\
    wrapper_cut_accounted Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut ChainRevelation.opened) => //.
  + exact wrapper_wots_exposure_hash_accounted.
  exact wrapper_wots_exposure_sign_accounted.
qed.

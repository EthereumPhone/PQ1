(* Failed signing is absorbing; every opening in a live session has a returned witness. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawSigner FullSession ExposureLog ClientQueryLog.
require import PersistentGrind AcceptedContexts MonotoneHistory.
require import ChainValueView ChainStageSampling CachedChainOracle ChainSignerView ChainSessionView.
require import ObservedValueOpening ObservedSignerOpening ExposureCutEvidence.

op session_cut_accounted h s seed root entries layer tree kp index cut failed opened =
  (!failed /\ opened => exposure_cut_opened h s seed root entries layer tree kp index cut).

lemma observed_chain_session_opening seed0 root0 message0 opened0 failed0 s0 h0 :
  hoare[ChainSession(ObservedChain(Independent)).sign :
    FullSession.seed=seed0 /\ FullSession.root=root0 /\ message=message0 /\ ChainStage.seed=seed0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\ ChainCut.cut<7 /\
    ChainRevelation.opened=opened0 /\ FullSession.failed=failed0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    (failed0 => FullSession.failed) /\
    (!FullSession.failed /\ ChainRevelation.opened => opened0 \/
      (res<>None /\ returned_cut_opened Independent.rawhistory Independent.secrethistory seed0 root0 message0
        (oget res) ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut))].
proof.
  proc; sp 1; if; last by auto; smt().
  wp; call (observed_signer_history_opening seed0 root0 message0 opened0 s0 h0); auto; smt().
qed.
lemma observed_exposure_sign_accounted :
  hoare[ChainExposureSession(ObservedChain(Independent)).sign :
    ChainStage.seed=FullSession.seed /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\ ChainCut.cut<7 /\
    session_cut_accounted Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut
      FullSession.failed ChainRevelation.opened ==>
    ChainStage.seed=FullSession.seed /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\ ChainCut.cut<7 /\
    session_cut_accounted Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut
      FullSession.failed ChainRevelation.opened].
proof.
  proc; exists* FullSession.seed,FullSession.root,message,ChainRevelation.opened,FullSession.failed,
    Independent.secrethistory,Independent.rawhistory;
    elim* => seed0 root0 message0 opened0 failed0 s0 h0.
  wp; call (observed_chain_session_opening seed0 root0 message0 opened0 failed0 s0 h0).
  auto; rewrite /session_cut_accounted;
    smt(extends_refl exposure_cut_opened_extends exposure_cut_opened_rcons).
qed.
lemma observed_exposure_hash_history s0 h0 :
  hoare[ChainExposureSession(ObservedChain(Independent)).hash :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc; inline FullSession(ChainPrefix(ObservedChain(Independent))).hash; if.
  + rcondt 4; first by auto.
    wp; call (independent_hash_extends s0 h0); auto.
  rcondf 3; first by auto.
  auto.
qed.
lemma observed_exposure_hash_accounted :
  hoare[ChainExposureSession(ObservedChain(Independent)).hash :
    ChainStage.seed=FullSession.seed /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\ ChainCut.cut<7 /\
    session_cut_accounted Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut
      FullSession.failed ChainRevelation.opened ==>
    ChainStage.seed=FullSession.seed /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\ ChainCut.cut<7 /\
    session_cut_accounted Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut
      FullSession.failed ChainRevelation.opened].
proof.
  exists* Independent.secrethistory,Independent.rawhistory; elim* => s0 h0.
  conseq (observed_exposure_hash_history s0 h0); rewrite /session_cut_accounted;
    smt(extends_refl exposure_cut_opened_extends).
qed.
lemma observed_client_cut_accounted
  (A <: FullClient {-Independent,-FullSession,-ExposureLog,-ClientQueryLog,-ChainStage,-ChainCut,-ChainRevelation}) :
  hoare[A(ChainExposureSession(ObservedChain(Independent))).run :
    ChainStage.seed=FullSession.seed /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\ ChainCut.cut<7 /\
    session_cut_accounted Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut
      FullSession.failed ChainRevelation.opened ==>
    ChainStage.seed=FullSession.seed /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\ ChainCut.cut<7 /\
    session_cut_accounted Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut
      FullSession.failed ChainRevelation.opened].
proof.
  proc (ChainStage.seed=FullSession.seed /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\ ChainCut.cut<7 /\
    session_cut_accounted Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut
      FullSession.failed ChainRevelation.opened) => //.
  + exact observed_exposure_hash_accounted.
  exact observed_exposure_sign_accounted.
qed.

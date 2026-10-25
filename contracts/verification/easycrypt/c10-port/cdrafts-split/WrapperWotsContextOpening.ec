(* Initialization, adaptive calls and final public verification preserve the
   release-only opening ledger without an absorbing failure state. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen RawSigner.
require import WrapperSession WrapperByteSession ExposureLog ClientQueryLog WrapperWotsReleaseSession WrapperWotsChainContext.
require import PersistentGrind AcceptedContexts ChainValueView ChainStageSampling CachedChainOracle.
require import ObservedValueOpening ObservedGameOpening ExposureCutEvidence WrapperWotsSessionOpening.

lemma wrapper_wots_driver_cut_accounted
  (A <: WrapperClient {-Independent,-WrapperSession,-ExposureLog,-ClientQueryLog,-ChainStage,-ChainCut,-ChainRevelation}) :
  hoare [WrapperWotsReleaseDriver(A,ChainPrefix(ObservedChain(Independent)),ObservedChain(Independent)).run :
    ChainStage.seed=seed /\ valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ !ChainRevelation.opened ==>
    ChainRevelation.opened => exposure_cut_opened Independent.rawhistory Independent.secrethistory
      WrapperSession.seed WrapperSession.root ExposureLog.entries
      ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut].
proof.
  proc; seq 5 : (wrapper_cut_accounted Independent.rawhistory Independent.secrethistory
    WrapperSession.seed WrapperSession.root ExposureLog.entries
    ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut ChainRevelation.opened).
  + call (wrapper_wots_client_cut_accounted A); wp;
      inline WrapperSession(ChainPrefix(ObservedChain(Independent))).init;
      auto; rewrite /wrapper_cut_accounted; smt().
  sp 2; if; last by auto; rewrite /wrapper_cut_accounted; smt().
  exists* Independent.secrethistory,Independent.rawhistory; elim* => s0 h0.
  call (observed_verify_histories RawSigner s0 h0); auto;
    rewrite /wrapper_cut_accounted; smt(extends_refl exposure_cut_opened_extends).
qed.

lemma wrapper_wots_context_cut_accounted
  (A <: WrapperClient {-Independent,-WrapperSession,-ExposureLog,-ClientQueryLog,-ChainStage,-ChainCut,-ChainRevelation}) :
  hoare [WrapperChainWotsContext(A,ObservedChain(Independent)).run :
    ChainStage.seed=pad(node KeygenInputs.public_seed) /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ !ChainRevelation.opened ==>
    ChainRevelation.opened => exposure_cut_opened Independent.rawhistory Independent.secrethistory
      WrapperSession.seed WrapperSession.root ExposureLog.entries
      ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut].
proof.
  proc; call (wrapper_wots_driver_cut_accounted A).
  call (observed_preparation_unopened false); auto; smt().
qed.

lemma wrapper_wots_candidates_cut_accounted
  (A <: WrapperByteClient {-Independent,-WrapperSession,-ExposureLog,-ClientQueryLog,-ChainStage,-ChainCut,-ChainRevelation}) :
  hoare [WrapperChainWotsCandidates(A,ObservedChain(Independent)).run :
    ChainStage.seed=pad(node KeygenInputs.public_seed) /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ !ChainRevelation.opened ==>
    ChainRevelation.opened => exposure_cut_opened Independent.rawhistory Independent.secrethistory
      WrapperSession.seed WrapperSession.root ExposureLog.entries
      ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut].
proof. proc; wp; call (wrapper_wots_context_cut_accounted (WrapperByteLift(A))); auto. qed.

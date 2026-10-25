(* The original wrapper's returned references transfer to the passive chain
   game. A selected unreturned cut consequently remains unopened. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen.
require import WrapperSession WrapperByteSession ExposureLog ClientQueryLog ExposureSupport.
require import WrapperQueryDriver WrapperExposureHistory WrapperWotsChainContext WrapperWotsContextOpening.
require import ChainValueView ChainStageSampling CachedChainOracle ChainContextCoupling.
require import ObservedValueOpening ExposureCutEvidence ActualWotsCoordinate.

lemma wrapper_observed_wots_candidates_projection
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,
    -ChainStage,-ChainCut,-ChainRevelation,-CachedChain,-ObservedChain}) :
  equiv [WrapperOriginalWotsCandidates(A,Independent).run ~ WrapperChainWotsCandidates(A,ObservedChain(Independent)).run :
    ={glob A,glob Independent,glob WrapperLimits,glob KeygenInputs,glob WrapperSession,glob ExposureLog,glob ClientQueryLog} ==>
    ={res,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory}].
proof.
  transitivity WrapperChainWotsCandidates(A,ConcreteChain(Independent)).run
    (={glob A,glob Independent,glob WrapperLimits,glob KeygenInputs,glob WrapperSession,glob ExposureLog,glob ClientQueryLog} ==>
      ={res,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory})
    (={glob A,glob Independent,glob WrapperLimits,glob KeygenInputs,glob WrapperSession,glob ExposureLog,glob ClientQueryLog} ==>
      ={res,glob A,glob Independent,glob WrapperSession,glob ExposureLog,glob ClientQueryLog}) => //.
  + smt().
  + conseq (wrapper_wots_candidates_projection A); smt().
  conseq (chain_context_observer_projection (WrapperChainWotsCandidates(A))); smt().
qed.

lemma wrapper_original_wots_candidates_supported
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) qs0 :
  0<=qs0 =>
  hoare [WrapperOriginalWotsCandidates(A,Independent).run : WrapperLimits.sign_cap=qs0 ==>
    exposures_supported Independent.rawhistory Independent.secrethistory
      WrapperSession.seed WrapperSession.root ExposureLog.entries].
proof.
  move=> hqs; proc; wp; call (wrapper_query_context_history (WrapperByteLift(A)) qs0 hqs);
    auto; rewrite /wrapper_exposures_supported; smt().
qed.

lemma wrapper_observed_wots_candidates_supported
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,
    -ChainStage,-ChainCut,-ChainRevelation,-CachedChain,-ObservedChain}) qs0 :
  0<=qs0 =>
  hoare [WrapperChainWotsCandidates(A,ObservedChain(Independent)).run : WrapperLimits.sign_cap=qs0 ==>
    exposures_supported Independent.rawhistory Independent.secrethistory
      WrapperSession.seed WrapperSession.root ExposureLog.entries].
proof.
  move=> hqs.
  have he : equiv [WrapperChainWotsCandidates(A,ObservedChain(Independent)).run ~ WrapperOriginalWotsCandidates(A,Independent).run :
    ={glob A,glob Independent,glob WrapperLimits,glob KeygenInputs,glob WrapperSession,glob ExposureLog,glob ClientQueryLog} ==>
    ={Independent.rawhistory,Independent.secrethistory,glob WrapperSession,glob ExposureLog}]
    by symmetry; conseq (wrapper_observed_wots_candidates_projection A); smt().
  conseq he (wrapper_original_wots_candidates_supported A qs0 hqs); smt().
qed.

lemma wrapper_observed_actual_cut_unopened
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,
    -ChainStage,-ChainCut,-ChainRevelation,-CachedChain,-ObservedChain}) qs0 :
  0<=qs0 =>
  hoare [WrapperChainWotsCandidates(A,ObservedChain(Independent)).run :
    WrapperLimits.sign_cap=qs0 /\ ChainStage.seed=pad(node KeygenInputs.public_seed) /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ !ChainRevelation.opened ==>
    selected_wots_cut Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries res (ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,ChainCut.cut) =>
    !ChainRevelation.opened].
proof.
  move=> hqs.
  conseq (wrapper_wots_candidates_cut_accounted A) (wrapper_observed_wots_candidates_supported A qs0 hqs).
  + smt().
  rewrite /selected_wots_cut /=; smt(exposure_cut_conflicts_unreturned).
qed.

(* Selected-cut probability for the actual initialized byte wrapper. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen.
require import WrapperSession WrapperByteSession ExposureLog ClientQueryLog.
require import ChainValueView ChainStageSampling CachedChainOracle ChainByteCandidates WrapperWotsChainContext.
require import PublicTargetSampling PrivateValueSampling ChainVectorInstall DualDigestSampling RedactedChainOracle ChainPublicHybrid.
require import WrapperSelectedChainSampling WrapperLateSelectedPreservation WrapperEarlyObservedWots WrapperEarlySelectedCharge.
require import FreshChainGuess WrapperWotsFreshBound WrapperWotsCandidateBudget ObservedValueOpening.
require import WotsCoordinateUniverse WotsCoordinateValidity ActualWotsCoordinate.
import RealOrder.

require import PrefixIdeal WrapperQueryDriver WrapperOriginalWotsUnion WrapperOriginalWotsCoordinateBound ActualWotsCut.

lemma wrapper_byte_wots_cut_bound
  (A <: WrapperByteClient {-Independent,-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WrapperWotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,-CachedChain,
    -SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,
    -ChainRedaction,-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,
    -ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) qr qs &m :
  (forall (V <: WrapperByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : res /\
    (actual_top_cut Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries ClientQueryLog.output \/
     actual_bottom_cut Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
      ExposureLog.entries ClientQueryLog.output)] <=
    632475648%r*((wrapper_wots_candidate_budget qr qs+88)%r*(1%r/2%r)^128).
proof.
  move=> ha hr hs hqr hqs.
  have he : Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : res /\
      (actual_top_cut Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
        ExposureLog.entries ClientQueryLog.output \/
       actual_bottom_cut Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
        ExposureLog.entries ClientQueryLog.output)] <=
    Pr[WrapperOriginalWotsCandidateGame(A).run() @ &m : exists c, mem wots_coordinates c /\
      selected_wots_cut Independent.rawhistory Independent.secrethistory WrapperSession.seed WrapperSession.root
        ExposureLog.entries res c].
  + byequiv (_ : ={glob A,glob Independent,glob WrapperLimits,glob KeygenInputs,glob WrapperSession,
      glob ExposureLog,glob ClientQueryLog} ==> _) => //.
    proc; inline WrapperOriginalWotsCandidates(A,Independent).run.
    wp; call (_ : ={glob A,glob Independent,glob WrapperLimits,glob KeygenInputs,glob WrapperSession,
      glob ExposureLog,glob ClientQueryLog}); first by sim.
    inline Independent.init; auto; smt(actual_top_coordinate actual_bottom_coordinate).
  have hb:=wrapper_original_wots_universe_bound A qr qs &m ha hr hs hqr hqs; smt().
qed.

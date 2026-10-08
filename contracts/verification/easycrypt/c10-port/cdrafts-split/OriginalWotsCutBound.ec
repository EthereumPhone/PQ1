(* Fixed-coordinate WOTS charge for the unchanged initialized adaptive byte candidate game. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen FullPrefix.
require import FullSession ByteSession ExposureLog ClientQueryLog.
require import ChainValueView ChainStageSampling CachedChainOracle ChainByteCandidates.
require import PublicTargetSampling PrivateValueSampling ChainVectorInstall DualDigestSampling RedactedChainOracle ChainPublicHybrid.
require import SelectedChainSampling LateSelectedPreservation EarlyObservedWots EarlySelectedCharge FreshChainGuess FreshByteBound.
require import ObservedValueOpening.
require import SelectedWotsBound WotsCoordinateUniverse WotsCoordinateValidity ActualWotsCoordinate.
require import PrefixIdeal ClientQueryDriver OriginalWotsUnion OriginalWotsCoordinateBound ActualWotsCut.
import RealOrder.



lemma original_byte_wots_cut_bound
  (A <: ByteClient {-Independent,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,-CachedChain,
    -SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,
    -ChainRedaction,-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,
    -ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) qr qs &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : res /\
    (actual_top_cut Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries ClientQueryLog.output \/
     actual_bottom_cut Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries ClientQueryLog.output)] <=
    632475648%r*((full_public_budget qr qs+86)%r*(1%r/2%r)^128).
proof.
  move=> ha hr hs hqr hqs.
  have he : Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : res /\
      (actual_top_cut Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
        ExposureLog.entries ClientQueryLog.output \/
       actual_bottom_cut Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
        ExposureLog.entries ClientQueryLog.output)] <=
    Pr[OriginalWotsCandidateGame(A).run() @ &m : exists c, mem wots_coordinates c /\
      selected_wots_cut Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
        ExposureLog.entries res c].
  + byequiv (_ : ={glob A,glob Independent,glob FullLimits,glob KeygenInputs,glob FullSession,
      glob ExposureLog,glob ClientQueryLog} ==> _) => //.
    proc; inline OriginalWotsCandidates(A,Independent).run.
    wp; call (_ : ={glob A,glob Independent,glob FullLimits,glob KeygenInputs,glob FullSession,
      glob ExposureLog,glob ClientQueryLog}); first by sim.
    inline Independent.init; auto; smt(actual_top_coordinate actual_bottom_coordinate).
  have hb:=original_wots_universe_bound A qr qs &m ha hr hs hqr hqs; smt().
qed.

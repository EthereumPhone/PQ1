require import AllCore List Distr StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen FullPrefix.
require import FullSession ByteSession ExposureLog ClientQueryLog.
require import ChainValueView ChainStageSampling CachedChainOracle ChainByteCandidates.
require import PublicTargetSampling PrivateValueSampling ChainVectorInstall DualDigestSampling RedactedChainOracle ChainPublicHybrid.
require import SelectedChainSampling LateSelectedPreservation EarlyObservedWots EarlySelectedCharge FreshChainGuess FreshCandidateByteBound.
require import ObservedValueOpening.
require import SelectedWotsCandidateBound WotsCoordinateUniverse WotsCoordinateValidity ActualWotsCoordinate.
require import WotsCandidateCoordinateBound.
require import ChainVariableSessionCost ChainCandidateMass ChainCandidateBound OriginalWotsCoordinateBound.
import RealOrder.
require import WotsCandidateUnion.

lemma checked (A <: ByteClient {-Independent,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,-CachedChain,
    -SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,
    -ChainRedaction,-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,
    -ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) qr qs &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[OriginalWotsCandidateGame(A).run() @ &m : exists c, mem wots_coordinates c /\
    selected_wots_cut Independent.rawhistory Independent.secrethistory FullSession.seed FullSession.root
      ExposureLog.entries res c] <=
    632475648%r*((chain_candidate_budget qr qs+86+2)%r*(1%r/2%r)^128).
proof.
  move=> ha hr hs hqr hqs; exact (original_wots_candidate_universe_bound A qr qs &m ha hr hs hqr hqs).
qed.

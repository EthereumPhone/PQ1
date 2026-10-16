require import AllCore List Distr StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen FullPrefix.
require import FullSession ByteSession ExposureLog ClientQueryLog.
require import ChainValueView ChainStageSampling CachedChainOracle ChainByteCandidates.
require import PublicTargetSampling PrivateValueSampling ChainVectorInstall DualDigestSampling RedactedChainOracle ChainPublicHybrid.
require import SelectedChainSampling LateSelectedPreservation EarlyObservedWots EarlySelectedCharge FreshChainGuess FreshCandidateByteBound.
require import ObservedValueOpening.
require import ChainVariableSessionCost ChainCandidateMass ChainCandidateBound OriginalWotsCoordinateBound.
import RealOrder.
require import SelectedWotsCandidateBound.

lemma checked (A <: ByteClient {-Independent,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,-CachedChain,
    -SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,
    -ChainRedaction,-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,
    -ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>

  valid_chain_address ChainStage.layer{m} ChainStage.tree{m} ChainStage.kp{m} ChainStage.index{m} =>
  0<=ChainCut.cut{m}<7 => 0<=FullLimits.raw_cap{m} => 0<=FullLimits.sign_cap{m} =>
  Pr[SelectedWotsGame(A).run() @ &m : res] <=
    8%r*(chain_candidate_budget FullLimits.raw_cap{m} FullLimits.sign_cap{m}+86+2)%r*(1%r/2%r)^128.
proof.
  exact (selected_wots_candidate_bound A &m).
qed.

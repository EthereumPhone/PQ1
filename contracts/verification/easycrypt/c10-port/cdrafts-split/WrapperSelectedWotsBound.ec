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


lemma wrapper_selected_wots_bound
  (A <: WrapperByteClient {-Independent,-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WrapperWotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,-CachedChain,
    -SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,
    -ChainRedaction,-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,
    -ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) &m :
  (forall (V <: WrapperByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  ChainStage.seed{m}=pad(node KeygenInputs.public_seed{m}) =>
  valid_chain_address ChainStage.layer{m} ChainStage.tree{m} ChainStage.kp{m} ChainStage.index{m} =>
  0<=ChainCut.cut{m}<7 => 0<=WrapperLimits.raw_cap{m} => 0<=WrapperLimits.sign_cap{m} =>
  Pr[WrapperSelectedWotsGame(A).run() @ &m : res] <=
    8%r*(wrapper_wots_candidate_budget WrapperLimits.raw_cap{m} WrapperLimits.sign_cap{m}+88)%r*(1%r/2%r)^128.
proof.
  move=> ha hseed hc hcut hr hs.
  have h1 : Pr[WrapperSelectedWotsGame(A).run() @ &m : res]<=Pr[WrapperLateSelectedWotsGame(A).run() @ &m : res].
  + byequiv (wrapper_selected_wots_late_preserved A) => //; move: hc; rewrite /valid_chain_address; smt().
  have h2 : Pr[WrapperEarlySelectedWotsGame(A).run() @ &m : res]=Pr[WrapperLateSelectedWotsGame(A).run() @ &m : res]
    by byequiv (wrapper_selected_chain_early_late A) => //.
  have h3 : Pr[WrapperEarlySelectedWotsGame(A).run() @ &m : res]=Pr[WrapperEarlyPlainWotsGame(A).run() @ &m : res]
    by byequiv (wrapper_early_selected_plain A) => //.
  have h4 : Pr[WrapperEarlyPlainWotsGame(A).run() @ &m : res]=Pr[WrapperEarlyObservedWotsGame(A).run() @ &m : res]
    by byequiv (wrapper_early_plain_observed A) => //.
  have h5 : Pr[WrapperEarlyObservedWotsGame(A).run() @ &m : res]<=
    Pr[FreshCachedChainGuess(WrapperChainWotsCandidates(A)).run() @ &m : res].
  + byequiv (wrapper_early_observed_cache_charge A WrapperLimits.sign_cap{m} hs) => //; smt().
  have hb:=wrapper_wots_fresh_candidate_bound A &m ha hcut hr hs.
  smt().
qed.

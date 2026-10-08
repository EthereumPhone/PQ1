(* Fixed-coordinate WOTS charge for the unchanged initialized adaptive byte candidate game. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen FullPrefix.
require import FullSession ByteSession ExposureLog ClientQueryLog.
require import ChainValueView ChainStageSampling CachedChainOracle ChainByteCandidates.
require import PublicTargetSampling PrivateValueSampling ChainVectorInstall DualDigestSampling RedactedChainOracle ChainPublicHybrid.
require import SelectedChainSampling LateSelectedPreservation EarlyObservedWots EarlySelectedCharge FreshChainGuess FreshByteBound.
require import ObservedValueOpening.
import RealOrder.

lemma selected_wots_original_bound
  (A <: ByteClient {-Independent,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -WotsCandidatesLog,-ChainStage,-ChainCut,-ChainRevelation,-ObservedChain,-CachedChain,
    -SamplingOracle,-PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample,
    -ChainRedaction,-ChainVectorInstall,-RedactedCachedChain,-RedactedChainPrefix,-DualDigest,
    -ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  ChainStage.seed{m}=pad(node KeygenInputs.public_seed{m}) =>
  valid_chain_address ChainStage.layer{m} ChainStage.tree{m} ChainStage.kp{m} ChainStage.index{m} =>
  0<=ChainCut.cut{m}<7 => 0<=FullLimits.raw_cap{m} => 0<=FullLimits.sign_cap{m} =>
  Pr[SelectedWotsGame(A).run() @ &m : res] <=
    8%r*(full_public_budget FullLimits.raw_cap{m} FullLimits.sign_cap{m}+86)%r*(1%r/2%r)^128.
proof.
  move=> ha hseed hc hcut hr hs.
  have h1 : Pr[SelectedWotsGame(A).run() @ &m : res]<=Pr[LateSelectedWotsGame(A).run() @ &m : res].
  + byequiv (selected_wots_late_preserved A) => //; move: hc; rewrite /valid_chain_address; smt().
  have h2 : Pr[EarlySelectedWotsGame(A).run() @ &m : res]=Pr[LateSelectedWotsGame(A).run() @ &m : res]
    by byequiv (selected_chain_early_late A) => //.
  have h3 : Pr[EarlySelectedWotsGame(A).run() @ &m : res]=Pr[EarlyPlainWotsGame(A).run() @ &m : res]
    by byequiv (early_selected_plain A) => //.
  have h4 : Pr[EarlyPlainWotsGame(A).run() @ &m : res]=Pr[EarlyObservedWotsGame(A).run() @ &m : res]
    by byequiv (early_plain_observed A) => //.
  have h5 : Pr[EarlyObservedWotsGame(A).run() @ &m : res]<=
    Pr[FreshCachedChainGuess(ChainByteCandidates(A)).run() @ &m : res].
  + byequiv (early_observed_cache_charge A FullLimits.sign_cap{m} hs) => //; smt().
  have hb:=fresh_byte_unopened_bound A &m ha hcut hr hs.
  smt().
qed.

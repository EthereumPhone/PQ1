(* The byte client's selected programmed-chain charge has no remaining cost premise. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion FullPrefix.
require import FullSession ByteSession ExposureLog ClientQueryLog.
require import ChainValueView ChainStageSampling CachedChainOracle ChainByteCandidates ChainByteLossless.
require import ChainVectorInstall DualDigestSampling RedactedChainOracle ChainPublicHybrid.
require import ChainVisibleGuess ProgrammedChainBound VisibleByteBudget.
import RealOrder.

lemma programmed_byte_unopened_bound
  (A <: ByteClient {-Independent,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -ChainStage,-ChainCut,-ChainRevelation,-ChainRedaction,-ChainVectorInstall,-CachedChain,
    -RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain}) &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=ChainCut.cut{m}<7 => 0<=FullLimits.raw_cap{m} => 0<=FullLimits.sign_cap{m} =>
  Pr[ProgrammedUnopenedChainGuess(ChainByteCandidates(A)).run() @ &m : res] <=
    8%r*(full_public_budget FullLimits.raw_cap{m} FullLimits.sign_cap{m}+86)%r*(1%r/2%r)^128.
proof.
  move=> ha hc hr hs.
  apply (programmed_unopened_chain_bound (ChainByteCandidates(A))
    (full_public_budget FullLimits.raw_cap{m} FullLimits.sign_cap{m}+86) &m).
  + move=> O hh hd hv; exact (chain_byte_candidates_lossless A O ha hh hd hv).
  + exact hc.
  + rewrite /full_public_budget /signing_budget; smt().
  conseq (visible_byte_candidate_budget A FullLimits.raw_cap{m} FullLimits.sign_cap{m} hr hs); smt().
qed.

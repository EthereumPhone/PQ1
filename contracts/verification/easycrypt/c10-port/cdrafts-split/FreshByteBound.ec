(* A numerical unopened-cut bound for fresh memo sampling and the actual byte client. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion FullPrefix.
require import FullSession ByteSession ExposureLog ClientQueryLog.
require import ChainValueView ChainStageSampling CachedChainOracle ChainByteCandidates ChainByteLossless.
require import ChainVectorInstall DualDigestSampling RedactedChainOracle ChainPublicHybrid.
require import PrivateValueSampling PublicTargetSampling FreshChainGuess ProgrammedChainBound ProgrammedByteBound.
import RealOrder.

lemma fresh_byte_unopened_bound
  (A <: ByteClient {-Independent,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,
    -ChainStage,-ChainCut,-ChainRevelation,-ChainRedaction,-ChainVectorInstall,-CachedChain,
    -RedactedCachedChain,-RedactedChainPrefix,-DualDigest,-ChainGuess,-ChainHybridPrefix,-HybridCachedChain,
    -PrivateMemoSample,-PrivateValueSample,-PublicMemoSample,-PublicTargetSample}) &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=ChainCut.cut{m}<7 => 0<=FullLimits.raw_cap{m} => 0<=FullLimits.sign_cap{m} =>
  Pr[FreshCachedChainGuess(ChainByteCandidates(A)).run() @ &m : res] <=
    8%r*(full_public_budget FullLimits.raw_cap{m} FullLimits.sign_cap{m}+86)%r*(1%r/2%r)^128.
proof.
  move=> ha hc hr hs.
  have hll : forall (O <: ChainOracle {-ChainByteCandidates(A)}),
    islossless O.hash => islossless O.derive => islossless O.value => islossless ChainByteCandidates(A,O).run.
  + move=> O hh hd hv; exact (chain_byte_candidates_lossless A O ha hh hd hv).
  have he1 : Pr[FreshCachedChainGuess(ChainByteCandidates(A)).run() @ &m : res]=
    Pr[FreshRedactedChainGuess(ChainByteCandidates(A)).run() @ &m : res]
    by byequiv (fresh_chain_redaction (ChainByteCandidates(A)) hll) => //.
  have he2 : Pr[FreshRedactedChainGuess(ChainByteCandidates(A)).run() @ &m : res]=
    Pr[ProgrammedUnopenedChainGuess(ChainByteCandidates(A)).run() @ &m : res].
  + byequiv (fresh_redacted_programmed (ChainByteCandidates(A))) => //; smt().
  rewrite he1 he2; exact (programmed_byte_unopened_bound A &m ha hc hr hs).
qed.

require import AllCore List Distr DList RealSeries StdOrder Ring.
require import C10RawOracle C10Randomizer RawWots WotsAcceptanceMass.
require import AcceptedPrefixSampling FullDigestPrefixSampling.
require import AcceptedEncodingPool.

lemma checked (A <: FullDigestClient {-FullDigestSamples}) q &m :
  0<=q => Pr[FullDigestGame(A).run() @ &m :
    accepted_encoding_pool_collision FullDigestSamples.nodes]<=
    accepted_encoding_charge q.
proof.
  move=> hq; exact (adaptive_accepted_encoding_bound A q &m hq).
qed.

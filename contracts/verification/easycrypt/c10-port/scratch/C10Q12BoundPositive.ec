require import AllCore List Distr StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames PrefixIdeal.
require import HonestByteContext HonestByteCost HonestBytePhysical.
import RealOrder.

lemma independent_error_zero &m : Pr[IndependentGame(HonestByteError).run() @ &m : res]=0%r.
proof. exact (independent_honest_byte_error_zero &m). qed.
lemma physical_error_bound &m : Pr[RealGame(HonestByteError).run() @ &m : res]<=30520798%r*(1%r/2%r)^256.
proof. exact (physical_honest_byte_error_concrete &m). qed.

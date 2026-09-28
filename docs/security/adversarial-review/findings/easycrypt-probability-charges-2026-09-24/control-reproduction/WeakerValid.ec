require import AllCore List Distr StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames PrefixIdeal.
require import HonestByteContext HonestByteCost HonestBytePhysical.
import RealOrder.

lemma true_weaker_bound &m : Pr[RealGame(HonestByteError).run() @ &m : res] <= 30520798%r * (1%r/2%r)^256 + 1%r.
proof. have h := physical_honest_byte_error_concrete &m; smt(). qed.

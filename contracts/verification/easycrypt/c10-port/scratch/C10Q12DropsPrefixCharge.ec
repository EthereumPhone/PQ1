require import AllCore List Distr StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames PrefixIdeal.
require import HonestByteContext HonestByteCost HonestBytePhysical.
import RealOrder.

lemma no_prefix_charge &m : Pr[RealGame(HonestByteError).run() @ &m : res]<=0%r.
proof. exact (physical_honest_byte_error_concrete &m). qed.

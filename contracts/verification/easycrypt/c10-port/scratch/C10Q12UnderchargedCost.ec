require import AllCore List Distr StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames PrefixIdeal.
require import HonestByteContext HonestByteCost HonestBytePhysical.
import RealOrder.

lemma undercharged_cost q0 :
  hoare [HonestByteError(Independent).run : size Independent.queries=q0 ==>
    q0<=size Independent.queries<=q0+3*signing_budget+364892].
proof. exact (honest_byte_public_cost q0). qed.

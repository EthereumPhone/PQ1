(* Discharge the valid-history invariant from the actual initialization and
   key preparation. The paired experiment preserves the same success event. *)
require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixGames KeygenPrefixes KeygenExhaustion.
require import FullSession ByteSession C10SearchAcceptance C10PairedSession.

require import C10PairedInitialization.

lemma checked
  (A <: ByteClient {-FullSession,-Physical,-Shared,-FullLimits,-KeygenInputs}) &m :
  Pr[RealGame(PairedByteContext(A)).run() @ &m : res] =
  Pr[RealGame(ByteContext(A)).run() @ &m : !res].
proof. exact (paired_byte_success_probability A &m). qed.

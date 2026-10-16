require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixGames.
require import RawKeygen KeygenPrefixes KeygenExhaustion FullSession ByteSession.
require import C10Representation C10CallerInputBridge C10TreeCallerBridge.
require import C10SearchAcceptance C10PairedSession C10PairedInitialization.
require import C10PairedKeygen.

lemma checked
  (A <: ByteClient {-FullSession,-Physical,-Shared,-FullLimits,-KeygenInputs}) &m :
  Pr[RealGame(PairedKeygenByteContext(A)).run() @ &m : res] =
  Pr[RealGame(ByteContext(A)).run() @ &m : !res].
proof. exact (paired_keygen_byte_success_probability A &m). qed.

require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixGames.
require import RawKeygen KeygenPrefixes KeygenExhaustion FullSession ByteSession.
require import C10Representation C10CallerInputBridge C10TreeCallerBridge.
require import C10SearchAcceptance C10PairedSession C10PairedInitialization.
require import C10PairedKeygen.

lemma checked
  (A <: ByteClient {-FullSession,-Physical,-Shared,-FullLimits,-KeygenInputs}) :
  equiv[RealGame(ByteContext(A)).run ~ RealGame(PairedKeygenByteContext(A)).run :
    ={glob A,glob KeygenInputs} ==>
    ={res,glob A,glob FullSession,glob Physical} /\ valid_history Shared.history{1}].
proof. exact (paired_keygen_byte_initialized A). qed.

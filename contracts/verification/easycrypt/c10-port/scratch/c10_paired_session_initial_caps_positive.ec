(* Discharge the valid-history invariant from the actual initialization and
   key preparation. The paired experiment preserves the same success event. *)
require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixGames KeygenPrefixes KeygenExhaustion.
require import FullSession ByteSession C10SearchAcceptance C10PairedSession.

require import C10PairedInitialization.

lemma checked
  (A <: ByteClient {-FullSession,-Physical,-Shared,-FullLimits,-KeygenInputs}) :
  equiv[RealGame(ByteContext(A)).run ~ RealGame(PairedByteContext(A)).run :
    ={glob A,glob FullLimits,glob KeygenInputs} ==>
    ={res,glob A,glob FullSession,glob Physical} /\ valid_history Shared.history{1}].
proof. exact (paired_byte_initialized A). qed.

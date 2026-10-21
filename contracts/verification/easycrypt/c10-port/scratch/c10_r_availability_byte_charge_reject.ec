require import AllCore List Distr FMap StdOrder StdBigop.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames.
require import KeygenPrefixes KeygenExhaustion FullSession ByteSession FullPrefix.
require import RObservedSigner FullRBound FullRGame FullRInitialization.
require import GrindTail GrindExhaustion SessionClosedForm.
import RField RealOrder Bigreal BRA.
require import ByteRAvailability.

lemma checked
    (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-RFailure,-Physical,-Hybrid,-Shared,-Independent})
    qr qs &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0 <= qr => 0 <= qs => FullLimits.raw_cap{m} = qr => FullLimits.sign_cap{m} = qs =>
  Pr[RealGame(FullRFailureContext(ByteLift(A))).run() @ &m : res] <=
    byte_r_availability_charge qr qs - 1%r.
proof. exact (byte_r_initialized_exhaustion A qr qs &m). qed.

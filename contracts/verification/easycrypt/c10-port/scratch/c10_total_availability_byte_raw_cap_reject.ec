require import AllCore List Distr FMap StdOrder Ring.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames.
require import RawKeygen KeygenExhaustion FullSession ByteSession.
require import RObservedSigner FullRGame ByteRAvailability FullAvailabilityTrace.
require import WotsRejectDomain PhysicalRejectBound.
import RField RealOrder.
require import ByteTotalAvailability.

lemma checked
    (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-RFailure,-Physical,-Hybrid,-Shared,-Independent})
    qr qs &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => true => FullLimits.sign_cap{m}=qs =>
  Pr[RealGame(ByteContext(A)).run() @ &m : FullSession.failed] <=
    byte_total_availability_charge qr qs.
proof. exact (byte_total_initialized_availability A qr qs &m). qed.

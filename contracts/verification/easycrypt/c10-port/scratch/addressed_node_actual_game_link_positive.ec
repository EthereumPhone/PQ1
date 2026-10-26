require import AllCore List Distr FSet FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion FullSession ByteSession.
require import ExposureLog ClientQueryLog ClientQueryDriver QueryPublicCharges.
require import DomainNodeCollision DomainQueryCount DomainSessionCost DomainMemoOracle ByteDomainCollision ProjectedBirthday.
require import AddressedNodeCollision AddressedBuckets AddressedBucketBudget AddressedAudit AddressedCollisionBound AddressedSessionExceptionCount.
import RField RealOrder.
require import AddressedByteCollision.
lemma checked
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent,-AddressedAudit}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ByteContext(A)).run() @ &m : addressed_node_collision Independent.rawhistory]
    <=addressed_node_charge qr qs.
proof. exact (byte_addressed_node_collision A qr qs &m). qed.

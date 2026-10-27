require import AllCore List Distr FSet FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import WrapperSession WrapperByteSession WrapperQueryDriver WrapperPrefixBound RawWrapperCost.
require import ExposureLog ClientQueryLog WrapperPublicCharges.
require import MemoNodeCollision DomainNodeCollision ProjectedMemoOracle ProjectedBirthday.
require import AddressedNodeCollision AddressedBuckets AddressedAudit AddressedCollisionBound.
require import AddressedWrapperMemoSession AddressedWrapperBucketBudget.
import RField RealOrder.
require import AddressedWrapperByteCollision.
lemma checked
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-Independent,-AddressedAudit}) qr qs &m :
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperByteContext(A)).run() @ &m : addressed_node_collision Independent.rawhistory]
    <=wrapper_addressed_node_charge qr qs.
proof. exact (wrapper_byte_addressed_node_collision A qr qs &m). qed.

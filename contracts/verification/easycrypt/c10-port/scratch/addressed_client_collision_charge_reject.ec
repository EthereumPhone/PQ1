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
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-AddressedAudit,
    -Physical,-ProjectedMemo,-ProjectedSamples}) qr qs &m :
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : addressed_node_collision Independent.rawhistory]
    <=0%r.
proof. exact (wrapper_query_byte_addressed_collision_best A qr qs &m). qed.

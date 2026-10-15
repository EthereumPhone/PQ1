require import AllCore List Distr StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames PrefixIdeal.
require import KeygenPrefixes KeygenExhaustion FullSession FullSessionCost FullPrefix ByteSession ByteBound.
require import ProjectedBirthday ProjectedMemoOracle MemoNodeCollision PublicCollisionState.
import RealOrder.
require import DomainQueryCount DomainNodeCollision DomainMemoOracle DomainCollisionBound DomainSessionCost IndependentWidths.
require import QueryPublicCharges ExposureLog ClientQueryLog ClientQueryDriver.
require import ByteDomainCollision.

lemma checked (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-Physical,-DomainMemo,-ProjectedSamples}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m : public_node_collision Independent.rawhistory] <=
    ((node_public_budget qr qs)*(node_public_budget qr qs-1))%r/2%r*(1%r/2%r)^128.
proof.
  move=> hr hs hqr hqs; exact (query_byte_domain_collision A qr qs &m hr hs hqr hqs).
qed.

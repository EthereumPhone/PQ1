require import AllCore List Distr StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames PrefixIdeal.
require import KeygenPrefixes KeygenExhaustion FullSession FullSessionCost FullPrefix ByteSession ByteBound.
require import ProjectedBirthday ProjectedMemoOracle MemoNodeCollision PublicCollisionState BytePublicCollision.
import RealOrder.

lemma too_small (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent,-Physical}) qr qs :
  0<=qr => 0<=qs =>
  hoare [ByteContext(A,Independent).run :
    FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs /\ Independent.queries=[] ==>
    size Independent.queries<=qr].
proof. exact (byte_context_public_cost A qr qs). qed.

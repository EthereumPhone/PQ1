require import AllCore List Distr StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames PrefixIdeal.
require import KeygenPrefixes KeygenExhaustion FullSession FullSessionCost FullPrefix ByteSession ByteBound.
require import ProjectedBirthday ProjectedMemoOracle MemoNodeCollision PublicCollisionState BytePublicCollision.
import RealOrder.
lemma bound
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Physical,-Hybrid,-Shared,
    -Independent,-ProjectedMemo,-ProjectedSamples}) qr qs &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign =>
    islossless A(V).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[RealGame(ByteContext(A)).run() @ &m : res] <=
    ((full_public_budget qr qs)*(full_public_budget qr qs-1))%r/2%r*(1%r/2%r)^128 +
    (full_public_budget qr qs)%r*(1%r/2%r)^256.
proof. exact (byte_public_collision_hop A qr qs &m). qed.

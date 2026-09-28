require import AllCore List Distr FMap StdOrder.
require import C10RawOracle C10Randomizer RawKeygen PrefixGuess.
require import ProjectedBirthday MemoNodeCollision ProjectedMemoOracle PublicCollisionGame PublicCollisionBound NodeCollisionEvents.
import RealOrder.
lemma bound (A <: PrefixContext {-Independent,-ProjectedMemo,-ProjectedSamples}) q &m :
  0<=q =>
  hoare [A(Independent).run : Independent.queries=[] ==> size Independent.queries<=q] =>
  Pr[IndependentNodeCollision(A).run() @ &m : res] <=
    (q*(q-1))%r/2%r*(1%r/2%r)^256.
proof. exact (public_node_birthday A q &m). qed.

require import AllCore List Distr FMap StdOrder DList DBool.
require import C10RawOracle C10Counter C10Bytes C10Randomizer C10RawGrind RawKeygen PrefixGuess PrefixHybrid PrefixGames PrefixIdeal.
require import KeygenPrefixes KeygenExhaustion FullSession FullSessionCost FullPrefix ByteSession ByteBound.
require import ProjectedBirthday ProjectedMemoOracle MemoNodeCollision PublicCollisionState BytePublicCollision.
require import RawWots PersistentGrind RawCountRecorded WotsReferenceRoot RawWotsRecovery WotsZeroSentinel PublicNodeZero BytePublicNodeBad.
import RealOrder.

lemma no_budget (A <: PrefixContext {-Independent,-ProjectedMemo,-ProjectedSamples}) q &m :
  0<=q => Pr[IndependentNodeZero(A).run() @ &m : res] <= q%r*(1%r/2%r)^128.
proof. exact (public_node_zero_at_state A q &m). qed.

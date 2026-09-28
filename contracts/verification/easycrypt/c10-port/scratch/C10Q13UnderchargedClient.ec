require import AllCore List Distr FMap StdOrder.
require import C10RawOracle C10Randomizer RawKeygen PrefixGuess RoleGrindCost.
require import ProjectedBirthday MemoNodeCollision ProjectedMemoOracle PublicCollisionGame PublicCollisionBound NodeCollisionEvents.
import RealOrder.

module TwoFresh (O : PrefixOracle) = {
 proc run() : bool = { var d; d <@ O.hash([]); d <@ O.derive([]); d <@ O.hash([0]); return true; }
}.
module CachedOnly (O : PrefixOracle) = {
 proc run() : bool = { var d; d <@ O.hash([]); d <@ O.hash([]); return true; }
}.
module PrivateOnly (O : PrefixOracle) = {
 proc run() : bool = { var d; d <@ O.derive([]); d <@ O.derive([0]); return true; }
}.

lemma two_fresh_budget : hoare [TwoFresh(Independent).run : Independent.queries=[] ==> size Independent.queries<=2].
proof. proc; call (independent_hash_count 1); call (independent_derive_count 1); call (independent_hash_count 0); auto; smt(). qed.
lemma undercharged : hoare [TwoFresh(Independent).run : Independent.queries=[] ==> size Independent.queries<=1].
proof. exact two_fresh_budget. qed.

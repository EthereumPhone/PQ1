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
lemma two_fresh_bound &m : Pr[IndependentNodeCollision(TwoFresh).run() @ &m : res] <= (1%r/2%r)^128.
proof. have h:=public_node_birthday TwoFresh 2 &m _ two_fresh_budget; smt(). qed.
lemma cached_no_collision : hoare [IndependentNodeCollision(CachedOnly).run : true ==> !res].
proof.
  proc; inline*.
  rcondt 6; first by auto; smt(emptyE domE).
  rcondf 11; first by auto; smt(get_setE domE).
  auto; rewrite /public_node_collision; smt(emptyE get_setE domE).
qed.
lemma private_no_collision : hoare [IndependentNodeCollision(PrivateOnly).run : true ==> !res].
proof.
  proc; inline*.
  rcondt 5; first by auto; smt(emptyE domE).
  rcondt 9; first by auto; smt(emptyE get_setE domE).
  auto; rewrite /public_node_collision; smt(emptyE).
qed.
lemma nonempty_countermodel :
  public_node_collision (empty.[[] <- nseq 256 false].[[0] <- nseq 256 false]).
proof.
  rewrite /public_node_collision.
  exists [] [0] (nseq 256 false) (nseq 256 false); smt(get_setE).
qed.

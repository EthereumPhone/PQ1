(* Remove private bad-event instrumentation from the ideal observation. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle C10Randomizer SecretPrefix PrefixGuess PrefixHybrid PrefixGames PrefixBound.
import RField RealOrder.

module IndependentGame (A : PrefixContext) = {
  proc run() : bool = {
    var result;
    Independent.init();
    result <@ A(Independent).run();
    return result;
  }
}.
lemma ideal_observation (A <: PrefixContext {-Hybrid,-Independent}) :
  equiv[IdealGame(A).run ~ IndependentGame(A).run : ={glob A} ==> ={res,glob A}].
proof.
  proc; seq 1 0 : (={glob A}).
  + by rnd{1}; auto; smt(full_digest_ll).
  exists* key{1}; elim* => key0.
  call (hybrid_instrumentation A key0); inline *; auto; rewrite /prefix_hit /=.
qed.

lemma physical_to_independent
  (A <: PrefixContext {-Physical,-Hybrid,-Shared,-Independent}) q &m :
  (forall (O <: PrefixOracle {-A}), islossless O.hash =>
    islossless O.derive => islossless A(O).run) =>
  0 <= q =>
  hoare[A(Independent).run : Independent.queries = [] ==> size Independent.queries <= q] =>
  Pr[RealGame(A).run() @ &m : res] <=
    Pr[IndependentGame(A).run() @ &m : res] + q%r * (1%r/2%r)^256.
proof.
  move=> hll hq hb.
  have h := shared_prefix_bound A q &m hll hq hb.
  have he : Pr[IdealGame(A).run() @ &m : res] =
      Pr[IndependentGame(A).run() @ &m : res]
    by byequiv (ideal_observation A) => //.
  by rewrite -he.
qed.

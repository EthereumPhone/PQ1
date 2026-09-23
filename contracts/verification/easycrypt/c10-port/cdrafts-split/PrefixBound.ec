(* Classical one-secret prefix separation for a bounded adaptive context.
   q counts all public raw calls, including calls made inside modeled code. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle C10Randomizer SecretPrefix PrefixGuess PrefixHybrid PrefixGames.
import RField RealOrder.

lemma shared_prefix_bound
  (A <: PrefixContext {-Physical,-Hybrid,-Shared,-Independent}) q &m :
  (forall (O <: PrefixOracle {-A}), islossless O.hash =>
    islossless O.derive => islossless A(O).run) =>
  0 <= q =>
  hoare[A(Independent).run : Independent.queries = [] ==> size Independent.queries <= q] =>
  Pr[RealGame(A).run() @ &m : res] <=
    Pr[IdealGame(A).run() @ &m : res] + q%r * (1%r/2%r)^256.
proof.
  move=> hll hq hb.
  have he : Pr[RealGame(A).run() @ &m : res] <=
    Pr[IdealGame(A).run() @ &m : res \/ Hybrid.bad].
  + byequiv (_ : ={glob A} ==> res{1} => res{2} \/ Hybrid.bad{2}) => //.
    conseq (games_up_to_prefix A hll); smt().
  have hu : Pr[IdealGame(A).run() @ &m : res \/ Hybrid.bad] <=
    Pr[IdealGame(A).run() @ &m : res] + Pr[IdealGame(A).run() @ &m : Hybrid.bad].
  + by rewrite Pr[mu_or]; smt(ge0_mu).
  have hg := ideal_prefix_guess_bound A q &m hq hb.
  have hi := ideal_bad_is_guess A &m.
  smt().
qed.

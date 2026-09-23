(* Freeze the context's initial state when its public resource limits are
   run-time inputs. No uniform budget over unrelated initial states is assumed. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle C10Randomizer SecretPrefix PrefixGuess PrefixHybrid PrefixGames PrefixIdeal.
import RField RealOrder.

lemma prefix_guess_at_state (A <: PrefixContext {-Independent}) q &m :
  0 <= q =>
  hoare[A(Independent).run : Independent.queries = [] /\ (glob A) = (glob A){m} ==>
    size Independent.queries <= q] =>
  Pr[Guess(A).run() @ &m : res] <= q%r * (1%r/2%r)^256.
proof.
  move=> hq hb.
  have he : Pr[Guess(A).run() @ &m : res] = Pr[GuessLate(A).run() @ &m : res]
    by byequiv (guess_late A) => //.
  rewrite he.
  byphoare (_ : (glob A) = (glob A){m} ==> res) => //.
  proc; rnd.
  call hb; inline Independent.init; auto => /> queries hsize.
  have h := fixed_prefix_list queries.
  have hn : 0%r <= (1%r/2%r)^256 by apply expr_ge0; smt().
  smt(le_fromint).
qed.

lemma physical_to_independent_at_state
  (A <: PrefixContext {-Physical,-Hybrid,-Shared,-Independent}) q &m :
  (forall (O <: PrefixOracle {-A}), islossless O.hash =>
    islossless O.derive => islossless A(O).run) =>
  0 <= q =>
  hoare[A(Independent).run : Independent.queries = [] /\ (glob A) = (glob A){m} ==>
    size Independent.queries <= q] =>
  Pr[RealGame(A).run() @ &m : res] <=
    Pr[IndependentGame(A).run() @ &m : res] + q%r * (1%r/2%r)^256.
proof.
  move=> hll hq hb.
  have he : Pr[RealGame(A).run() @ &m : res] <=
    Pr[IdealGame(A).run() @ &m : res \/ Hybrid.bad].
  + byequiv (_ : ={glob A} ==> res{1} => res{2} \/ Hybrid.bad{2}) => //.
    conseq (games_up_to_prefix A hll); smt().
  have hu : Pr[IdealGame(A).run() @ &m : res \/ Hybrid.bad] <=
    Pr[IdealGame(A).run() @ &m : res] + Pr[IdealGame(A).run() @ &m : Hybrid.bad].
  + by rewrite Pr[mu_or]; smt(ge0_mu).
  have hg := prefix_guess_at_state A q &m hq hb.
  have hi := ideal_bad_is_guess A &m.
  have ho : Pr[IdealGame(A).run() @ &m : res] =
    Pr[IndependentGame(A).run() @ &m : res]
    by byequiv (ideal_observation A) => //.
  smt().
qed.

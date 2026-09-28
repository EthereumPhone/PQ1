(* Next-batch model: independent public and keyed tables, with raw query
   recording. The hybrid connection to one physical oracle is still pending. *)
require import AllCore List Distr DList FMap StdOrder.
require import C10RawOracle C10Randomizer SecretPrefix.
import RField RealOrder.

module type PrefixOracle = {
  proc hash(x : raw_input) : digest
  proc derive(tail : raw_input) : digest
}.
module type PrefixContext (O : PrefixOracle) = {
  proc run() : bool { O.hash, O.derive }
}.
module Independent = {
  var rawhistory : (raw_input,digest) fmap
  var secrethistory : (raw_input,digest) fmap
  var queries : raw_input list
  proc init() : unit = {
    rawhistory <- empty; secrethistory <- empty; queries <- [];
  }
  proc hash(x : raw_input) : digest = {
    var y;
    queries <- rcons queries x;
    if (x \notin rawhistory) { y <$ full_digest; rawhistory.[x] <- y; }
    return oget rawhistory.[x];
  }
  proc derive(tail : raw_input) : digest = {
    var y;
    if (tail \notin secrethistory) { y <$ full_digest; secrethistory.[tail] <- y; }
    return oget secrethistory.[tail];
  }
}.
module Guess (A : PrefixContext) = {
  proc run() : bool = {
    var key, ignored;
    key <$ full_digest;
    Independent.init();
    ignored <@ A(Independent).run();
    return prefix_hit key Independent.queries;
  }
}.
module GuessLate (A : PrefixContext) = {
  proc run() : bool = {
    var key, ignored;
    Independent.init();
    ignored <@ A(Independent).run();
    key <$ full_digest;
    return prefix_hit key Independent.queries;
  }
}.

lemma guess_late (A <: PrefixContext {-Independent}) :
  equiv[Guess(A).run ~ GuessLate(A).run : ={glob A} ==> ={res}].
proof. by proc; swap{1} 1 2; sim. qed.

lemma ideal_prefix_guess_bound (A <: PrefixContext {-Independent}) (q : int) &m :
  0 <= q =>
  hoare[A(Independent).run : Independent.queries = [] ==> size Independent.queries <= q] =>
  Pr[Guess(A).run() @ &m : res] <= q%r * (1%r/2%r)^256.
proof.
  move=> hq hb.
  have he : Pr[Guess(A).run() @ &m : res] = Pr[GuessLate(A).run() @ &m : res]
    by byequiv (guess_late A) => //.
  rewrite he.
  byphoare (_ : true ==> res) => //.
  proc; rnd.
  call hb; inline Independent.init; auto => /> queries hsize.
  have h := fixed_prefix_list queries.
  have hn : 0%r <= (1%r/2%r)^256 by apply expr_ge0; smt().
  smt(le_fromint).
qed.

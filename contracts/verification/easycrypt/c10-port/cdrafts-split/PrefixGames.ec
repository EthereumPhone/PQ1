require import AllCore List Distr DList FMap.
require import C10Bytes C10Randomizer C10RawOracle SecretPrefix PrefixGuess PrefixHybrid.

module RealGame (A : PrefixContext) = {
  proc run() : bool = {
    var key, result;
    key <$ full_digest;
    Physical.key <- bits_to_bytes key;
    Shared.init();
    result <@ A(Physical).run();
    return result;
  }
}.
module IdealGame (A : PrefixContext) = {
  proc run() : bool = {
    var key, result;
    key <$ full_digest;
    Hybrid.key <- bits_to_bytes key;
    Hybrid.bad <- false;
    Independent.init();
    result <@ A(Hybrid).run();
    return result;
  }
}.

lemma games_up_to_prefix
  (A <: PrefixContext {-Physical,-Hybrid,-Shared,-Independent}) :
  (forall (O <: PrefixOracle {-A}), islossless O.hash =>
    islossless O.derive => islossless A(O).run) =>
  equiv[RealGame(A).run ~ IdealGame(A).run : ={glob A} ==>
    !Hybrid.bad{2} => ={res,glob A}].
proof.
  move=> hll; proc; call (adaptive_prefix A hll).
  inline *; auto => /> key hkey.
  have hs : size key = 256 by move: hkey; rewrite /full_digest supp_dlist /=; smt().
  rewrite bits_to_bytes_size hs /tables_agree /=.
  by smt(emptyE).
qed.

lemma prefix_hit_rcons key queries x :
  prefix_hit key (rcons queries x) =
  (prefix_hit key queries \/ take 32 x = bits_to_bytes key).
proof. by rewrite /prefix_hit -cats1 has_cat /=. qed.

lemma hybrid_instrumentation
  (A <: PrefixContext {-Hybrid,-Independent}) key :
  equiv[A(Hybrid).run ~ A(Independent).run :
    ={glob A,glob Independent} /\ Hybrid.key{1} = bits_to_bytes key /\
    Hybrid.bad{1} = prefix_hit key Independent.queries{2} ==>
    ={res,glob A,glob Independent} /\ Hybrid.key{1} = bits_to_bytes key /\
    Hybrid.bad{1} = prefix_hit key Independent.queries{2}].
proof.
  proc (={glob Independent} /\ Hybrid.key{1} = bits_to_bytes key /\
    Hybrid.bad{1} = prefix_hit key Independent.queries{2}) => //.
  + proc; inline *; sp 3 1; if; auto; smt(prefix_hit_rcons).
  by proc; inline *; sp 1 0; if; auto; smt().
qed.

lemma ideal_bad_is_guess
  (A <: PrefixContext {-Hybrid,-Independent}) &m :
  Pr[IdealGame(A).run() @ &m : Hybrid.bad] = Pr[Guess(A).run() @ &m : res].
proof.
  byequiv (_ : ={glob A} ==> Hybrid.bad{1} = res{2}) => //.
  proc; seq 1 1 : (={glob A,key}).
  + by auto.
  exists* key{1}; elim* => key0.
  call (hybrid_instrumentation A key0); inline *; auto; rewrite /prefix_hit /=.
qed.

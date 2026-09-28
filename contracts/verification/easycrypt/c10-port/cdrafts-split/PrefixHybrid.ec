(* External next-batch hybrid. One uniform secret prefix, shared across every
   private derivation; all public raw inputs remain available. *)
require import AllCore List Distr FMap.
require import C10Bytes C10Randomizer C10RawOracle SecretPrefix PrefixGuess.

module Physical = {
  var key : raw_input
  proc hash(x : raw_input) : digest = {
    var y; y <@ Shared.hash(x); return y;
  }
  proc derive(tail : raw_input) : digest = {
    var y; y <@ Shared.hash(key ++ tail); return y;
  }
}.
module Hybrid = {
  var key : raw_input
  var bad : bool
  proc hash(x : raw_input) : digest = {
    var y;
    bad <- bad \/ take 32 x = key;
    y <@ Independent.hash(x);
    return y;
  }
  proc derive(tail : raw_input) : digest = {
    var y; y <@ Independent.derive(tail); return y;
  }
}.

op tables_agree key (physical raw private : (raw_input,digest) fmap) =
  (forall x, take 32 x <> key => physical.[x] = raw.[x]) /\
  (forall tail, physical.[key ++ tail] = private.[tail]).

lemma prefixed_input (key tail : raw_input) : size key = 32 => take 32 (key ++ tail) = key.
proof. by move=> hk; rewrite take_cat hk /= take0 cats0. qed.

lemma public_update key physical raw private x y :
  size key = 32 => take 32 x <> key => tables_agree key physical raw private =>
  tables_agree key physical.[x <- y] raw.[x <- y] private.
proof.
  rewrite /tables_agree => hk hx [hpub hpriv]; split.
  + by move=> z hz; rewrite !get_setE; smt().
  move=> tail; rewrite get_setE.
  have hn : key ++ tail <> x by smt(prefixed_input).
  smt().
qed.

lemma private_update key physical raw private tail y :
  size key = 32 => tables_agree key physical raw private =>
  tables_agree key physical.[key ++ tail <- y] raw private.[tail <- y].
proof.
  rewrite /tables_agree => hk [hpub hpriv]; split.
  + move=> x hx; rewrite get_setE; smt(prefixed_input).
  move=> t; rewrite !get_setE; smt(catsI).
qed.

lemma independent_hash_ll : islossless Independent.hash.
proof. by proc; sp 1; if; auto; smt(full_digest_ll). qed.
lemma independent_derive_ll : islossless Independent.derive.
proof. by proc; if; auto; smt(full_digest_ll). qed.

lemma public_query :
  equiv[Physical.hash ~ Hybrid.hash :
    ={x} /\ Physical.key{1} = Hybrid.key{2} /\ size Hybrid.key{2} = 32 /\
    !Hybrid.bad{2} /\ tables_agree Hybrid.key{2} Shared.history{1}
      Independent.rawhistory{2} Independent.secrethistory{2} ==>
    !Hybrid.bad{2} => ={res} /\ Physical.key{1} = Hybrid.key{2} /\
      size Hybrid.key{2} = 32 /\ tables_agree Hybrid.key{2} Shared.history{1}
        Independent.rawhistory{2} Independent.secrethistory{2}].
proof.
  proc; case (take 32 x{2} = Hybrid.key{2}).
  + wp; call{1} hash_ll; call{2} independent_hash_ll; auto; smt().
  inline *; sp 2 3; if.
  + auto; rewrite /tables_agree; smt(domE).
  + by auto; smt(public_update get_set_sameE).
  by auto; rewrite /tables_agree; smt().
qed.

lemma private_query :
  equiv[Physical.derive ~ Hybrid.derive :
    ={tail} /\ Physical.key{1} = Hybrid.key{2} /\ size Hybrid.key{2} = 32 /\
    !Hybrid.bad{2} /\ tables_agree Hybrid.key{2} Shared.history{1}
      Independent.rawhistory{2} Independent.secrethistory{2} ==>
    !Hybrid.bad{2} => ={res} /\ Physical.key{1} = Hybrid.key{2} /\
      size Hybrid.key{2} = 32 /\ tables_agree Hybrid.key{2} Shared.history{1}
        Independent.rawhistory{2} Independent.secrethistory{2}].
proof.
  proc; inline *; sp 2 1; if.
  + auto; rewrite /tables_agree; smt(domE).
  + by auto; smt(private_update get_set_sameE).
  by auto; rewrite /tables_agree; smt().
qed.

lemma physical_hash_ll : islossless Physical.hash.
proof. by proc; call hash_ll; auto. qed.
lemma physical_derive_ll : islossless Physical.derive.
proof. by proc; call hash_ll; auto. qed.
lemma hybrid_hash_ll : islossless Hybrid.hash.
proof. by proc; call independent_hash_ll; auto. qed.
lemma hybrid_derive_ll : islossless Hybrid.derive.
proof. by proc; call independent_derive_ll; auto. qed.

lemma adaptive_prefix
  (A <: PrefixContext {-Physical,-Hybrid,-Shared,-Independent}) :
  (forall (O <: PrefixOracle {-A}), islossless O.hash =>
    islossless O.derive => islossless A(O).run) =>
  equiv[A(Physical).run ~ A(Hybrid).run :
    ={glob A} /\ Physical.key{1} = Hybrid.key{2} /\ size Hybrid.key{2} = 32 /\
    !Hybrid.bad{2} /\ tables_agree Hybrid.key{2} Shared.history{1}
      Independent.rawhistory{2} Independent.secrethistory{2} ==>
    !Hybrid.bad{2} => ={res,glob A} /\ Physical.key{1} = Hybrid.key{2} /\
      size Hybrid.key{2} = 32 /\ tables_agree Hybrid.key{2} Shared.history{1}
        Independent.rawhistory{2} Independent.secrethistory{2}].
proof.
  move=> hll.
  proc (Hybrid.bad)
    (Physical.key{1} = Hybrid.key{2} /\ size Hybrid.key{2} = 32 /\
      tables_agree Hybrid.key{2} Shared.history{1}
        Independent.rawhistory{2} Independent.secrethistory{2}) true.
  + by smt().
  + by smt().
  + exact hll.
  + conseq public_query; smt().
  + move=> &2 _; exact physical_hash_ll.
  + move=> &1; by proc; call independent_hash_ll; auto; smt().
  + conseq private_query; smt().
  + move=> &2 _; exact physical_derive_ll.
  + move=> &1; by proc; call independent_derive_ll; auto.
qed.

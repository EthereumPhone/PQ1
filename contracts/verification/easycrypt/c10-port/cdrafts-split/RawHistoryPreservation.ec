(* External Q research: every adaptive public/private oracle client preserves
   already memoized public outputs. Private observer state is not exposed. *)
require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess.

lemma independent_hash_keeps x0 d0 :
  hoare[Independent.hash : Independent.rawhistory.[x0] = Some d0 ==>
    Independent.rawhistory.[x0] = Some d0].
proof. proc; sp 1; if; auto; smt(get_setE domE). qed.

lemma independent_derive_keeps x0 d0 :
  hoare[Independent.derive : Independent.rawhistory.[x0] = Some d0 ==>
    Independent.rawhistory.[x0] = Some d0].
proof. by proc; if; auto. qed.

lemma independent_context_keeps (A <: PrefixContext {-Independent}) x0 d0 :
  hoare[A(Independent).run : Independent.rawhistory.[x0] = Some d0 ==>
    Independent.rawhistory.[x0] = Some d0].
proof.
  proc (Independent.rawhistory.[x0] = Some d0) => //.
  + exact (independent_hash_keeps x0 d0).
  exact (independent_derive_keeps x0 d0).
qed.

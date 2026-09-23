(* External Q2 research: neither memoized table overwrites existing values. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PersistentGrind AcceptedContexts.

lemma independent_hash_extends s0 h0 :
  hoare[Independent.hash :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof. proc; sp 1; if; auto; rewrite /extends; smt(get_setE domE). qed.

lemma independent_derive_extends s0 h0 :
  hoare[Independent.derive :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof. proc; if; auto; rewrite /extends; smt(get_setE domE). qed.

lemma independent_derive_records tail0 :
  hoare[Independent.derive : tail = tail0 ==> Independent.secrethistory.[tail0] = Some res].
proof. proc; if; auto; smt(get_set_sameE domE). qed.

lemma independent_prefix_extends (A <: PrefixContext {-Independent}) s0 h0 :
  hoare[A(Independent).run :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory) => //.
  + exact (independent_hash_extends s0 h0).
  exact (independent_derive_extends s0 h0).
qed.

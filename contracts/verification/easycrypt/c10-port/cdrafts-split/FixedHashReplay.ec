(* A memoized public query returns the fixed witness and preserves both tables. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PersistentGrind.

lemma hash_from_history x0 d0 s0 h0 :
  hoare [Independent.hash :
    x=x0 /\ h0.[x0]=Some d0 /\ extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    res=d0 /\ extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof. proc; sp 1; if; auto; rewrite /extends; smt(domE). qed.

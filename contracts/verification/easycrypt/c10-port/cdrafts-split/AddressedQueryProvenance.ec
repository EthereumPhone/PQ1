(* Any newly memoized public input occurs in the actual appended query log.
   Existing keys may be queried again; they never become fresh draws again. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes.
require import ForsComponentHistory.

op appended_query_history (old : (raw_input,digest) fmap) (base : raw_input list)
    (h : (raw_input,digest) fmap) (queries : raw_input list) =
  exists inputs, queries=base++inputs /\ forall x, x \in h => x \in old \/ x \in inputs.

lemma appended_query_history_initial h base : appended_query_history h base h base.
proof. rewrite /appended_query_history; exists []; rewrite cats0; smt(). qed.

lemma appended_query_history_push old base h queries x :
  appended_query_history old base h queries => appended_query_history old base h (rcons queries x).
proof.
  move=> [inputs [hq hi]]; exists (rcons inputs x).
  rewrite -!cats1; split; first smt(catA).
  smt(mem_cat mem_seq1).
qed.

lemma appended_query_history_insert old base h queries x d :
  appended_query_history old base h queries =>
  appended_query_history old base h.[x<-d] (rcons queries x).
proof.
  move=> [inputs [hq hi]]; exists (rcons inputs x).
  rewrite -!cats1; split; first smt(catA).
  smt(mem_cat mem_seq1 mem_set).
qed.

lemma appended_query_history_member old base h queries inputs x :
  appended_query_history old base h queries => queries=base++inputs =>
  x \in h => x \notin old => x \in inputs.
proof.
  move=> [ys [hq hy]] hi hx ho.
  have hh : drop (size base) (base++ys)=drop (size base) (base++inputs) by smt().
  move: hh; rewrite !drop_size_cat; smt().
qed.

lemma hash_appended_query_history old base :
  hoare [Independent.hash : appended_query_history old base Independent.rawhistory Independent.queries ==>
    appended_query_history old base Independent.rawhistory Independent.queries].
proof.
  proc; sp 1; if; auto; smt(appended_query_history_push appended_query_history_insert).
qed.

lemma derive_appended_query_history old base :
  hoare [Independent.derive : appended_query_history old base Independent.rawhistory Independent.queries ==>
    appended_query_history old base Independent.rawhistory Independent.queries].
proof. proc; if; auto. qed.

lemma fors_appended_query_history old base :
  hoare [PreparationView(Independent).fors : appended_query_history old base Independent.rawhistory Independent.queries ==>
    appended_query_history old base Independent.rawhistory Independent.queries].
proof. proc; call (derive_appended_query_history old base); auto. qed.

lemma fors_sign_appended_query_history (S <: ForsSigning {-Independent}) old base :
  hoare [S(PreparationView(Independent)).sign : appended_query_history old base Independent.rawhistory Independent.queries ==>
    appended_query_history old base Independent.rawhistory Independent.queries].
proof.
  proc (appended_query_history old base Independent.rawhistory Independent.queries) => //.
  + exact (hash_appended_query_history old base).
  exact (fors_appended_query_history old base).
qed.

lemma fors_root_appended_query_history (S <: ForsRoot {-Independent}) old base :
  hoare [S(PreparationView(Independent)).root : appended_query_history old base Independent.rawhistory Independent.queries ==>
    appended_query_history old base Independent.rawhistory Independent.queries].
proof.
  proc (appended_query_history old base Independent.rawhistory Independent.queries) => //.
  + exact (hash_appended_query_history old base).
  exact (fors_appended_query_history old base).
qed.

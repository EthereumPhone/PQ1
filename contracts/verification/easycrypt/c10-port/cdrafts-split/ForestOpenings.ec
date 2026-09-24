(* The actual shuffled forest arrays retain each visited tree's opening. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawForest PersistentGrind ForsOpening.

op forest_openings h seed ht digest (secrets : raw_input list)
    (auths : raw_input list list) (roots : raw_input list) (visited : int list) =
  size secrets=13 /\ size auths=12 /\ size roots=13 /\
  forall t, t \in visited => fors_opening h seed ht t (forest_index digest t)
    (nth (nseq 16 0) secrets t) (nth [] auths t) (nth (nseq 16 0) roots t).

lemma forest_openings_extends h h' seed ht digest secrets auths roots visited :
  extends h h' => forest_openings h seed ht digest secrets auths roots visited =>
  forest_openings h' seed ht digest secrets auths roots visited.
proof. rewrite /forest_openings; smt(fors_opening_extends). qed.

lemma forest_openings_empty h seed ht digest :
  forest_openings h seed ht digest (nseq 13 (nseq 16 0)) (nseq 12 (nseq 11 (nseq 16 0)))
    (nseq 13 (nseq 16 0)) [].
proof. by rewrite /forest_openings !size_nseq /=. qed.

lemma forest_openings_step h seed ht digest secrets auths roots visited t secret auth root :
  0<=t<12 => forest_openings h seed ht digest secrets auths roots visited =>
  fors_opening h seed ht t (forest_index digest t) secret auth root =>
  forest_openings h seed ht digest (put secrets t secret) (put auths t auth) (put roots t root) (rcons visited t).
proof.
  move=> hindex [hse [hau [hro hv]]] hf.
  rewrite /forest_openings !size_put hse hau hro /=.
  move=> i; rewrite mem_rcons !nth_put 1,2,3:/#; smt().
qed.

lemma forest_openings_last h seed ht digest secrets auths roots finalsecret root :
  forest_openings h seed ht digest secrets auths roots (range 0 12) =>
  forest_openings h seed ht digest (put secrets 12 finalsecret) auths (put roots 12 root) (range 0 12).
proof.
  move=> [hse [hau [hro hv]]]; rewrite /forest_openings !size_put hse hau hro /=.
  move=> i hi; rewrite !nth_put 1,2:/#; smt(mem_range).
qed.

lemma forest_visited_complete h seed ht digest secrets auths roots order :
  perm_eq order (range 0 12) => forest_openings h seed ht digest secrets auths roots (take 12 order) =>
  forest_openings h seed ht digest secrets auths roots (range 0 12).
proof.
  rewrite /forest_openings; smt(perm_eq_size size_range take_size perm_eq_mem).
qed.

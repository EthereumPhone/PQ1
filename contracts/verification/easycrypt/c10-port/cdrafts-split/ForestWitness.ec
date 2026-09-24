(* The thirteenth tree is represented by its actual root-as-secret hash. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawForest RawForsPathReplay PersistentGrind ForestOpenings.

op forest_special_input seed ht secret = fors_leaf_input seed ht 12 0 secret.
op forest_compress_input seed ht roots =
  seed ++ address 0 ht 4 0 0 0 0 ++ flatten (map pad roots).
op forest_witness h seed ht digest secrets auths roots =
  forest_openings h seed ht digest secrets auths roots (range 0 12) /\
  exists d, h.[forest_special_input seed ht (nth (nseq 16 0) secrets 12)]=Some d /\
    nth (nseq 16 0) roots 12=node d.

lemma forest_witness_extends h h' seed ht digest secrets auths roots :
  extends h h' => forest_witness h seed ht digest secrets auths roots =>
  forest_witness h' seed ht digest secrets auths roots.
proof.
  move=> he [hp [d [hd hv]]].
  have hp' := forest_openings_extends h h' seed ht digest secrets auths roots (range 0 12) he hp.
  rewrite /forest_witness; split; first exact hp'.
  exists d; move: he; rewrite /extends; smt().
qed.

lemma forest_special_recorded h seed ht digest secrets auths roots finalsecret d :
  forest_openings h seed ht digest secrets auths roots (range 0 12) =>
  h.[forest_special_input seed ht finalsecret]=Some d =>
  forest_witness h seed ht digest (put secrets 12 finalsecret) auths (put roots 12 (node d)).
proof.
  move=> hp hd; have hp' := forest_openings_last h seed ht digest secrets auths roots finalsecret (node d) hp.
  rewrite /forest_witness; split; first exact hp'.
  have hse : size secrets=13 by move: hp; rewrite /forest_openings; smt().
  have hro : size roots=13 by move: hp; rewrite /forest_openings; smt().
  exists d; rewrite !nth_put 1,2:/#; smt().
qed.

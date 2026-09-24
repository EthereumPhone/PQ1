(* A recorded FORS opening includes its initial leaf entry and returned root. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawFors PersistentGrind PathReplay RawForsPathReplay.

op fors_opening h seed ht tree target secret auth root =
  size auth=11 /\ exists d,
    h.[fors_leaf_input seed ht tree target secret]=Some d /\
    path_recorded h (fors_pair seed ht tree) (node d,0,target) auth /\
    (path_value h (fors_pair seed ht tree) (node d,0,target) auth).`1=root.

lemma fors_opening_extends h h' seed ht tree target secret auth root :
  extends h h' => fors_opening h seed ht tree target secret auth root =>
  fors_opening h' seed ht tree target secret auth root.
proof.
  move=> he [ha [d [hd [hp hv]]]].
  have hpe := path_recorded_extends h h' (fors_pair seed ht tree) (node d,0,target) auth he hp.
  rewrite /fors_opening; split; first exact ha.
  exists d; move: he; rewrite /extends; smt().
qed.

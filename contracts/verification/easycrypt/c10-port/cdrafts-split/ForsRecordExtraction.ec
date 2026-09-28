(* Recovery at a recorded FORS root identifies its actual private leaf value. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawSignature RawForsPathReplay.
require import ForsRootWitness ForsPrivateLeaves ForsOpening ForsLeafInputs.
require import PathReplay PathInputs MemoNodeCollision NodeCollisionEvents.

lemma recorded_fors_extracts h s seed ht tree index secret auth root :
  size secret=16 => rows_width 11 auth => 0<=index<2048 =>
  fors_root_witness h s seed ht tree root =>
  fors_opening h seed ht tree index secret auth root =>
  !public_node_collision h =>
  exists sd, s.[fors_private_key ht tree index]=Some sd /\ secret=node sd.
proof.
  move=> hw ha hi hr [hasize [d [hd [hp hv]]]] hn.
  have [sd reference_auth [hra [hs hreference]]] := fors_root_reference_at h s seed ht tree root index hr hi.
  move: hreference => [hrs [rd [hrd [hrp hrv]]]].
  have he : node d=node rd.
  + have hx := path_leaf_or_input_collision h (fors_pair seed ht tree) auth reference_auth
      (node d) (node rd) 0 index (fors_pair_injective seed ht tree) _ _ _ (node_width d) (node_width rd) hp hrp _.
    - move: ha hra; rewrite /rows_width; smt().
    - move: ha; rewrite /rows_width; smt().
    - move: hra; rewrite /rows_width; smt().
    - smt().
    smt(path_input_collision_is_public).
  have hx := fors_leaf_equal_or_collision h seed ht tree index secret (node sd) d rd
    hw (node_width sd) hd hrd he.
  exists sd; smt(fors_leaf_collision_is_public).
qed.

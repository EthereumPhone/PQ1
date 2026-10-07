(* Coordinate coverage and actual encoded private-input coverage coincide. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawForest ForsPrivateLeaves ForsInputSeparation.
require import ForestCoordinates SignerCoordinates ExposureCoverage ExposurePrivate ExposureReferences.
require import ExposureSupport ExposureWidths JointNodeCollision MemoNodeCollision.

op returned_private_input h seed root entries key =
  exists d tree, logged_digest h seed root entries d /\ 0<=tree<12 /\
    key=fors_private_key (hypertree_index d) tree (forest_index d tree).

lemma returned_input_coordinate h seed root entries ht tree index :
  0<=ht<4294967296 => 0<=tree<12 => 0<=index<4294967296 =>
  returned_private_input h seed root entries (fors_private_key ht tree index) <=>
    returned_coordinate h seed root entries ht tree index.
proof.
  rewrite /returned_private_input /returned_coordinate => hh htree hi; split.
  + move=> [d t [hd [htr he]]].
    have hc := fors_private_key_injective ht tree index (hypertree_index d) t (forest_index d t)
      hh _ hi _ _ _ he; 1..4:smt(hypertree_index_range forest_index_range).
    split; first exact htree.
    exists d; smt().
  move=> [_ [d [hd [he hi']]]]; exists d tree; smt().
qed.

lemma unreturned_encoded_input h seed root entries d tree :
  0<=tree<12 =>
  !returned_coordinate h seed root entries (hypertree_index d) tree (forest_index d tree) =>
  !returned_private_input h seed root entries
    (fors_private_key (hypertree_index d) tree (forest_index d tree)).
proof. smt(returned_input_coordinate hypertree_index_range forest_index_range). qed.

lemma returned_input_cat h seed root entries1 entries2 key :
  returned_private_input h seed root (entries1++entries2) key =
  (returned_private_input h seed root entries1 key \/ returned_private_input h seed root entries2 key).
proof. rewrite /returned_private_input /logged_digest; smt(mem_cat). qed.

lemma returned_input_empty h seed root key : !returned_private_input h seed root [] key.
proof. rewrite /returned_private_input /logged_digest /=; smt(). qed.

lemma unreturned_value_not_logged h s seed root entries d tree sd ht' tree' index' :
  exposures_supported h s seed root entries => exposures_width entries =>
  !public_node_collision h => !private_node_alias h s => 0<=tree<12 =>
  !returned_coordinate h seed root entries (hypertree_index d) tree (forest_index d tree) =>
  s.[fors_private_key (hypertree_index d) tree (forest_index d tree)]=Some sd =>
  !logged_fors_value h seed root entries ht' tree' index' (node sd).
proof.
  move=> hs hw hn ha ht hu hsd; apply negP => hv.
  have [sd' [hsd' heq]] := logged_fors_private_value h s seed root entries ht' tree' index'
    (node sd) hs hw hn hv.
  have [message signature d' [hm [hd [hh [htr' [hi' hv']]]]]] := hv.
  have hneq : fors_private_key (hypertree_index d) tree (forest_index d tree) <>
    fors_private_key ht' tree' index'.
  + apply negP => he.
    have hc := fors_digest_coordinate_injective d tree d' tree' _ _ _; 1..3:smt().
    have hr : returned_coordinate h seed root entries (hypertree_index d) tree (forest_index d tree).
    - rewrite /returned_coordinate; split; first exact ht.
      exists d'; split; first by rewrite /logged_digest; exists message signature.
      smt().
    smt().
  move: ha; rewrite /private_node_alias /public_node_collision; smt().
qed.
